"""The DHCPv4 client state machine (RFC 2131 section 3.1, 4.1, 4.4).

RFC 2131 prints no byte vectors for the client, so every expectation is a rule read from the text
and the test names the paragraph. The random source is scripted: ``uniform`` returns 0 unless a
test says otherwise, so each timer is a round number.
"""

from __future__ import annotations

from dataclasses import replace

from leasespy.client4 import (
    Bound,
    Client4,
    ClientState,
    Lost,
    Send,
)
from leasespy.options4 import Option4, encode_client_id
from leasespy.wire4 import DhcpMessage4, DhcpMessageType

MAC = bytes.fromhex("00053c048d59")
SERVER = bytes([192, 0, 2, 1])
OTHER_SERVER = bytes([192, 0, 2, 2])
ADDRESS = bytes([192, 0, 2, 50])
XID = 0x01020304
ZERO = bytes(4)


class Rng:
    def __init__(self, jitter: float = 0.0, xid: int = XID) -> None:
        self.jitter = jitter
        self.xid = xid
        self.uniform_calls: list[tuple[float, float]] = []

    def uniform(self, a: float, b: float) -> float:
        self.uniform_calls.append((a, b))
        return self.jitter

    def randint(self, a: int, b: int) -> int:
        return self.xid


def reply(kind, *, xid=XID, yiaddr=ADDRESS, server=SERVER, lease=3600, extra=()) -> DhcpMessage4:
    options = [Option4(53, bytes([int(kind)])), Option4(54, server)]
    if lease is not None:
        options.append(Option4(51, lease.to_bytes(4, "big")))
    options.extend(extra)
    return DhcpMessage4(
        op=2,
        htype=1,
        hops=0,
        xid=xid,
        secs=0,
        flags=0,
        ciaddr=ZERO,
        yiaddr=yiaddr,
        siaddr=ZERO,
        giaddr=ZERO,
        chaddr=MAC,
        options=tuple(options),
    )


def sent(actions):
    return [a for a in actions if isinstance(a, Send)]


def bound_client(lease=3600, extra=(), rng=None, client_id=None):
    client = Client4(MAC, rng=rng or Rng(), client_id=client_id)
    client.start(0.0)
    client.receive(reply(DhcpMessageType.OFFER), 1.0)
    actions = client.receive(reply(DhcpMessageType.ACK, lease=lease, extra=extra), 2.0)
    return client, actions


def test_start_broadcasts_a_discover_with_ciaddr_zero_and_the_broadcast_flag() -> None:
    client = Client4(MAC, rng=Rng())
    (send,) = sent(client.start(0.0))
    message = send.message
    assert send.unicast_to is None
    assert message.message_type == DhcpMessageType.DISCOVER
    assert message.ciaddr == ZERO
    assert message.xid == XID
    assert message.chaddr == MAC
    assert message.broadcast
    assert client.state is ClientState.SELECTING


def test_the_startup_delay_is_one_to_ten_seconds() -> None:
    rng = Rng(jitter=5.5)
    assert Client4(MAC, rng=rng).startup_delay() == 5.5
    assert rng.uniform_calls == [(1.0, 10.0)]


def test_an_offer_with_the_wrong_xid_is_discarded_and_an_ack_in_selecting_too() -> None:
    client = Client4(MAC, rng=Rng())
    client.start(0.0)
    assert client.receive(reply(DhcpMessageType.OFFER, xid=XID + 1), 1.0) == []
    assert client.receive(reply(DhcpMessageType.ACK), 1.0) == []
    assert client.state is ClientState.SELECTING


def test_the_request_carries_the_offers_xid_server_and_requested_address() -> None:
    client = Client4(MAC, rng=Rng())
    client.start(0.0)
    (send,) = sent(client.receive(reply(DhcpMessageType.OFFER), 1.0))
    message = send.message
    assert message.message_type == DhcpMessageType.REQUEST
    assert message.xid == XID
    assert message.option(54) == SERVER  # Table 5: MUST after SELECTING
    assert message.option(50) == ADDRESS  # Table 5: MUST in SELECTING
    assert message.ciaddr == ZERO
    assert send.unicast_to is None
    assert client.state is ClientState.REQUESTING


def test_an_ack_binds_with_default_t1_t2_counted_from_the_request() -> None:
    client, actions = bound_client(lease=1000)
    (bound,) = [a for a in actions if isinstance(a, Bound)]
    assert client.state is ClientState.BOUND
    assert bound.address == ADDRESS
    assert bound.lease == 1000
    # The REQUEST went out at t=1, so the lease runs from 1, not from the ACK at 2.
    assert bound.leased_at == 1.0
    assert bound.t1 == 1.0 + 500  # 0.5 * lease, section 4.4.5 paragraph 6
    assert bound.t2 == 1.0 + 875  # 0.875 * lease


def test_server_given_t1_and_t2_are_used_when_ordered() -> None:
    extra = (Option4(58, (100).to_bytes(4, "big")), Option4(59, (200).to_bytes(4, "big")))
    _, actions = bound_client(lease=1000, extra=extra)
    (bound,) = [a for a in actions if isinstance(a, Bound)]
    assert (bound.t1, bound.t2) == (101.0, 201.0)


def test_server_times_that_break_t1_before_t2_before_expiry_fall_back_to_the_defaults() -> None:
    """Section 4.4.5 paragraph 1: T1 MUST be earlier than T2, earlier than expiry."""
    extra = (Option4(58, (900).to_bytes(4, "big")), Option4(59, (200).to_bytes(4, "big")))
    _, actions = bound_client(lease=1000, extra=extra)
    (bound,) = [a for a in actions if isinstance(a, Bound)]
    assert (bound.t1, bound.t2) == (501.0, 876.0)


def test_an_infinite_lease_sets_no_timers() -> None:
    client, actions = bound_client(lease=0xFFFFFFFF)
    (bound,) = [a for a in actions if isinstance(a, Bound)]
    assert (bound.t1, bound.t2) == (None, None)
    assert client.next_deadline is None
    assert client.tick(10**9) == []


def test_t1_renews_by_unicast_with_ciaddr_and_no_server_id_or_requested_address() -> None:
    client, _ = bound_client(lease=1000)
    assert client.tick(500.9) == []
    (send,) = sent(client.tick(501.0))
    message = send.message
    assert client.state is ClientState.RENEWING
    assert send.unicast_to == SERVER
    assert message.message_type == DhcpMessageType.REQUEST
    assert message.ciaddr == ADDRESS
    assert message.option(54) is None  # section 4.4.5 paragraph 3
    assert message.option(50) is None  # Table 5: MUST NOT in BOUND or RENEWING


def test_t2_rebinds_by_broadcast() -> None:
    client, _ = bound_client(lease=1000)
    client.tick(501.0)
    (send,) = sent(client.tick(876.0))
    assert client.state is ClientState.REBINDING
    assert send.unicast_to is None  # section 4.4.5 paragraph 5
    assert send.message.ciaddr == ADDRESS
    assert send.message.option(54) is None


def test_a_tick_past_t2_goes_straight_to_rebinding() -> None:
    client, _ = bound_client(lease=1000)
    (send,) = sent(client.tick(900.0))
    assert client.state is ClientState.REBINDING
    assert send.unicast_to is None


def test_renewing_retries_after_half_the_time_to_t2_never_under_sixty_seconds() -> None:
    """Section 4.4.5 paragraph 8."""
    client, _ = bound_client(lease=1000)
    client.tick(501.0)  # RENEWING; T2 is at 876, so half of the 375 s left is 187.5
    assert client.next_deadline == 501.0 + 187.5
    assert sent(client.tick(501.0 + 187.4)) == []
    (retry,) = sent(client.tick(501.0 + 187.5))
    assert retry.unicast_to == SERVER
    # Close to T2 the wait floors at 60 seconds.
    client2, _ = bound_client(lease=1000)
    client2.tick(501.0)
    client2.tick(501.0 + 187.5)  # now at 688.5, 187.5 to T2: half is 93.75
    assert client2.next_deadline == 688.5 + 93.75
    client2.tick(688.5 + 93.75)  # at 782.25, 93.75 to T2: half is 46.9, floored to 60
    assert client2.next_deadline == 782.25 + 60.0


def test_an_ack_while_renewing_returns_to_bound_and_restarts_the_lease_clock() -> None:
    client, _ = bound_client(lease=1000)
    (renew,) = sent(client.tick(501.0))
    ack = reply(DhcpMessageType.ACK, xid=renew.message.xid, lease=2000)
    (bound,) = [a for a in client.receive(ack, 503.0) if isinstance(a, Bound)]
    assert client.state is ClientState.BOUND
    assert bound.leased_at == 501.0  # the time the REQUEST was sent (paragraph 4)
    assert bound.t1 == 501.0 + 1000


def test_an_ack_with_the_wrong_xid_while_renewing_is_discarded() -> None:
    """Section 4.4.5 paragraph 4."""
    client, _ = bound_client(lease=1000)
    client.tick(501.0)
    assert client.receive(reply(DhcpMessageType.ACK, xid=1), 503.0) == []
    assert client.state is ClientState.RENEWING


def test_lease_expiry_drops_the_address_and_returns_to_init() -> None:
    """Section 4.4.5 paragraph 9."""
    client, _ = bound_client(lease=1000)
    client.tick(876.0)
    actions = client.tick(1001.0)
    assert [type(a) for a in actions] == [Lost, Send]
    assert isinstance(actions[0], Lost)
    assert actions[0].address == ADDRESS
    assert actions[0].reason == "lease expired"
    assert sent(actions)[0].message.message_type == DhcpMessageType.DISCOVER
    assert client.state is ClientState.SELECTING


def test_a_nak_returns_to_init_and_restarts_discovery() -> None:
    """Section 3.1 paragraph 19, section 3.2 paragraph 10."""
    client = Client4(MAC, rng=Rng())
    client.start(0.0)
    client.receive(reply(DhcpMessageType.OFFER), 1.0)
    actions = client.receive(reply(DhcpMessageType.NAK), 2.0)
    assert sent(actions)[0].message.message_type == DhcpMessageType.DISCOVER
    assert not [a for a in actions if isinstance(a, Lost)]  # nothing was bound yet
    assert client.state is ClientState.SELECTING


def test_a_nak_after_binding_reports_the_lost_address() -> None:
    client, _ = bound_client(lease=1000)
    (renew,) = sent(client.tick(501.0))
    actions = client.receive(reply(DhcpMessageType.NAK, xid=renew.message.xid), 502.0)
    assert [a.reason for a in actions if isinstance(a, Lost)] == ["NAK"]


def test_discover_retransmits_after_4_8_16_32_then_64_seconds() -> None:
    """Section 4.1 paragraph 8: doubling from 4 seconds up to a maximum of 64."""
    client = Client4(MAC, rng=Rng())
    client.start(0.0)
    waits = []
    now = 0.0
    for _ in range(7):
        deadline = client.next_deadline
        assert deadline is not None
        waits.append(deadline - now)
        now = deadline
        assert sent(client.tick(now))
    assert waits == [4.0, 8.0, 16.0, 32.0, 64.0, 64.0, 64.0]


def test_each_backoff_delay_is_randomized_by_minus_one_to_plus_one() -> None:
    rng = Rng(jitter=0.5)
    client = Client4(MAC, rng=rng)
    client.start(0.0)
    assert client.next_deadline == 4.5
    assert rng.uniform_calls == [(-1.0, 1.0)]


def test_a_request_in_requesting_is_retransmitted_with_the_same_xid() -> None:
    client = Client4(MAC, rng=Rng())
    client.start(0.0)
    client.receive(reply(DhcpMessageType.OFFER), 1.0)
    (again,) = sent(client.tick(5.0))
    assert again.message.message_type == DhcpMessageType.REQUEST
    assert again.message.xid == XID
    assert again.message.option(54) == SERVER


def test_an_offer_without_a_server_identifier_or_address_is_not_selected() -> None:
    client = Client4(MAC, rng=Rng())
    client.start(0.0)
    no_server = reply(DhcpMessageType.OFFER)
    no_server = replace(no_server, options=tuple(o for o in no_server.options if o.code != 54))
    assert client.receive(no_server, 1.0) == []
    assert client.receive(reply(DhcpMessageType.OFFER, yiaddr=ZERO), 1.0) == []
    assert client.state is ClientState.SELECTING


def test_a_server_reply_with_a_different_client_identifier_is_discarded() -> None:
    """RFC 6842 section 3 paragraph 4, including an identifier the client never sent."""
    mine = encode_client_id(7, b"\x00\x03\x00\x01" + MAC)
    client = Client4(MAC, rng=Rng(), client_id=mine)
    client.start(0.0)
    foreign = reply(DhcpMessageType.OFFER, extra=(Option4(61, b"\x01" + MAC),))
    assert client.receive(foreign, 1.0) == []
    echoed = reply(DhcpMessageType.OFFER, extra=(Option4(61, mine),))
    assert sent(client.receive(echoed, 1.0))
    bare = Client4(MAC, rng=Rng())
    bare.start(0.0)
    assert bare.receive(reply(DhcpMessageType.OFFER, extra=(Option4(61, mine),)), 1.0) == []


def test_the_client_identifier_and_parameter_list_ride_every_message() -> None:
    """RFC 2131 section 4.4.1 paragraph 1: the request list goes in all subsequent messages."""
    mine = encode_client_id(7, b"\x00\x03\x00\x01" + MAC)
    client = Client4(MAC, rng=Rng(), client_id=mine, parameter_request_list=bytes([1, 3, 6]))
    (discover,) = sent(client.start(0.0))
    offer = reply(DhcpMessageType.OFFER, extra=(Option4(61, mine),))
    (request,) = sent(client.receive(offer, 1.0))
    for message in (discover.message, request.message):
        assert message.option(61) == mine
        assert message.option(55) == bytes([1, 3, 6])


def test_a_chaddr_over_sixteen_octets_is_refused() -> None:
    import pytest

    with pytest.raises(ValueError, match="chaddr"):
        Client4(bytes(17), rng=Rng())
