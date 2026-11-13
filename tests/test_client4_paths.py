"""DHCPv4 client: INIT-REBOOT, DHCPINFORM, DHCPDECLINE and DHCPRELEASE (RFC 2131 section 4.4).

Every expectation is a rule read from the section it names, including Table 5 of section 4.4.1
(the fields and options each message may and must carry).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from leasespy.client4 import (
    DECLINE_WAIT,
    Bound,
    Client4,
    ClientState,
    GaveUp,
    Inform4,
    Informed,
    Lost,
    Send,
)
from leasespy.options4 import Option4
from leasespy.wire4 import DhcpMessage4, DhcpMessageType

MAC = bytes.fromhex("00053c048d59")
SERVER = bytes([192, 0, 2, 1])
ADDRESS = bytes([192, 0, 2, 50])
XID = 0x01020304
ZERO = bytes(4)


class Rng:
    """A scripted random source: no jitter and one fixed transaction identifier."""

    def uniform(self, a: float, b: float) -> float:
        return 0.0

    def randint(self, a: int, b: int) -> int:
        return XID


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


def bound_client(lease=3600, client_id=None, parameter_request_list=b""):
    client = Client4(
        MAC, rng=Rng(), client_id=client_id, parameter_request_list=parameter_request_list
    )
    extra = (Option4(61, client_id),) if client_id is not None else ()
    client.start(0.0)
    client.receive(reply(DhcpMessageType.OFFER, extra=extra), 1.0)
    client.receive(reply(DhcpMessageType.ACK, lease=lease, extra=extra), 2.0)
    return client, None


def test_init_reboot_requests_the_remembered_address() -> None:
    """RFC 2131 section 4.4.2 paragraph 1 and Table 5."""
    client = Client4(MAC, rng=Rng(), parameter_request_list=bytes([1, 3]))
    (send,) = sent(client.start_reboot(5.0, ADDRESS))
    message = send.message
    assert client.state is ClientState.REBOOTING
    assert send.unicast_to is None  # broadcast
    assert message.message_type == DhcpMessageType.REQUEST
    assert message.option(50) == ADDRESS  # the requested IP address: MUST
    assert message.option(54) is None  # the server identifier: MUST NOT
    assert message.ciaddr == ZERO  # section 3.2 paragraph 2: MUST NOT fill in ciaddr
    assert message.xid == XID
    assert message.option(55) == bytes([1, 3])  # the list rides every message (4.4.1 para 1)
    assert message.broadcast


def test_an_ack_from_any_server_binds_and_the_lease_counts_from_the_request() -> None:
    """Section 4.4.2 paragraph 2."""
    client = Client4(MAC, rng=Rng())
    client.start_reboot(5.0, ADDRESS)
    other = bytes([192, 0, 2, 77])
    actions = client.receive(reply(DhcpMessageType.ACK, server=other, lease=1000), 6.0)
    (bound,) = (a for a in actions if isinstance(a, Bound))
    assert client.state is ClientState.BOUND
    assert bound.address == ADDRESS
    assert bound.server_id == other
    assert bound.leased_at == 5.0
    assert bound.t1 == pytest.approx(5.0 + 500.0)


def test_a_reboot_ack_with_the_wrong_xid_is_discarded() -> None:
    client = Client4(MAC, rng=Rng())
    client.start_reboot(0.0, ADDRESS)
    assert client.receive(reply(DhcpMessageType.ACK, xid=XID + 1), 1.0) == []
    assert client.state is ClientState.REBOOTING


def test_a_nak_in_init_reboot_restarts_with_a_discover() -> None:
    """Section 3.2 paragraph 10: the remembered address cannot be reused."""
    client = Client4(MAC, rng=Rng())
    client.start_reboot(0.0, ADDRESS)
    actions = client.receive(reply(DhcpMessageType.NAK, yiaddr=ZERO), 1.0)
    assert Lost(ADDRESS, "NAK") in actions
    (send,) = sent(actions)
    assert send.message.message_type == DhcpMessageType.DISCOVER
    assert client.state is ClientState.SELECTING


def test_init_reboot_retransmits_the_same_request_on_the_4_8_16_schedule() -> None:
    """Section 3.2 paragraph 11 and section 4.1."""
    client = Client4(MAC, rng=Rng())
    client.start_reboot(0.0, ADDRESS)
    assert client.tick(3.9) == []
    (again,) = sent(client.tick(4.0))
    assert again.message.xid == XID
    assert again.message.option(50) == ADDRESS
    assert again.message.option(54) is None
    assert client.tick(11.9) == []
    assert len(sent(client.tick(12.0))) == 1  # 4 then 8 seconds later


def test_a_reboot_client_refuses_an_unusable_address() -> None:
    with pytest.raises(ValueError, match="remembered"):
        Client4(MAC, rng=Rng()).start_reboot(0.0, ZERO)


def test_a_reboot_ack_without_a_server_identifier_renews_by_broadcast() -> None:
    """Section 4.4.2 does not require the ACK to name its server (RFC 2132 section 9.7: optional)."""
    client = Client4(MAC, rng=Rng())
    client.start_reboot(0.0, ADDRESS)
    ack = reply(DhcpMessageType.ACK, lease=1000)
    ack = replace(ack, options=tuple(o for o in ack.options if o.code != 54))
    client.receive(ack, 1.0)
    (send,) = sent(client.tick(501.0))
    assert send.unicast_to is None  # there is no server to unicast to


def test_decline_after_an_address_conflict() -> None:
    """Section 4.4.1 paragraph 8 and Table 5, section 4.4.4 paragraph 1, section 3.1 paragraph 18."""
    client, _ = bound_client(parameter_request_list=bytes([1, 3]), client_id=b"\x01abc")
    actions = client.address_in_use(10.0)
    (send,) = sent(actions)
    message = send.message
    assert message.message_type == DhcpMessageType.DECLINE
    assert send.unicast_to is None  # the client broadcasts DHCPDECLINE
    assert message.ciaddr == ZERO
    assert message.flags == 0
    assert message.option(50) == ADDRESS  # requested IP address: MUST
    assert message.option(54) == SERVER  # server identifier: MUST
    assert message.option(55) is None  # parameter request list: MUST NOT
    assert message.option(51) is None  # lease time: MUST NOT
    assert message.option(61) == b"\x01abc"  # client identifier: MAY
    assert Lost(ADDRESS, "address in use") in actions
    assert client.state is ClientState.INIT
    assert client.restart_not_before == 10.0 + DECLINE_WAIT
    assert DECLINE_WAIT == 10.0


def test_a_client_that_declined_can_start_again_after_the_wait() -> None:
    client, _ = bound_client()
    client.address_in_use(10.0)
    (send,) = sent(client.start(client.restart_not_before))
    assert send.message.message_type == DhcpMessageType.DISCOVER
    assert client.state is ClientState.SELECTING


def test_only_a_bound_client_can_decline_or_release() -> None:
    fresh = Client4(MAC, rng=Rng())
    with pytest.raises(ValueError, match="bound"):
        fresh.address_in_use(0.0)
    with pytest.raises(ValueError, match="no lease"):
        fresh.release()


def test_release_is_unicast_with_ciaddr_and_the_server_and_no_requested_address() -> None:
    """Section 4.4.6, Table 5, section 4.4.4 paragraph 1."""
    client, _ = bound_client(parameter_request_list=bytes([1]))
    actions = client.release()
    (send,) = sent(actions)
    message = send.message
    assert message.message_type == DhcpMessageType.RELEASE
    assert send.unicast_to == SERVER
    assert message.ciaddr == ADDRESS
    assert message.flags == 0
    assert message.option(54) == SERVER  # server identifier: MUST
    assert message.option(50) is None  # requested IP address: MUST NOT
    assert message.option(55) is None
    assert Lost(ADDRESS, "released") in actions
    assert client.state is ClientState.INIT
    assert client.next_deadline is None


def test_release_while_renewing_is_allowed() -> None:
    client, _ = bound_client(lease=1000)
    client.tick(501.0)
    assert client.state is ClientState.RENEWING
    (send,) = sent(client.release())
    assert send.message.message_type == DhcpMessageType.RELEASE


# ----------------------------------------------------------------------------- DHCPINFORM


def inform_ack(xid: int = XID) -> DhcpMessage4:
    extra = (Option4(6, bytes([192, 0, 2, 53])),)
    return reply(DhcpMessageType.ACK, xid=xid, yiaddr=ZERO, lease=None, extra=extra)


def test_inform_has_ciaddr_and_none_of_the_forbidden_options() -> None:
    """Section 4.4.3 paragraph 1 and Table 5: no requested IP, no lease time, no server id."""
    inform = Inform4(MAC, ADDRESS, rng=Rng(), parameter_request_list=bytes([6, 15]))
    (send,) = sent(inform.start(0.0))
    message = send.message
    assert message.message_type == DhcpMessageType.INFORM
    assert message.ciaddr == ADDRESS
    assert message.option(50) is None
    assert message.option(51) is None
    assert message.option(54) is None
    assert message.option(55) == bytes([6, 15])
    assert message.xid == XID
    assert send.unicast_to is None  # no known server: broadcast (paragraph 2)


def test_inform_is_unicast_to_a_known_server() -> None:
    inform = Inform4(MAC, ADDRESS, rng=Rng(), server=SERVER)
    (send,) = sent(inform.start(0.0))
    assert send.unicast_to == SERVER


def test_an_ack_with_the_same_xid_finishes_the_inform() -> None:
    inform = Inform4(MAC, ADDRESS, rng=Rng())
    inform.start(0.0)
    assert inform.receive(inform_ack(xid=XID + 1), 1.0) == []
    (done,) = inform.receive(inform_ack(), 1.0)
    assert isinstance(done, Informed)
    assert done.server_id == SERVER
    assert any(o.code == 6 for o in done.options)
    assert inform.done
    assert inform.tick(10**6) == []  # nothing more to send
    assert inform.receive(inform_ack(), 2.0) == []


def test_inform_retransmits_with_the_same_xid_and_gives_up_after_four_tries() -> None:
    """Section 4.4.3 paragraph 4: 60 seconds or 4 tries."""
    inform = Inform4(MAC, ADDRESS, rng=Rng())
    inform.start(0.0)
    times = [0.0]
    now = 0.0
    while not inform.done:
        now = inform.next_deadline or now
        actions = inform.tick(now)
        for a in actions:
            if isinstance(a, Send):
                assert a.message.xid == XID
                times.append(now)
            if isinstance(a, GaveUp):
                assert a.tries == 4
    assert times == [0.0, 4.0, 12.0, 28.0]
    assert now == 60.0  # 4 + 8 + 16 + 32 seconds, the last wait ends the tries


def test_inform_discards_a_reply_for_another_client_identifier() -> None:
    inform = Inform4(MAC, ADDRESS, rng=Rng(), client_id=b"\x01abc")
    inform.start(0.0)
    assert inform.receive(inform_ack(), 1.0) == []  # the ACK carries no identifier


def test_inform_refuses_no_address() -> None:
    with pytest.raises(ValueError, match="own configured address"):
        Inform4(MAC, ZERO, rng=Rng())
