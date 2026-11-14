"""The ARP probe and conflict rules of RFC 5227, over the packet layout of RFC 826.

RFC 5227 prints no packet in octets, so the expected bytes are written out here from the field
rules of RFC 5227 section 1.1 (ARP Probe, ARP Announcement) and the layout of RFC 826: hardware
type 1, protocol type 0x0800 (RFC 894), lengths 6 and 4, opcode 1 for a request.
"""

from __future__ import annotations

import pytest

from leasespy import arp
from leasespy.arp import ArpPacket
from leasespy.errors import DhcpError

ME = bytes.fromhex("02aabbccdd01")
OTHER = bytes.fromhex("02aabbccdd02")
ADDR = bytes([192, 0, 2, 9])
HEADER = bytes.fromhex("0001080006040001")


def test_a_probe_has_a_zero_sender_ip_our_hardware_zero_target_hardware_and_the_probed_target() -> (
    None
):
    wire = arp.encode_probe(ME, "192.0.2.9")
    assert wire == HEADER + ME + bytes(4) + bytes(6) + ADDR
    assert len(wire) == arp.ARP_LENGTH
    packet = arp.decode_arp(wire)
    assert arp.is_probe(packet)
    assert not arp.is_announcement(packet)


def test_an_announcement_is_a_probe_with_the_address_in_both_ip_fields() -> None:
    wire = arp.encode_announcement(ME, ADDR)
    assert wire == HEADER + ME + ADDR + bytes(6) + ADDR
    packet = arp.decode_arp(wire)
    assert arp.is_announcement(packet)
    assert not arp.is_probe(packet)


def test_decoding_round_trips_and_ignores_ethernet_padding() -> None:
    wire = arp.encode_probe(ME, ADDR) + bytes(18)
    assert arp.encode_arp(arp.decode_arp(wire)) == wire[: arp.ARP_LENGTH]


def test_a_reply_is_decoded_and_is_not_a_request() -> None:
    reply = ArpPacket(2, OTHER, ADDR, ME, bytes([192, 0, 2, 1]))
    packet = arp.decode_arp(arp.encode_arp(reply))
    assert packet == reply
    assert not packet.is_request


@pytest.mark.parametrize(
    "mutate",
    [
        lambda w: w[:27],  # short
        lambda w: b"\x00\x06" + w[2:],  # hardware type not Ethernet
        lambda w: w[:2] + b"\x86\xdd" + w[4:],  # protocol type not IPv4
        lambda w: w[:4] + b"\x08" + w[5:],  # hardware length 8
        lambda w: w[:5] + b"\x10" + w[6:],  # protocol length 16
        lambda w: w[:6] + b"\x00\x03" + w[8:],  # opcode 3
        lambda w: w[:6] + b"\x00\x00" + w[8:],  # opcode 0
    ],
)
def test_a_packet_that_is_not_ethernet_ipv4_arp_is_refused(mutate) -> None:
    with pytest.raises(DhcpError):
        arp.decode_arp(mutate(arp.encode_probe(ME, ADDR)))


def test_bad_addresses_are_refused_when_building() -> None:
    with pytest.raises(DhcpError):
        arp.encode_probe(ME, "300.1.1.1")
    with pytest.raises(DhcpError):
        arp.encode_probe(ME, b"\x01\x02\x03")
    with pytest.raises(DhcpError):
        arp.encode_probe(b"\x01\x02", ADDR)


# ------------------------------------------------------------------ section 2.1.1


def test_the_probe_schedule_waits_then_sends_three_probes_and_clears_two_seconds_after_the_last() -> (
    None
):
    low = arp.probe_schedule(lambda a, _b: a)
    assert low.send_at == (0.0, 1.0, 2.0)
    assert low.clear_at == 4.0
    high = arp.probe_schedule(lambda _a, b: b)
    assert high.send_at == (1.0, 3.0, 5.0)
    assert high.clear_at == 7.0
    assert len(high.send_at) == arp.PROBE_NUM


def test_the_schedule_asks_for_the_random_ranges_the_text_gives() -> None:
    asked: list[tuple[float, float]] = []

    def uniform(a: float, b: float) -> float:
        asked.append((a, b))
        return a

    arp.probe_schedule(uniform)
    assert asked == [
        (0.0, arp.PROBE_WAIT),
        (arp.PROBE_MIN, arp.PROBE_MAX),
        (arp.PROBE_MIN, arp.PROBE_MAX),
    ]


def test_any_packet_with_the_probed_address_as_sender_is_a_conflict_request_or_reply() -> None:
    request = ArpPacket(1, OTHER, ADDR, bytes(6), bytes([192, 0, 2, 1]))
    reply = ArpPacket(2, OTHER, ADDR, ME, bytes([192, 0, 2, 1]))
    assert arp.probe_conflict(request, ADDR, [ME])
    assert arp.probe_conflict(reply, "192.0.2.9", [ME])


def test_another_hosts_probe_for_the_same_address_is_a_conflict_but_our_own_echo_is_not() -> None:
    theirs = arp.decode_arp(arp.encode_probe(OTHER, ADDR))
    ours = arp.decode_arp(arp.encode_probe(ME, ADDR))
    assert arp.probe_conflict(theirs, ADDR, [ME])
    assert not arp.probe_conflict(ours, ADDR, [ME])  # a hub echoing our packet back
    assert arp.probe_conflict(
        ours, ADDR, [OTHER]
    )  # the same packet is foreign to a host that is not us


def test_unrelated_arp_traffic_is_not_a_conflict() -> None:
    other_target = arp.decode_arp(arp.encode_probe(OTHER, bytes([192, 0, 2, 77])))
    chatter = ArpPacket(1, OTHER, bytes([192, 0, 2, 5]), bytes(6), ADDR)  # asking who has ADDR
    assert not arp.probe_conflict(other_target, ADDR, [ME])
    assert not arp.probe_conflict(chatter, ADDR, [ME])


def test_the_rate_limit_starts_at_ten_conflicts() -> None:
    assert arp.probe_gap(arp.MAX_CONFLICTS - 1) == 0.0
    assert arp.probe_gap(arp.MAX_CONFLICTS) == arp.RATE_LIMIT_INTERVAL == 60.0
    assert arp.probe_gap(500) == 60.0


# ------------------------------------------------------------------ sections 2.3 and 2.4


def test_two_announcements_two_seconds_apart() -> None:
    assert arp.announce_schedule().send_at == (0.0, 2.0)
    assert arp.announce_schedule(10.0).send_at == (10.0, 12.0)
    assert arp.announce_schedule().clear_at is None


def test_a_later_claim_to_our_address_from_other_hardware_is_a_conflict() -> None:
    claim = ArpPacket(2, OTHER, ADDR, ME, ADDR)
    echo = ArpPacket(1, ME, ADDR, bytes(6), ADDR)
    probe = arp.decode_arp(
        arp.encode_probe(OTHER, ADDR)
    )  # sender IP zero: section 2.1.1's, not 2.4's
    assert arp.use_conflict(claim, ADDR, [ME])
    assert not arp.use_conflict(echo, ADDR, [ME])
    assert not arp.use_conflict(probe, ADDR, [ME])


def test_defence_is_allowed_once_and_a_second_conflict_within_ten_seconds_means_cease() -> None:
    assert arp.defend_or_cease(None, 100.0) == "announce"
    assert arp.defend_or_cease(95.0, 100.0) == "cease"
    assert arp.defend_or_cease(89.0, 100.0) == "announce"
    assert (
        arp.defend_or_cease(90.0, 100.0) == "announce"
    )  # exactly DEFEND_INTERVAL ago is not within it
