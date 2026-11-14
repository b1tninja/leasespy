"""The ARP probe of IPv4 Address Conflict Detection, as pure functions (RFC 5227, RFC 826).

RFC 2131 section 4.4.1 asks a DHCP client to probe an offered address before using it, and to send
DHCPDECLINE if the probe finds it in use. The probe itself is ARP, so it is not part of the DHCP
state machine: :meth:`leasespy.client4.Client4.address_in_use` takes its verdict. This module builds
the packets, decides what a received packet means, and lays out the schedule, and nothing here
opens a socket, reads a clock or draws a random number: the caller supplies the ``uniform``
function, the time and the frame around the packet.

What is here, each pinned by ``tests/test_arp.py``:

* the 28-octet ARP packet of RFC 826 for Ethernet and IPv4 (:func:`encode_arp`,
  :func:`decode_arp`), with the ARP Probe, the ARP Announcement and the defence announcement of
  RFC 5227 sections 1.1, 2.1.1, 2.3 and 2.4 built on it. The Ethernet header is the caller's;
* :func:`probe_schedule` and :func:`announce_schedule`: the times at which packets are sent and at
  which an address may be taken as clear (section 2.1.1, section 2.3);
* :func:`probe_conflict` and :func:`use_conflict`: whether a received packet means the address is
  taken, during probing (section 2.1.1) and afterwards (section 2.4);
* :func:`defend_or_cease`: the choice of section 2.4 paragraph (b);
* :func:`probe_gap`: the rate limit of section 2.1.1 after ten conflicts.

Not here: the Ethernet frame, an ARP responder, broadcast ARP replies (section 2.6), and the choice
between sections 2.4 (a), (b) and (c), which is policy.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Callable, Collection
from dataclasses import dataclass

from .errors import DhcpError

__all__ = [
    "ANNOUNCE_INTERVAL",
    "ANNOUNCE_NUM",
    "ANNOUNCE_WAIT",
    "ARP_LENGTH",
    "DEFEND_INTERVAL",
    "MAX_CONFLICTS",
    "PROBE_MAX",
    "PROBE_MIN",
    "PROBE_NUM",
    "PROBE_WAIT",
    "RATE_LIMIT_INTERVAL",
    "ArpPacket",
    "Schedule",
    "announce_schedule",
    "decode_arp",
    "defend_or_cease",
    "encode_announcement",
    "encode_arp",
    "encode_probe",
    "is_announcement",
    "is_probe",
    "probe_conflict",
    "probe_gap",
    "probe_schedule",
    "use_conflict",
]

# RFC 5227 section 1.1, the table of timing constants.
PROBE_WAIT = 1.0
PROBE_NUM = 3
PROBE_MIN = 1.0
PROBE_MAX = 2.0
ANNOUNCE_WAIT = 2.0
ANNOUNCE_NUM = 2
ANNOUNCE_INTERVAL = 2.0
MAX_CONFLICTS = 10
RATE_LIMIT_INTERVAL = 60.0
DEFEND_INTERVAL = 10.0

ARP_LENGTH = 28  # 8 octets of header and two 6-octet and two 4-octet addresses
_HTYPE_ETHERNET = 1  # RFC 826: ares_hrd$Ethernet (= 1)
_PTYPE_IPV4 = 0x0800  # RFC 894: the Ethernet type of IP, which RFC 826 reuses for ar$pro
_OP_REQUEST = 1  # RFC 826: ares_op$REQUEST
_OP_REPLY = 2  # RFC 826: ares_op$REPLY
_ZERO_IP = b"\x00\x00\x00\x00"
_ZERO_MAC = bytes(6)
_FORMAT = ">HHBBH6s4s6s4s"


@dataclass(frozen=True, slots=True)
class ArpPacket:
    """The fields of an Ethernet and IPv4 ARP packet. Addresses are raw octets."""

    op: int
    sender_hw: bytes
    sender_ip: bytes
    target_hw: bytes
    target_ip: bytes

    @property
    def is_request(self) -> bool:
        return self.op == _OP_REQUEST


def _ip(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 4:
            raise DhcpError(f"an IPv4 address is 4 octets, not {len(value)}")
        return value
    try:
        return ipaddress.IPv4Address(value).packed
    except ValueError as exc:
        raise DhcpError(f"not an IPv4 address: {value!r}") from exc


def _mac(value: bytes) -> bytes:
    if len(value) != 6:
        raise DhcpError(f"an Ethernet address is 6 octets, not {len(value)}")
    return bytes(value)


def encode_arp(packet: ArpPacket) -> bytes:
    """The 28 octets of RFC 826 for hardware type Ethernet and protocol type IPv4."""
    return struct.pack(
        _FORMAT,
        _HTYPE_ETHERNET,
        _PTYPE_IPV4,
        6,
        4,
        packet.op,
        _mac(packet.sender_hw),
        _ip(packet.sender_ip),
        _mac(packet.target_hw),
        _ip(packet.target_ip),
    )


def decode_arp(data: bytes) -> ArpPacket:
    """Read an Ethernet and IPv4 ARP packet; anything else raises :class:`DhcpError`.

    Octets after the 28th are ignored, because an Ethernet frame is padded to its minimum size.
    The hardware type, protocol type and both address lengths must be those of Ethernet and IPv4
    and the opcode must be a request or a reply: RFC 5227 uses ARP for IPv4 on Ethernet only, and a
    packet that is not that cannot conflict with an address.
    """
    if len(data) < ARP_LENGTH:
        raise DhcpError(f"an ARP packet is {ARP_LENGTH} octets, got {len(data)}")
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = struct.unpack_from(_FORMAT, data)
    if (htype, ptype, hlen, plen) != (_HTYPE_ETHERNET, _PTYPE_IPV4, 6, 4):
        raise DhcpError("not an Ethernet and IPv4 ARP packet")
    if op not in (_OP_REQUEST, _OP_REPLY):
        raise DhcpError(f"ARP opcode {op} is neither a request nor a reply")
    return ArpPacket(op, sha, spa, tha, tpa)


def encode_probe(hardware: bytes, address: str | bytes) -> bytes:
    """An ARP Probe (RFC 5227 section 1.1 and section 2.1.1).

    A request whose sender IP address is all zeroes, so that a host already using the address does
    not learn ours into its cache; the sender hardware address is ours, the target hardware address
    is zeroes ("SHOULD"), and the target IP address is the one being probed.
    """
    return encode_arp(ArpPacket(_OP_REQUEST, _mac(hardware), _ZERO_IP, _ZERO_MAC, _ip(address)))


def encode_announcement(hardware: bytes, address: str | bytes) -> bytes:
    """An ARP Announcement (section 1.1, section 2.3): a probe whose sender IP is the address.

    The same packet is the defence of section 2.4 paragraph (b): our own hardware and IP address as
    sender, the target IP address our own, and the target hardware address zeroes.
    """
    ip = _ip(address)
    return encode_arp(ArpPacket(_OP_REQUEST, _mac(hardware), ip, _ZERO_MAC, ip))


def is_probe(packet: ArpPacket) -> bool:
    """A request with an all-zero sender IP address (section 1.1)."""
    return packet.is_request and packet.sender_ip == _ZERO_IP


def is_announcement(packet: ArpPacket) -> bool:
    """A request whose sender and target IP addresses are the same non-zero address."""
    return (
        packet.is_request and packet.sender_ip == packet.target_ip and packet.sender_ip != _ZERO_IP
    )


# --------------------------------------------------------------------------- schedules


@dataclass(frozen=True, slots=True)
class Schedule:
    """Times in seconds from the start: when to send, and when the address is clear.

    ``clear_at`` is None for an announcement schedule, which has no waiting period.
    """

    send_at: tuple[float, ...]
    clear_at: float | None


def probe_schedule(uniform: Callable[[float, float], float]) -> Schedule:
    """When to send the probes of section 2.1.1, and when the address may be used.

    A random wait of zero to PROBE_WAIT seconds, then PROBE_NUM probes "spaced randomly and
    uniformly, PROBE_MIN to PROBE_MAX seconds apart". The address is clear ANNOUNCE_WAIT seconds
    after the last probe if nothing conflicting arrived. ``uniform(a, b)`` is the caller's random
    source, so a test supplies fixed values.
    """
    at = uniform(0.0, PROBE_WAIT)
    times = [at]
    for _ in range(PROBE_NUM - 1):
        at += uniform(PROBE_MIN, PROBE_MAX)
        times.append(at)
    return Schedule(tuple(times), times[-1] + ANNOUNCE_WAIT)


def announce_schedule(start: float = 0.0) -> Schedule:
    """ANNOUNCE_NUM announcements, ANNOUNCE_INTERVAL seconds apart, from ``start`` (section 2.3)."""
    return Schedule(tuple(start + n * ANNOUNCE_INTERVAL for n in range(ANNOUNCE_NUM)), None)


def probe_gap(conflicts: int) -> float:
    """The least time between attempts on new addresses after ``conflicts`` conflicts so far.

    Section 2.1.1: after MAX_CONFLICTS or more conflicts on an interface, "no more than one
    attempted new address per RATE_LIMIT_INTERVAL". Below that there is no limit.
    """
    return RATE_LIMIT_INTERVAL if conflicts >= MAX_CONFLICTS else 0.0


# --------------------------------------------------------------------------- conflicts


def probe_conflict(
    packet: ArpPacket, address: str | bytes, own_hardware: Collection[bytes]
) -> bool:
    """Whether ``packet`` means ``address`` is taken, from the start of probing to the end.

    Section 2.1.1: "any ARP packet (Request *or* Reply)" whose sender IP address is the address
    being probed is a conflict; so, by "SHOULD", is an ARP Probe for the same target address whose
    sender hardware address is not one of ours (two hosts probing at once). The second test needs
    ``own_hardware`` because a hub or an access point may echo our own probe back. The first test
    applies whoever the sender is, exactly as the text reads.
    """
    target = _ip(address)
    if packet.sender_ip == target:
        return True
    return is_probe(packet) and packet.target_ip == target and packet.sender_hw not in own_hardware


def use_conflict(packet: ArpPacket, address: str | bytes, own_hardware: Collection[bytes]) -> bool:
    """Whether ``packet`` is a conflicting ARP packet for an address we use (section 2.4).

    Any request or reply whose sender IP address is ours and whose sender hardware address is none
    of our interfaces'. A probe has a zero sender address, so it never matches here.
    """
    return packet.sender_ip == _ip(address) and packet.sender_hw not in own_hardware


def defend_or_cease(last_conflict: float | None, now: float) -> str:
    """Section 2.4 paragraph (b): ``"announce"`` once, or ``"cease"`` on a repeat within ten seconds.

    ``last_conflict`` is when the previous conflicting packet was seen, None for the first. A host
    with active connections that has seen none within DEFEND_INTERVAL seconds may defend by
    broadcasting one announcement (:func:`encode_announcement`); if the previous conflict is
    recent it "MUST immediately cease using this address". The caller records ``now`` either way.
    """
    if last_conflict is not None and now - last_conflict < DEFEND_INTERVAL:
        return "cease"
    return "announce"
