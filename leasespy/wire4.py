"""DHCPv4 message format (RFC 2131 section 2, RFC 2132 section 9.3, RFC 3396, RFC 6842).

The fixed header is 236 octets (RFC 2131 section 2, Figure 1), then the 4-octet magic cookie and
the options. A message without the cookie is a plain BOOTP message: it decodes with no options and
its vendor field kept raw, so a caller can tell the two apart and nothing is guessed.

The option overload of RFC 2132 section 9.3 is read here: when option 52 says so, ``file`` and
``sname`` hold options and are read after the options field, in the order of RFC 3396 section 5
(options, file, sname). A message that overloads a field returns that field empty, because its
octets are options and not a string. Encoding puts every option in the options field, split where
RFC 3396 section 6 requires, unless the caller gives ``options_limit``: then options that do not
fit spill into ``file`` and ``sname`` and option 52 says so (RFC 2132 section 9.3).

Nothing here applies the discard rules of RFC 2131 section 4.3 or RFC 6842 section 3 paragraph 4;
those belong to a state machine.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass

from .errors import DhcpError
from .options4 import (
    MAGIC_COOKIE,
    OPTION_END,
    OPTION_MESSAGE_TYPE,
    OPTION_OVERLOAD,
    Option4,
    aggregate,
    decode_options4,
    encode_options4,
)

__all__ = [
    "BOOTREPLY",
    "BOOTREQUEST",
    "BROADCAST_FLAG",
    "DhcpMessage4",
    "DhcpMessageType",
    "decode_message4",
    "encode_message4",
]

BOOTREQUEST = 1  # RFC 2131 section 2, Table 1
BOOTREPLY = 2
BROADCAST_FLAG = 0x8000  # RFC 2131 section 2, Figure 2: the leftmost bit
_FIXED = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
_OVERLOAD_FILE, _OVERLOAD_SNAME = 1, 2
_MAX_PART = 255


class DhcpMessageType(enum.IntEnum):
    """Option 53 values that RFC 2132 section 9.6 and later documents define for the client."""

    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


@dataclass(frozen=True, slots=True)
class DhcpMessage4:
    """A DHCPv4 or BOOTP message. Addresses are 4 raw octets; ``chaddr`` is ``hlen`` octets.

    ``options`` are aggregated (RFC 3396): one entry per code. ``sname`` and ``file`` are the raw
    fields up to their first NUL, or empty when option overload made them option storage.
    ``vendor`` is the raw bytes after the fixed header when the magic cookie is absent.
    """

    op: int
    htype: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: bytes
    yiaddr: bytes
    siaddr: bytes
    giaddr: bytes
    chaddr: bytes
    sname: bytes = b""
    file: bytes = b""
    options: tuple[Option4, ...] = ()
    vendor: bytes = b""
    has_cookie: bool = True

    @property
    def broadcast(self) -> bool:
        """The B flag (RFC 2131 section 2, Figure 2)."""
        return bool(self.flags & BROADCAST_FLAG)

    def option(self, code: int) -> bytes | None:
        """Data of the (aggregated) option ``code``, or None when it is absent."""
        for option in self.options:
            if option.code == code:
                return option.data
        return None

    @property
    def message_type(self) -> int | None:
        """Option 53 as an integer. A value that is not exactly one octet raises DhcpError."""
        data = self.option(OPTION_MESSAGE_TYPE)
        if data is None:
            return None
        if len(data) != 1:
            raise DhcpError(f"DHCP message type option of {len(data)} octets, must be 1")
        return data[0]


def _text(field: bytes) -> bytes:
    """A sname or file field up to its first NUL (RFC 2131 section 2, Table 1: null terminated)."""
    return field.split(b"\x00", 1)[0]


def decode_message4(raw: bytes) -> DhcpMessage4:
    """Decode a DHCPv4 or BOOTP message (RFC 2131 section 2).

    Raises :class:`DhcpError` for a datagram shorter than 236 octets, an ``op`` other than 1 or 2,
    an ``hlen`` above 16, and malformed options. Unknown option codes are kept.
    """
    data = bytes(raw)
    if len(data) < _FIXED.size:
        raise DhcpError(f"DHCPv4 message of {len(data)} octets is shorter than 236")
    (
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        sname,
        file,
    ) = _FIXED.unpack_from(data)
    if op not in (BOOTREQUEST, BOOTREPLY):
        raise DhcpError(f"op {op} is neither BOOTREQUEST (1) nor BOOTREPLY (2)")
    if hlen > 16:
        raise DhcpError(f"hlen {hlen} exceeds the 16-octet chaddr field")
    tail = data[_FIXED.size :]
    if tail[:4] != MAGIC_COOKIE:
        return DhcpMessage4(
            op, htype, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr[:hlen],
            _text(sname), _text(file), (), tail, False,
        )  # fmt: skip
    parts = decode_options4(tail[4:])
    overload = 0
    for part in parts:
        if part.code == OPTION_OVERLOAD:
            if len(part.data) != 1 or part.data[0] not in (1, 2, 3):
                raise DhcpError("option overload must be one octet with the value 1, 2 or 3")
            overload = part.data[0]
    if overload & _OVERLOAD_FILE:
        parts += decode_options4(file)
        file = b""
    if overload & _OVERLOAD_SNAME:
        parts += decode_options4(sname)
        sname = b""
    return DhcpMessage4(
        op, htype, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr[:hlen],
        _text(sname), _text(file), aggregate(parts), b"", True,
    )  # fmt: skip


def _cost(data: bytes) -> int:
    """Octets one option takes whole: a 2-octet header per part of at most 255 octets."""
    return len(data) + 2 * max(1, -(-len(data) // _MAX_PART))


def _pack(options: tuple[Option4, ...], capacities: list[int]) -> list[bytearray] | None:
    """Place options in buffers of the given capacities (End excluded), or None if they do not fit.

    An option goes whole into the first buffer with room (first fit). One that fits nowhere whole
    is split on an octet boundary across the buffers in the aggregate order of RFC 3396 section 5
    paragraph 4, every part carrying the same code, none above 255 octets and none crossing a
    boundary (section 5 paragraph 6, section 6 paragraphs 2 to 4). Splitting is the last resort:
    section 4 paragraph 5 says to split only when there is no choice.
    """
    buffers = [bytearray() for _ in capacities]
    for option in options:
        if not 1 <= option.code <= 254:
            raise DhcpError(f"option code {option.code} cannot be encoded (0 is Pad, 255 is End)")
        data = bytes(option.data)
        cost = _cost(data)
        for buffer, capacity in zip(buffers, capacities, strict=True):
            if len(buffer) + cost <= capacity:
                buffer += encode_options4([option], end=False)
                break
        else:
            rest = data
            for buffer, capacity in zip(buffers, capacities, strict=True):
                while rest and capacity - len(buffer) >= 3:
                    take = min(_MAX_PART, capacity - len(buffer) - 2, len(rest))
                    buffer += bytes((option.code, take)) + rest[:take]
                    rest = rest[take:]
            if rest or not data:
                return None
    return buffers


def _options_area(message: DhcpMessage4, options_limit: int) -> tuple[bytes, bytes, bytes]:
    """The options field, ``file`` and ``sname`` octets for a message under ``options_limit``."""
    if options_limit < 2:
        raise DhcpError("options_limit must leave room for at least one option and End")
    if any(option.code == OPTION_OVERLOAD for option in message.options):
        raise DhcpError("option 52 is set by the encoder when it overloads; do not supply it")
    whole = _pack(message.options, [options_limit - 1])
    if whole is not None:
        return bytes(whole[0]) + bytes((OPTION_END,)), message.file, message.sname
    # RFC 2131 section 4.1 and RFC 2132 section 9.3: only a field the message does not use as a
    # string can hold options. Tried in order: file, sname, both (values 1, 2, 3).
    free = [(_OVERLOAD_FILE, 127), (_OVERLOAD_SNAME, 63)]
    free = [
        (bit, cap)
        for bit, cap in free
        if not (message.file if bit == _OVERLOAD_FILE else message.sname)
    ]
    choices = [[entry] for entry in free] + ([free] if len(free) == 2 else [])
    for chosen in choices:
        value = sum(bit for bit, _ in chosen)
        capacities = [options_limit - 1 - 3] + [cap for _, cap in chosen]
        if capacities[0] < 0:
            continue
        buffers = _pack(message.options, capacities)
        if buffers is None:
            continue
        first = bytes((OPTION_OVERLOAD, 1, value)) + bytes(buffers[0]) + bytes((OPTION_END,))
        extra = {
            bit: bytes(buf) + bytes((OPTION_END,))
            for (bit, _), buf in zip(chosen, buffers[1:], strict=True)
        }
        return (
            first,
            extra.get(_OVERLOAD_FILE, message.file),
            extra.get(_OVERLOAD_SNAME, message.sname),
        )
    raise DhcpError(f"the options do not fit in {options_limit} octets, even overloaded")


def encode_message4(message: DhcpMessage4, *, options_limit: int | None = None) -> bytes:
    """Encode a message; options go in the options field, split per RFC 3396 section 6.

    ``options_limit`` is the number of octets the options field may take after the magic cookie.
    The caller derives it from the link or from option 57, because RFC 2132 section 9.10 does not
    say whether the 28 octets of IP and UDP header count toward the "maximum length DHCP message".
    When the options do not fit, they spill into ``file`` and then ``sname`` and option 52 is
    added (RFC 2132 section 9.3, RFC 3396 section 5), but only into a field the message does not
    already use for a string. A message that cannot fit even so raises :class:`DhcpError`.
    """
    if message.op not in (BOOTREQUEST, BOOTREPLY):
        raise DhcpError("op must be 1 or 2")
    for name in ("ciaddr", "yiaddr", "siaddr", "giaddr"):
        if len(getattr(message, name)) != 4:
            raise DhcpError(f"{name} must be 4 octets")
    if len(message.chaddr) > 16:
        raise DhcpError("chaddr is at most 16 octets")
    if len(message.sname) > 63 or len(message.file) > 127:
        raise DhcpError("sname is at most 63 octets and file at most 127 (a NUL ends each)")
    for name, value, limit in (
        ("xid", message.xid, 0xFFFFFFFF),
        ("secs", message.secs, 0xFFFF),
        ("flags", message.flags, 0xFFFF),
        ("hops", message.hops, 0xFF),
        ("htype", message.htype, 0xFF),
    ):
        if not 0 <= value <= limit:
            raise DhcpError(f"{name} {value} out of range")
    if options_limit is None or not message.has_cookie:
        options, file, sname = encode_options4(message.options), message.file, message.sname
    else:
        options, file, sname = _options_area(message, options_limit)
    head = _FIXED.pack(
        message.op, message.htype, len(message.chaddr), message.hops, message.xid, message.secs,
        message.flags, message.ciaddr, message.yiaddr, message.siaddr, message.giaddr,
        message.chaddr.ljust(16, b"\x00"), sname.ljust(64, b"\x00"), file.ljust(128, b"\x00"),
    )  # fmt: skip
    if not message.has_cookie:
        return head + message.vendor
    return head + MAGIC_COOKIE + options
