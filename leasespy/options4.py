"""DHCPv4 option framing, aggregation and the client identifier (RFC 2132, RFC 3396, RFC 4361).

A DHCPv4 option is a 1-octet code, a 1-octet length and the data; only code 0 (Pad) and code 255
(End) have no length (RFC 2132 section 2 paragraph 1). The same code may appear more than once in
a message: RFC 3396 section 7 says the decoder MUST treat the parts as one option, joined in the
order of the aggregate option buffer (the options field, then ``file``, then ``sname``, RFC 3396
section 5). :func:`decode_options4` returns the parts as they stand and :func:`aggregate` joins them.

Names and lengths of the codes are IANA's (``leasespy._iana_dhcp``, generated from the
bootp-dhcp-parameters registry); this module defines only the codes whose framing or meaning the
codec itself needs.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._iana_dhcp import MESSAGE_TYPES, OPTION_RANGES, OPTIONS
from .errors import DhcpError

__all__ = [
    "CLIENT_ID_TYPE_DUID",
    "MAGIC_COOKIE",
    "OPTION_CLIENT_ID",
    "OPTION_END",
    "OPTION_MAX_MESSAGE_SIZE",
    "OPTION_MESSAGE_TYPE",
    "OPTION_OVERLOAD",
    "OPTION_PAD",
    "ClientId4",
    "Option4",
    "aggregate",
    "decode_client_id",
    "decode_options4",
    "encode_client_id",
    "encode_options4",
    "message_type_name",
    "option_name",
]

MAGIC_COOKIE = bytes((99, 130, 83, 99))  # RFC 2132 section 2 paragraph 4: 99.130.83.99
OPTION_PAD = 0  # RFC 2132 section 3.1
OPTION_END = 255  # RFC 2132 section 3.2
OPTION_OVERLOAD = 52  # RFC 2132 section 9.3
OPTION_MESSAGE_TYPE = 53  # RFC 2132 section 9.6
OPTION_CLIENT_ID = 61  # RFC 2132 section 9.14
OPTION_MAX_MESSAGE_SIZE = 57  # RFC 2132 section 9.10
CLIENT_ID_TYPE_DUID = 255  # RFC 4361 section 6.1 paragraph 3
_MAX_PART = 255


@dataclass(frozen=True, slots=True)
class Option4:
    """One DHCPv4 option part: a 1-octet code and up to 255 octets of data."""

    code: int
    data: bytes


def decode_options4(raw: bytes) -> list[Option4]:
    """Split one options buffer into parts, in order (RFC 2132 section 2).

    Pad octets are skipped and the End option stops the scan; whatever follows End is ignored
    (RFC 2132 section 3.2 says it should be pad, and nothing requires a decoder to check). A
    buffer that ends without End is accepted: RFC 3396 section 5 puts options in three buffers
    and does not say each must end with one, and a truncated-looking tail is an error only when
    a part's length runs past the buffer. Raises :class:`DhcpError` for a code with no length
    octet and for a length that overruns the buffer.
    """
    data = bytes(raw)
    parts: list[Option4] = []
    at = 0
    while at < len(data):
        code = data[at]
        at += 1
        if code == OPTION_PAD:
            continue
        if code == OPTION_END:
            break
        if at >= len(data):
            raise DhcpError(f"option {code} has no length octet")
        length = data[at]
        at += 1
        if length > len(data) - at:
            raise DhcpError(f"option {code} declares {length} octets but {len(data) - at} remain")
        parts.append(Option4(code, data[at : at + length]))
        at += length
    return parts


def aggregate(parts: list[Option4] | tuple[Option4, ...]) -> tuple[Option4, ...]:
    """Join parts that share a code into one option each (RFC 3396 section 4 paragraph 2, section 7).

    Codes come back in the order of their first part, and the data is joined in the order the parts
    were given. The joined data may exceed 255 octets: that is the point. No code is special-cased,
    because section 7 paragraph 1 says "two or more options with the same option code". A caller
    that needs a message type of exactly one octet therefore sees a duplicated option 53 as two
    octets and refuses it, which is the reading the RFC forces.
    """
    joined: dict[int, bytearray] = {}
    for part in parts:
        joined.setdefault(part.code, bytearray()).extend(part.data)
    return tuple(Option4(code, bytes(data)) for code, data in joined.items())


def encode_options4(options: list[Option4] | tuple[Option4, ...], *, end: bool = True) -> bytes:
    """Encode options, splitting any longer than 255 octets (RFC 3396 section 6).

    Parts are at most 255 octets, share the code and keep their order (section 6 paragraphs 2 and
    4). An empty option is one part of length zero. Codes 0 and 255 cannot carry data and are
    refused. ``end`` appends the End option.
    """
    out = bytearray()
    for option in options:
        if not 1 <= option.code <= 254:
            raise DhcpError(f"option code {option.code} cannot be encoded (0 is Pad, 255 is End)")
        data = bytes(option.data)
        if not data:
            out += bytes((option.code, 0))
            continue
        for start in range(0, len(data), _MAX_PART):
            chunk = data[start : start + _MAX_PART]
            out += bytes((option.code, len(chunk))) + chunk
    if end:
        out.append(OPTION_END)
    return bytes(out)


@dataclass(frozen=True, slots=True)
class ClientId4:
    """The client identifier option (code 61), read as RFC 4361 reads it.

    ``kind`` is the type octet. For type 255 ``iaid`` and ``duid`` are set (RFC 4361 section 6.1
    paragraph 3); for any other type, which RFC 2132 section 9.14 defines as an ARP hardware type
    followed by a hardware address, or as a free-form string for type 0, ``value`` holds the rest.
    """

    kind: int
    value: bytes
    iaid: int | None = None
    duid: bytes | None = None


def decode_client_id(data: bytes) -> ClientId4:
    """Read an option 61 payload. Raises :class:`DhcpError` when it is empty or a short type 255.

    RFC 4361 section 6.5 deletes "its minimum length is 2" from RFC 2132 section 9.14, but a
    payload with no type octet at all is still not an identifier. A type 255 identifier needs
    the 4-octet IAID and a non-empty DUID.
    """
    blob = bytes(data)
    if not blob:
        raise DhcpError("client identifier without a type octet")
    kind = blob[0]
    if kind != CLIENT_ID_TYPE_DUID:
        return ClientId4(kind, blob[1:])
    if len(blob) < 6:
        raise DhcpError(
            f"type 255 client identifier of {len(blob)} octets lacks an IAID and a DUID"
        )
    return ClientId4(kind, blob[1:], int.from_bytes(blob[1:5], "big"), blob[5:])


def encode_client_id(iaid: int, duid: bytes) -> bytes:
    """Build the option 61 payload of RFC 4361 section 6.1 paragraph 3: 255, IAID, DUID."""
    if not 0 <= iaid <= 0xFFFFFFFF:
        raise DhcpError("IAID must fit in 4 octets")
    if not duid:
        raise DhcpError("a DUID cannot be empty")
    return bytes((CLIENT_ID_TYPE_DUID,)) + iaid.to_bytes(4, "big") + bytes(duid)


def option_name(code: int) -> str:
    """IANA's name for a DHCPv4 option code, or ``"unassigned"``.

    From the generated table (``iana:bootp-dhcp-parameters§options``). A name here is not a claim
    that this package decodes the option; unknown codes are kept as opaque :class:`Option4`.
    """
    if code in OPTIONS:
        return OPTIONS[code][0]
    for low, high, name in OPTION_RANGES:
        if low <= code <= high:
            return name
    return "unassigned"


def message_type_name(value: int) -> str:
    """IANA's name for an option 53 value (``iana:bootp-dhcp-parameters§message-type-53``)."""
    entry = MESSAGE_TYPES.get(value)
    return entry[0] if entry else "unassigned"
