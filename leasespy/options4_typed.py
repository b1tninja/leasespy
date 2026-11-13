"""Typed readers for the DHCPv4 options of RFC 2132 (sections 3 to 9).

:func:`decode_typed` turns an :class:`~leasespy.options4.Option4` into a Python value: addresses
as :class:`ipaddress.IPv4Address`, counts and times as ``int``, switches as ``bool``, text as
``str``. A code that is not in the table returns ``None``, so an option this module does not know
stays an opaque ``Option4`` exactly as before; a code that is in the table and whose data breaks
the length or value rule of its section raises :class:`~leasespy.errors.DhcpError`. Nothing is
repaired.

Each rule comes from the section that defines the option; the table below names it. The
format of every option is the one RFC 2132 prints. Of its two verified errata (checked
2026-11-13), erratum 486 concerns the message type of section 9.6, whose figure says "1-9" while
the list has 1 to 8; later RFCs add types (FORCERENEW 9, the leasequery types 10 to 13), so the
reader here accepts any nonzero octet and leaves naming to ``options4.message_type_name``. Erratum
2305 only fixes a name (section 3.10 option 8 is the cookie server).

Not here: the client identifier (``options4.decode_client_id``, RFC 4361), options defined
outside RFC 2132, and the encapsulated vendor options of section 8.4, which are vendor-defined
and are kept opaque.
"""

from __future__ import annotations

import enum
import ipaddress
from dataclasses import dataclass

from .errors import DhcpError
from .options4 import Option4

__all__ = [
    "NETBIOS_NODE_TYPES",
    "OptionKind",
    "TypedOption",
    "decode_typed",
    "typed_kind",
]

#: RFC 2132 section 8.7 paragraph 2.
NETBIOS_NODE_TYPES = {0x1: "B-node", 0x2: "P-node", 0x4: "M-node", 0x8: "H-node"}


class OptionKind(enum.Enum):
    """How the data of an option is laid out."""

    ADDRESS = "address"  # exactly 4 octets
    ADDRESS_LIST = "address list"  # a non-empty multiple of 4
    ADDRESS_LIST_OR_EMPTY = "address list, possibly empty"  # option 68, section 8.13
    ADDRESS_PAIRS = "address pairs"  # a non-empty multiple of 8: policy filter, static routes
    INT32 = "signed 32-bit"  # time offset, section 3.4
    UINT8 = "unsigned 8-bit"
    UINT16 = "unsigned 16-bit"
    UINT32 = "unsigned 32-bit"
    UINT16_LIST = "list of unsigned 16-bit"  # path MTU plateau table, section 4.7
    UINT8_LIST = "list of option codes"  # parameter request list, section 9.8
    BOOL = "0 or 1"
    TEXT = "NVT ASCII text"  # at least one octet
    OPAQUE = "opaque"  # at least one octet
    NODE_TYPE = "NetBIOS node type"  # section 8.7
    MESSAGE_TYPE = "DHCP message type"  # section 9.6
    OVERLOAD = "option overload"  # section 9.3


@dataclass(frozen=True)
class _Spec:
    kind: OptionKind
    section: str
    minimum: int | None = None  # smallest legal value for integers (sections 4.4, 4.5, 5.1, 9.10)


_ADDRESS_LISTS = {
    3: "3.5",
    4: "3.6",
    5: "3.7",
    6: "3.8",
    7: "3.9",
    8: "3.10",
    9: "3.11",
    10: "3.12",
    11: "3.13",
    41: "8.2",
    42: "8.3",
    44: "8.5",
    45: "8.6",
    48: "8.9",
    49: "8.10",
    65: "8.12",
    69: "8.14",
    70: "8.15",
    71: "8.16",
    72: "8.17",
    73: "8.18",
    74: "8.19",
    75: "8.20",
    76: "8.21",
}

_TABLE: dict[int, _Spec] = {
    1: _Spec(OptionKind.ADDRESS, "3.3"),
    2: _Spec(OptionKind.INT32, "3.4"),
    12: _Spec(OptionKind.TEXT, "3.14"),
    13: _Spec(OptionKind.UINT16, "3.15"),
    14: _Spec(OptionKind.TEXT, "3.16"),
    15: _Spec(OptionKind.TEXT, "3.17"),
    16: _Spec(OptionKind.ADDRESS, "3.18"),
    17: _Spec(OptionKind.TEXT, "3.19"),
    18: _Spec(OptionKind.TEXT, "3.20"),
    19: _Spec(OptionKind.BOOL, "4.1"),
    20: _Spec(OptionKind.BOOL, "4.2"),
    21: _Spec(OptionKind.ADDRESS_PAIRS, "4.3"),
    22: _Spec(OptionKind.UINT16, "4.4", 576),
    23: _Spec(OptionKind.UINT8, "4.5", 1),
    24: _Spec(OptionKind.UINT32, "4.6"),
    25: _Spec(OptionKind.UINT16_LIST, "4.7", 68),
    26: _Spec(OptionKind.UINT16, "5.1", 68),
    27: _Spec(OptionKind.BOOL, "5.2"),
    28: _Spec(OptionKind.ADDRESS, "5.3"),
    29: _Spec(OptionKind.BOOL, "5.4"),
    30: _Spec(OptionKind.BOOL, "5.5"),
    31: _Spec(OptionKind.BOOL, "5.6"),
    32: _Spec(OptionKind.ADDRESS, "5.7"),
    33: _Spec(OptionKind.ADDRESS_PAIRS, "5.8"),
    34: _Spec(OptionKind.BOOL, "6.1"),
    35: _Spec(OptionKind.UINT32, "6.2"),
    36: _Spec(OptionKind.BOOL, "6.3"),
    37: _Spec(OptionKind.UINT8, "7.1", 1),
    38: _Spec(OptionKind.UINT32, "7.2"),
    39: _Spec(OptionKind.BOOL, "7.3"),
    40: _Spec(OptionKind.TEXT, "8.1"),
    43: _Spec(OptionKind.OPAQUE, "8.4"),
    46: _Spec(OptionKind.NODE_TYPE, "8.7"),
    47: _Spec(OptionKind.TEXT, "8.8"),
    50: _Spec(OptionKind.ADDRESS, "9.1"),
    51: _Spec(OptionKind.UINT32, "9.2"),
    52: _Spec(OptionKind.OVERLOAD, "9.3"),
    53: _Spec(OptionKind.MESSAGE_TYPE, "9.6"),
    54: _Spec(OptionKind.ADDRESS, "9.7"),
    55: _Spec(OptionKind.UINT8_LIST, "9.8"),
    56: _Spec(OptionKind.TEXT, "9.9"),
    57: _Spec(OptionKind.UINT16, "9.10", 576),
    58: _Spec(OptionKind.UINT32, "9.11"),
    59: _Spec(OptionKind.UINT32, "9.12"),
    60: _Spec(OptionKind.OPAQUE, "9.13"),
    64: _Spec(OptionKind.TEXT, "8.11"),
    66: _Spec(OptionKind.TEXT, "9.4"),
    67: _Spec(OptionKind.TEXT, "9.5"),
    68: _Spec(OptionKind.ADDRESS_LIST_OR_EMPTY, "8.13"),
}
_TABLE.update({code: _Spec(OptionKind.ADDRESS_LIST, s) for code, s in _ADDRESS_LISTS.items()})

#: Values of a decoded option.
TypedOption = (
    ipaddress.IPv4Address
    | list[ipaddress.IPv4Address]
    | list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]
    | int
    | bool
    | str
    | bytes
    | list[int]
)


def typed_kind(code: int) -> OptionKind | None:
    """The layout this module reads ``code`` with, or None when the code is not decoded here."""
    spec = _TABLE.get(code)
    return spec.kind if spec else None


def _fail(code: int, spec: _Spec, why: str) -> DhcpError:
    return DhcpError(f"option {code} (RFC 2132 section {spec.section}): {why}")


def _addresses(data: bytes, step: int) -> list[ipaddress.IPv4Address]:
    return [ipaddress.IPv4Address(data[i : i + 4]) for i in range(0, len(data), step)]


def decode_typed(option: Option4) -> TypedOption | None:
    """Read one option as its RFC 2132 type; None for a code this module does not decode.

    Raises :class:`DhcpError` when the length is not the one the option's section gives, when a
    boolean is not 0 or 1, when a value is below the minimum the section states (a datagram
    reassembly size under 576, an MTU under 68, a TTL of 0), when the path MTU plateau table is not
    ordered smallest to largest, when a static route has the default route as its destination
    (section 5.8 paragraph 3), and when text holds an octet above 127 (NVT ASCII).
    """
    spec = _TABLE.get(option.code)
    if spec is None:
        return None
    data, code, kind = option.data, option.code, spec.kind
    size = len(data)
    if kind is OptionKind.ADDRESS:
        if size != 4:
            raise _fail(code, spec, f"length {size}, must be 4")
        return ipaddress.IPv4Address(data)
    if kind in (OptionKind.ADDRESS_LIST, OptionKind.ADDRESS_LIST_OR_EMPTY):
        floor = 0 if kind is OptionKind.ADDRESS_LIST_OR_EMPTY else 4
        if size < floor or size % 4:
            raise _fail(code, spec, f"length {size}, must be a multiple of 4 and at least {floor}")
        return _addresses(data, 4)
    if kind is OptionKind.ADDRESS_PAIRS:
        if size < 8 or size % 8:
            raise _fail(code, spec, f"length {size}, must be a multiple of 8 and at least 8")
        pairs = [
            (ipaddress.IPv4Address(data[i : i + 4]), ipaddress.IPv4Address(data[i + 4 : i + 8]))
            for i in range(0, size, 8)
        ]
        if code == 33 and any(int(destination) == 0 for destination, _ in pairs):
            raise _fail(code, spec, "the default route 0.0.0.0 is an illegal destination")
        return pairs
    if kind is OptionKind.INT32:
        if size != 4:
            raise _fail(code, spec, f"length {size}, must be 4")
        return int.from_bytes(data, "big", signed=True)
    if kind in (OptionKind.UINT8, OptionKind.UINT16, OptionKind.UINT32):
        width = {OptionKind.UINT8: 1, OptionKind.UINT16: 2, OptionKind.UINT32: 4}[kind]
        if size != width:
            raise _fail(code, spec, f"length {size}, must be {width}")
        value = int.from_bytes(data, "big")
        if spec.minimum is not None and value < spec.minimum:
            raise _fail(code, spec, f"value {value} is below the legal minimum {spec.minimum}")
        return value
    if kind is OptionKind.UINT16_LIST:
        if size < 2 or size % 2:
            raise _fail(code, spec, f"length {size}, must be a multiple of 2 and at least 2")
        sizes = [int.from_bytes(data[i : i + 2], "big") for i in range(0, size, 2)]
        if spec.minimum is not None and sizes[0] < spec.minimum:
            raise _fail(
                code, spec, f"the smallest MTU is {sizes[0]}, the minimum is {spec.minimum}"
            )
        if sizes != sorted(sizes):
            raise _fail(code, spec, "the table must be ordered from smallest to largest")
        return sizes
    if kind is OptionKind.UINT8_LIST:
        if size < 1:
            raise _fail(code, spec, "needs at least one option code")
        return list(data)
    if kind is OptionKind.BOOL:
        if size != 1 or data[0] > 1:
            raise _fail(code, spec, "must be one octet holding 0 or 1")
        return bool(data[0])
    if kind is OptionKind.TEXT:
        if size < 1:
            raise _fail(code, spec, "needs at least one octet")
        if any(octet > 127 for octet in data):
            raise _fail(code, spec, "text must be NVT ASCII, and holds an octet above 127")
        return data.decode("ascii")
    if kind is OptionKind.OPAQUE:
        if size < 1:
            raise _fail(code, spec, "needs at least one octet")
        return bytes(data)
    if kind is OptionKind.NODE_TYPE:
        if size != 1 or data[0] not in NETBIOS_NODE_TYPES:
            raise _fail(code, spec, "must be one octet holding 0x1, 0x2, 0x4 or 0x8")
        return data[0]
    if kind is OptionKind.MESSAGE_TYPE:
        if size != 1 or data[0] == 0:
            raise _fail(code, spec, "must be one octet holding a nonzero type")
        return data[0]
    if size != 1 or data[0] not in (1, 2, 3):  # OptionKind.OVERLOAD
        raise _fail(code, spec, "must be one octet holding 1, 2 or 3")
    return data[0]
