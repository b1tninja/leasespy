"""option registry, encoders and decoders (RFC 2132, RFC 9915 sec. 21).

DHCPv6 option framing and the IA_NA option. DHCPv4 options (RFC 2132) are not implemented.

Codes are defined here only where RFC 9915 states the number in the option's own section
(sec. 21.2 to sec. 21.4, sec. 21.10, sec. 21.19, sec. 21.21). The obsolete IA_TA and Server
Unicast options are deliberately not named: RFC 9915 sec. 21.5 and sec. 21.12 say a receiver
ignores them, and RFC 9915 does not restate their numbers. They decode as unknown options,
which is what sec. 16 requires of any option the receiver does not know.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import DhcpError

__all__ = [
    "INFINITY",
    "OPTION_CLIENTID",
    "OPTION_IA_NA",
    "OPTION_IA_PD",
    "OPTION_RECONF_MSG",
    "OPTION_RELAY_MSG",
    "OPTION_SERVERID",
    "IaNa",
    "Option",
    "decode_ia_na",
    "decode_options",
    "encode_ia_na",
    "encode_option",
    "encode_options",
]

OPTION_CLIENTID = 1  # RFC 9915 sec. 21.2
OPTION_SERVERID = 2  # RFC 9915 sec. 21.3
OPTION_IA_NA = 3  # RFC 9915 sec. 21.4
OPTION_RELAY_MSG = 9  # RFC 9915 sec. 21.10
OPTION_RECONF_MSG = 19  # RFC 9915 sec. 21.19
OPTION_IA_PD = 25  # RFC 9915 sec. 21.21

INFINITY = 0xFFFFFFFF  # RFC 9915 sec. 7.7: a lifetime, T1 or T2 of "infinity"

_HEADER = struct.Struct("!HH")
_IA_NA_FIXED = struct.Struct("!III")
_MAX_FIELD = 0xFFFF
_MAX_U32 = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class Option:
    """One DHCPv6 option: a 2-octet code and its data (RFC 9915 sec. 21.1)."""

    code: int
    data: bytes


@dataclass(frozen=True, slots=True)
class IaNa:
    """The contents of an IA_NA option (RFC 9915 sec. 21.4)."""

    iaid: int
    t1: int
    t2: int
    options: tuple[Option, ...] = ()

    @property
    def discard(self) -> bool:
        """True when a client must discard this IA_NA: T1 > T2 with both above zero (sec. 21.4)."""
        return self.t1 > 0 and self.t2 > 0 and self.t1 > self.t2


def encode_option(option: Option) -> bytes:
    """Encode one option as code, length and data (RFC 2132, RFC 9915 sec. 21).

    Only the DHCPv6 framing of RFC 9915 sec. 21.1 is implemented. There is no padding.
    """
    if not isinstance(option.data, bytes | bytearray | memoryview):
        raise DhcpError("option data must be bytes")
    if not 0 <= option.code <= _MAX_FIELD:
        raise DhcpError(f"option code {option.code} does not fit in 2 octets")
    if len(option.data) > _MAX_FIELD:
        raise DhcpError(f"option data of {len(option.data)} octets does not fit in 2 octets")
    return _HEADER.pack(option.code, len(option.data)) + bytes(option.data)


def encode_options(options: tuple[Option, ...] | list[Option]) -> bytes:
    """Encode options serially with no padding (RFC 9915 sec. 8, the options field)."""
    return b"".join(encode_option(option) for option in options)


def decode_options(raw: bytes) -> list[Option]:
    """Split an options field into a flat list, order preserved (RFC 9915 sec. 21).

    Unknown codes are kept, never dropped (sec. 16 forbids discarding a message for them).
    Nothing is nested here: an IA_NA's own options are reached with :func:`decode_ia_na`, so
    there is no recursion to bound. Raises :class:`DhcpError` on a truncated header or an
    option-len that runs past the buffer; it never returns a partial list.
    """
    data = bytes(raw)
    options: list[Option] = []
    at = 0
    end = len(data)
    while at < end:
        if end - at < _HEADER.size:
            raise DhcpError(f"{end - at} trailing octet(s) cannot hold an option header")
        code, length = _HEADER.unpack_from(data, at)
        at += _HEADER.size
        if length > end - at:
            raise DhcpError(f"option {code} declares {length} octets but only {end - at} remain")
        options.append(Option(code, data[at : at + length]))
        at += length
    return options


def decode_ia_na(option: Option) -> IaNa:
    """Decode an IA_NA option's data: IAID, T1, T2, then options (RFC 9915 sec. 21.4)."""
    if option.code != OPTION_IA_NA:
        raise DhcpError(f"option {option.code} is not OPTION_IA_NA ({OPTION_IA_NA})")
    if len(option.data) < _IA_NA_FIXED.size:
        raise DhcpError(f"IA_NA of {len(option.data)} octets is shorter than 12")
    iaid, t1, t2 = _IA_NA_FIXED.unpack_from(option.data)
    return IaNa(iaid, t1, t2, tuple(decode_options(option.data[_IA_NA_FIXED.size :])))


def encode_ia_na(ia: IaNa) -> bytes:
    """Encode an IA_NA option including its header; option-len is 12 plus the options."""
    for name, value in (("iaid", ia.iaid), ("t1", ia.t1), ("t2", ia.t2)):
        if not 0 <= value <= _MAX_U32:
            raise DhcpError(f"IA_NA {name} {value} does not fit in 4 octets")
    body = _IA_NA_FIXED.pack(ia.iaid, ia.t1, ia.t2) + encode_options(ia.options)
    return encode_option(Option(OPTION_IA_NA, body))
