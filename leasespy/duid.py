"""DUID types and stability rules (RFC 9915 sec. 11).

A DUID is opaque. RFC 9915 sec. 11 says clients and servers MUST treat DUIDs as opaque values,
MUST only compare them for equality, and MUST NOT restrict them to the types the document
defines. So :class:`Duid` is its raw bytes and nothing else; equality and hashing use those
bytes only. :meth:`Duid.describe` is a separate, optional *diagnostic* view of types 1 to 4,
for logs and tools. Nothing in the library may branch on it, and a link-layer address read
from it is not a fact about the client (sec. 11 calls that unreliable).
"""

from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass

from .errors import DhcpError

__all__ = [
    "DUID_EN",
    "DUID_LL",
    "DUID_LLT",
    "DUID_UUID",
    "Duid",
    "DuidEn",
    "DuidLl",
    "DuidLlt",
    "DuidUuid",
    "DuidView",
    "duid_llt_time_to_datetime",
    "parse_duid",
]

DUID_LLT = 1  # RFC 9915 sec. 11.2
DUID_EN = 2  # RFC 9915 sec. 11.3
DUID_LL = 3  # RFC 9915 sec. 11.4
DUID_UUID = 4  # RFC 9915 sec. 11.5

_MAX_CONTENT = 128  # sec. 11.1: at most 128 octets, not counting the type code
_EPOCH = datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC)


@dataclass(frozen=True, slots=True)
class DuidLlt:
    """Diagnostic view of a type 1 DUID."""

    hardware_type: int
    time: int
    link_layer_address: bytes


@dataclass(frozen=True, slots=True)
class DuidEn:
    """Diagnostic view of a type 2 DUID."""

    enterprise_number: int
    identifier: bytes


@dataclass(frozen=True, slots=True)
class DuidLl:
    """Diagnostic view of a type 3 DUID."""

    hardware_type: int
    link_layer_address: bytes


@dataclass(frozen=True, slots=True)
class DuidUuid:
    """Diagnostic view of a type 4 DUID."""

    uuid: bytes


DuidView = DuidLlt | DuidEn | DuidLl | DuidUuid


@dataclass(frozen=True, slots=True)
class Duid:
    """An opaque DUID. Equality and hash are on ``raw`` alone (RFC 9915 sec. 11)."""

    raw: bytes

    @property
    def type_code(self) -> int:
        """The 2-octet type code, for display. Do not restrict behaviour to known values."""
        return int.from_bytes(self.raw[:2], "big")

    def describe(self) -> DuidView | None:
        """A typed diagnostic view of types 1 to 4, or None.

        None for any other type and for a known type whose body is too short for its layout
        (a type 4 DUID is exactly 16 octets after the type). Never raises: a DUID that does
        not fit its type is still a valid opaque DUID.
        """
        kind, body = self.type_code, self.raw[2:]
        if kind == DUID_LLT and len(body) >= 7:
            hardware_type, time = struct.unpack_from("!HI", body)
            return DuidLlt(hardware_type, time, body[6:])
        if kind == DUID_EN and len(body) >= 5:
            return DuidEn(int.from_bytes(body[:4], "big"), body[4:])
        if kind == DUID_LL and len(body) >= 3:
            return DuidLl(int.from_bytes(body[:2], "big"), body[2:])
        if kind == DUID_UUID and len(body) == 16:
            return DuidUuid(body)
        return None


def parse_duid(raw: bytes) -> Duid:
    """Wrap DUID bytes, checking only the length (RFC 9915 sec. 11).

    A DUID is a 2-octet type code followed by 1 to 128 octets (sec. 11.1). Unknown types are
    accepted, because sec. 11 forbids restricting DUIDs to the known ones.
    """
    data = bytes(raw)
    if len(data) < 3:
        raise DhcpError(f"a DUID is a type code plus at least 1 octet, got {len(data)} octets")
    if len(data) - 2 > _MAX_CONTENT:
        raise DhcpError(f"a DUID carries at most {_MAX_CONTENT} octets after its type code")
    return Duid(data)


def duid_llt_time_to_datetime(seconds: int) -> datetime.datetime:
    """Convert a DUID-LLT time to UTC: seconds since 2000-01-01, modulo 2**32 (sec. 11.2)."""
    return _EPOCH + datetime.timedelta(seconds=seconds % (1 << 32))
