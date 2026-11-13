"""DHCPv4 message codec: the fixed header, the cookie, overload and BOOTP."""

from __future__ import annotations

import contextlib
import random
import struct

import pytest

from leasespy.errors import DhcpError
from leasespy.options4 import MAGIC_COOKIE, Option4, encode_options4
from leasespy.wire4 import BOOTREQUEST, DhcpMessage4, decode_message4, encode_message4

_FIXED = "!BBBBIHH4s4s4s4s16s64s128s"
_MAC = bytes.fromhex("00053c048d59")


def _discover() -> DhcpMessage4:
    return DhcpMessage4(
        op=BOOTREQUEST,
        htype=1,
        hops=0,
        xid=0x3903F326,
        secs=0,
        flags=0x8000,
        ciaddr=bytes(4),
        yiaddr=bytes(4),
        siaddr=bytes(4),
        giaddr=bytes(4),
        chaddr=_MAC,
        options=(Option4(53, b"\x01"), Option4(61, b"\x01" + _MAC)),
    )


def _raw(options: bytes = b"", file: bytes = b"", sname: bytes = b"") -> bytes:
    head = struct.pack(
        _FIXED,
        2,
        1,
        6,
        0,
        1,
        0,
        0,
        bytes(4),
        bytes([10, 0, 0, 9]),
        bytes(4),
        bytes(4),
        bytes(6),
        sname.ljust(64, b"\0"),
        file.ljust(128, b"\0"),
    )
    return head + MAGIC_COOKIE + options


def test_header_is_236_octets_before_the_cookie() -> None:
    assert struct.calcsize(_FIXED) == 236


def test_encode_v4() -> None:
    raw = encode_message4(_discover())
    assert len(raw) == 236 + 4 + 3 + 9 + 1
    assert raw[:4] == bytes([1, 1, 6, 0])
    assert raw[4:8] == bytes.fromhex("3903f326")
    assert raw[10:12] == b"\x80\x00"
    assert raw[28:34] == _MAC
    assert raw[236:240] == MAGIC_COOKIE


def test_decode_v4() -> None:
    message = decode_message4(encode_message4(_discover()))
    assert message == _discover()
    assert message.broadcast
    assert message.message_type == 1


def test_option_overload_reads_file_then_sname_in_rfc3396_order() -> None:
    # Option 67 in three parts: options field "/d", then file "isk", then sname "less".
    raw = _raw(
        bytes([52, 1, 3, 67, 2]) + b"/d" + bytes([255]),
        file=bytes([67, 3]) + b"isk" + bytes([255]),
        sname=bytes([67, 4]) + b"less" + bytes([255]),
    )
    message = decode_message4(raw)
    assert message.option(67) == b"/diskless"
    assert message.file == b""
    assert message.sname == b""


def test_overload_of_file_only_leaves_sname_a_string() -> None:
    raw = _raw(bytes([52, 1, 1, 255]), file=bytes([12, 1, 0x61, 255]), sname=b"server")
    message = decode_message4(raw)
    assert message.option(12) == b"a"
    assert message.sname == b"server"


def test_bad_overload_value_is_refused() -> None:
    with pytest.raises(DhcpError):
        decode_message4(_raw(bytes([52, 1, 4, 255])))


def test_missing_cookie_is_bootp_with_raw_vendor_field() -> None:
    raw = _raw()[:236] + bytes(64)
    message = decode_message4(raw)
    assert not message.has_cookie
    assert message.options == ()
    assert message.vendor == bytes(64)
    assert encode_message4(message) == raw


def test_duplicate_message_type_makes_a_two_octet_option_and_is_refused() -> None:
    message = decode_message4(_raw(bytes([53, 1, 1, 53, 1, 2, 255])))
    with pytest.raises(DhcpError):
        _ = message.message_type


@pytest.mark.parametrize(
    "raw",
    [b"", bytes(235), bytes([3]) + bytes(235), bytes([1, 1, 17]) + bytes(233)],
)
def test_malformed_headers_raise_dhcperror(raw: bytes) -> None:
    with pytest.raises(DhcpError):
        decode_message4(raw)


def test_encode_refuses_a_bad_op_and_a_short_address() -> None:
    zero = bytes(4)
    with pytest.raises(DhcpError):
        encode_message4(DhcpMessage4(3, 1, 0, 0, 0, 0, zero, zero, zero, zero, b""))
    with pytest.raises(DhcpError):
        encode_message4(DhcpMessage4(1, 1, 0, 0, 0, 0, b"\0", zero, zero, zero, b""))


def test_long_option_survives_a_message_round_trip() -> None:
    long_data = bytes(range(200)) * 3
    zero = bytes(4)
    message = DhcpMessage4(
        BOOTREQUEST, 1, 0, 7, 0, 0, zero, zero, zero, zero, b"", options=(Option4(43, long_data),)
    )
    assert decode_message4(encode_message4(message)).option(43) == long_data
    assert len(decode_message4(encode_message4(message)).options) == 1
    assert encode_options4(message.options).count(bytes([43, 255])) == 2


def test_fuzz_seeded_never_other_exception() -> None:
    rng = random.Random(2132)
    seed = encode_message4(_discover())
    for _ in range(3000):
        blob = bytearray(seed)
        for _ in range(rng.randrange(1, 6)):
            blob[rng.randrange(len(blob))] = rng.randrange(256)
        cut = rng.randrange(len(blob) + 1)
        with contextlib.suppress(DhcpError):
            decode_message4(bytes(blob[:cut]))
