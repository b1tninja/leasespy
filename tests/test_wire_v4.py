"""DHCPv4 message codec: the fixed header, the cookie, overload and BOOTP."""

from __future__ import annotations

import contextlib
import random
import struct
from dataclasses import replace

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


def _bulky(*sizes: int) -> DhcpMessage4:
    """A discover with extra options whose data are ``sizes`` octets each (codes 100, 101, ...)."""
    extra = tuple(Option4(100 + n, bytes([n + 1]) * size) for n, size in enumerate(sizes))
    return replace(_discover(), options=_discover().options + extra)


def _without_overload(message: DhcpMessage4) -> tuple[Option4, ...]:
    return tuple(o for o in message.options if o.code != 52)


def test_encode_overloads_file_and_sname_when_the_options_field_is_full() -> None:
    """RFC 2132 section 9.3 and RFC 3396 sections 5 and 6: spill into file, then sname."""
    message = _bulky(100, 100)  # 12 + 2 x 102 octets, over the 150-octet field below
    raw = encode_message4(message, options_limit=150)
    decoded = decode_message4(raw)
    assert decoded.option(52) == b"\x01"  # only the file field was needed
    assert {o.code: o.data for o in _without_overload(decoded)} == {
        o.code: o.data for o in message.options
    }
    field = raw[236 + 4 :]
    assert len(field) <= 150  # the options field kept to its limit
    assert raw[44 + 64 : 44 + 64 + 3] != bytes(3)  # file (offset 108) holds options
    assert raw[44 : 44 + 64] == bytes(64)  # sname untouched
    assert len(raw) == 236 + 4 + len(field)


def test_overload_uses_sname_after_file_and_says_so_with_value_3() -> None:
    message = _bulky(120, 60, 55)  # 12 + 122 + 62 + 57 octets: file, sname, and a split option
    raw = encode_message4(message, options_limit=70)
    decoded = decode_message4(raw)
    assert decoded.option(52) == b"\x03"
    assert decoded.file == b""
    assert decoded.sname == b""  # both fields are option storage, so neither is a string
    assert {o.code: o.data for o in _without_overload(decoded)} == {
        o.code: o.data for o in message.options
    }


def test_a_message_that_fits_is_not_overloaded_and_option_52_is_never_added() -> None:
    raw = encode_message4(_discover(), options_limit=312)
    assert decode_message4(raw).option(52) is None
    assert raw == encode_message4(_discover())


def test_a_string_in_file_keeps_file_out_of_the_options() -> None:
    message = replace(_bulky(100, 40), file=b"boot.img")
    raw = encode_message4(message, options_limit=150)
    decoded = decode_message4(raw)
    assert decoded.option(52) == b"\x02"  # sname only; file stays the boot file name
    assert decoded.file == b"boot.img"


def test_an_option_that_fits_no_field_whole_is_split_with_the_same_code_in_order() -> None:
    """RFC 3396 section 6 paragraphs 2 to 4: parts of one option, in buffer order."""
    data = bytes(range(200))
    message = replace(_discover(), options=(Option4(53, b"\x01"), Option4(77, data)))
    raw = encode_message4(message, options_limit=100)
    decoded = decode_message4(raw)
    assert decoded.option(77) == data  # joined options, file, sname in that order
    assert decoded.option(52) in (b"\x01", b"\x03")


def test_overload_refuses_what_cannot_fit_and_option_52_supplied_by_the_caller() -> None:
    with pytest.raises(DhcpError, match="do not fit"):
        encode_message4(_bulky(250, 250, 250), options_limit=100)
    supplied = replace(_discover(), options=(Option4(52, b"\x01"),))
    with pytest.raises(DhcpError, match="option 52"):
        encode_message4(supplied, options_limit=100)
    with pytest.raises(DhcpError, match="options_limit"):
        encode_message4(_discover(), options_limit=1)


def test_overloaded_buffers_each_end_with_the_end_option() -> None:
    raw = encode_message4(_bulky(100, 100), options_limit=150)
    file_field = raw[44 + 64 : 44 + 64 + 128]
    assert 255 in file_field  # RFC 2132 section 3.2: the field ends its options with End
