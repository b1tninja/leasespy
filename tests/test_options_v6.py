"""DHCPv6 option framing and IA_NA (RFC 9915 sec. 21.1, sec. 21.4).

Expected bytes are written by hand from the figures in the RFC, never taken from the code
under test. RFC 9915 publishes no packet captures, so these are hand-built vectors.
"""

from __future__ import annotations

import contextlib
import random

import pytest

from leasespy.errors import DhcpError
from leasespy.options import (
    INFINITY,
    OPTION_IA_NA,
    IaNa,
    Option,
    decode_ia_na,
    decode_options,
    encode_ia_na,
    encode_option,
    encode_options,
)


def test_empty_buffer_is_empty_list():
    assert decode_options(b"") == []


def test_single_option_bytes():
    assert encode_option(Option(1, b"\xaa\xbb\xcc")) == bytes.fromhex("00010003aabbcc")
    assert decode_options(bytes.fromhex("00010003aabbcc")) == [Option(1, b"\xaa\xbb\xcc")]


def test_decode_options_roundtrip():
    options = [Option(1, b"abc"), Option(2, b""), Option(0xFFFF, b"\x00" * 300), Option(1, b"z")]
    assert decode_options(encode_options(options)) == options


def test_roundtrip_many_options_order_preserved():
    options = [Option(code, bytes([code % 256])) for code in (9, 3, 9, 1, 65535, 0, 3)]
    assert [o.code for o in decode_options(encode_options(options))] == [9, 3, 9, 1, 65535, 0, 3]


@pytest.mark.parametrize("size", [1, 2, 3])
def test_truncated_header_1_to_3_bytes_raises(size):
    with pytest.raises(DhcpError):
        decode_options(b"\x00\x01\x00"[:size])


def test_trailing_bytes_after_a_good_option_raise():
    with pytest.raises(DhcpError):
        decode_options(bytes.fromhex("0001000000"))


def test_length_beyond_buffer_raises():
    with pytest.raises(DhcpError):
        decode_options(bytes.fromhex("0001ffffaabb"))


def test_unknown_option_code_kept_not_dropped():
    assert decode_options(bytes.fromhex("12340002beef")) == [Option(0x1234, b"\xbe\xef")]


def test_zero_length_option_ok():
    assert decode_options(bytes.fromhex("00070000")) == [Option(7, b"")]


def test_encode_refuses_values_that_do_not_fit():
    with pytest.raises(DhcpError):
        encode_option(Option(0x10000, b""))
    with pytest.raises(DhcpError):
        encode_option(Option(-1, b""))
    with pytest.raises(DhcpError):
        encode_option(Option(1, b"x" * 0x10000))


def test_ia_na_option_len_is_12_plus_suboptions():
    sub = Option(5, b"\x01" * 24)
    wire = encode_ia_na(IaNa(iaid=1, t1=0, t2=0, options=(sub,)))
    # code 3, option-len 12 + (4 + 24) = 40, IAID 1, T1 0, T2 0, then the sub-option.
    assert wire[:4] == bytes.fromhex("00030028")
    assert wire[4:16] == bytes.fromhex("000000010000000000000000")
    assert wire[16:] == encode_option(sub)


def test_ia_na_decode_fields():
    wire = bytes.fromhex("0003000c0a0b0c0d00000e1000001c20")
    (option,) = decode_options(wire)
    assert option.code == OPTION_IA_NA
    ia = decode_ia_na(option)
    assert (ia.iaid, ia.t1, ia.t2, ia.options) == (0x0A0B0C0D, 3600, 7200, ())
    assert encode_ia_na(ia) == wire


def test_ia_na_shorter_than_12_raises():
    with pytest.raises(DhcpError):
        decode_ia_na(Option(OPTION_IA_NA, b"\x00" * 11))


def test_ia_na_wrong_code_raises():
    with pytest.raises(DhcpError):
        decode_ia_na(Option(4, b"\x00" * 12))


def test_ia_na_with_truncated_suboption_raises():
    with pytest.raises(DhcpError):
        decode_ia_na(Option(OPTION_IA_NA, b"\x00" * 12 + b"\x00\x05\x00\x10"))


def test_ia_na_t1_greater_than_t2_flagged():
    assert IaNa(1, t1=200, t2=100).discard is True


@pytest.mark.parametrize(
    ("t1", "t2"), [(0, 0), (0, 100), (100, 0), (100, 100), (50, 100), (INFINITY, INFINITY)]
)
def test_ia_na_t1_t2_zero_or_ordered_not_flagged(t1, t2):
    assert IaNa(1, t1=t1, t2=t2).discard is False


def test_ia_na_t1_infinity_with_finite_t2_is_flagged():
    assert IaNa(1, t1=INFINITY, t2=100).discard is True


def test_encode_ia_na_refuses_a_value_over_32_bits():
    with pytest.raises(DhcpError):
        encode_ia_na(IaNa(iaid=1 << 32, t1=0, t2=0))


def test_fuzz_seeded_never_other_exception():
    rng = random.Random(0x9915)
    for _ in range(5000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        try:
            options = decode_options(blob)
        except DhcpError:
            continue
        assert encode_options(options) == blob
        for option in options:
            with contextlib.suppress(DhcpError):
                decode_ia_na(option)
