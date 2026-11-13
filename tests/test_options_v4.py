"""DHCPv4 option framing, RFC 3396 aggregation and the RFC 4361 client identifier."""

from __future__ import annotations

import contextlib
import random

import pytest

from leasespy.errors import DhcpError
from leasespy.options4 import (
    Option4,
    aggregate,
    decode_client_id,
    decode_options4,
    encode_client_id,
    encode_options4,
)


def test_decode_v4_options() -> None:
    raw = bytes([0, 0, 53, 1, 1, 0, 12, 3]) + b"abc" + bytes([255]) + b"\xff\xff"
    assert decode_options4(raw) == [Option4(53, b"\x01"), Option4(12, b"abc")]


def test_pad_and_end_have_no_length_octet() -> None:
    assert decode_options4(bytes([0, 0, 255, 53, 1, 1])) == []


@pytest.mark.parametrize("raw", [bytes([53]), bytes([53, 2, 1]), bytes([12, 200, 1, 2])])
def test_truncated_option_raises_dhcperror(raw: bytes) -> None:
    with pytest.raises(DhcpError):
        decode_options4(raw)


def test_rfc3396_section_8_example_concatenates() -> None:
    # RFC 3396 section 8: option 67 "/diskless/foo" split 7 + 6.
    first = bytes([67, 7]) + b"/diskle"
    second = bytes([67, 6]) + b"ss/foo"
    parts = decode_options4(first + second + bytes([255]))
    assert aggregate(parts) == (Option4(67, b"/diskless/foo"),)


def test_concatenates_repeated_options() -> None:
    parts = [
        Option4(3, b"\x0a\x00\x00\x01"),
        Option4(6, b"\x08\x08\x08\x08"),
        Option4(3, b"\x0a\x00\x00\x02"),
    ]
    assert aggregate(parts) == (
        Option4(3, b"\x0a\x00\x00\x01\x0a\x00\x00\x02"),
        Option4(6, b"\x08\x08\x08\x08"),
    )


def test_long_option_is_split_at_255_and_round_trips() -> None:
    data = bytes(range(256)) * 2  # 512 octets
    parts = decode_options4(encode_options4([Option4(43, data)]))
    assert [len(p.data) for p in parts] == [255, 255, 2]
    assert all(p.code == 43 for p in parts)
    assert aggregate(parts) == (Option4(43, data),)


def test_pad_and_end_codes_cannot_be_encoded() -> None:
    for code in (0, 255, 256):
        with pytest.raises(DhcpError):
            encode_options4([Option4(code, b"x")])


def test_empty_option_is_one_part_of_length_zero() -> None:
    assert encode_options4([Option4(80, b"")], end=False) == bytes([80, 0])


def test_node_specific_client_id() -> None:
    duid = bytes.fromhex("00030001aabbccddeeff")
    payload = encode_client_id(0x01020304, duid)
    assert payload[:5] == bytes([255, 1, 2, 3, 4])
    cid = decode_client_id(payload)
    assert (cid.kind, cid.iaid, cid.duid) == (255, 0x01020304, duid)


def test_legacy_client_id_is_type_then_hardware_address() -> None:
    cid = decode_client_id(bytes([1]) + bytes.fromhex("aabbccddeeff"))
    assert (cid.kind, cid.value, cid.iaid, cid.duid) == (
        1,
        bytes.fromhex("aabbccddeeff"),
        None,
        None,
    )


@pytest.mark.parametrize("payload", [b"", bytes([255, 0, 0, 0, 1]), bytes([255, 0, 0, 0])])
def test_short_client_ids_are_refused(payload: bytes) -> None:
    with pytest.raises(DhcpError):
        decode_client_id(payload)


def test_fuzz_seeded_never_other_exception() -> None:
    rng = random.Random(2131)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        with contextlib.suppress(DhcpError):
            decode_options4(blob)
