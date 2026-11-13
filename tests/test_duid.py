"""DUID as an opaque value (RFC 9915 sec. 11)."""

from __future__ import annotations

import datetime

import pytest

from leasespy.duid import (
    Duid,
    DuidEn,
    DuidLl,
    DuidLlt,
    DuidUuid,
    duid_llt_time_to_datetime,
    parse_duid,
)
from leasespy.errors import DhcpError

# RFC 9915 sec. 11.3 Figure 6, octets in decimal: 0 2 0 0 126 217 12 192 132 211 3 0 9 18.
# The text beside it gives type 2, enterprise number 32473, identifier 0x0CC084D303000912.
EN_EXAMPLE = bytes([0, 2, 0, 0, 126, 217, 12, 192, 132, 211, 3, 0, 9, 18])


def test_parse_duid_en_example():
    duid = parse_duid(EN_EXAMPLE)
    assert duid.type_code == 2
    assert duid.describe() == DuidEn(32473, bytes.fromhex("0CC084D303000912"))


def test_equality_is_on_raw_bytes_only():
    assert parse_duid(EN_EXAMPLE) == Duid(EN_EXAMPLE)
    assert parse_duid(EN_EXAMPLE) != parse_duid(EN_EXAMPLE[:-1] + b"\x13")


def test_hash_stable_and_usable_as_dict_key():
    table = {parse_duid(EN_EXAMPLE): "x"}
    assert table[Duid(bytes(EN_EXAMPLE))] == "x"
    assert hash(parse_duid(EN_EXAMPLE)) == hash(parse_duid(bytes(EN_EXAMPLE)))


def test_unknown_type_accepted_and_describe_is_none():
    duid = parse_duid(b"\x00\xff\x01\x02\x03")
    assert duid.type_code == 0xFF
    assert duid.describe() is None


def test_length_bounds():
    with pytest.raises(DhcpError):
        parse_duid(b"\x00\x01")  # type plus 0 octets
    assert parse_duid(b"\x00\xff" + b"\x00" * 128).raw[:2] == b"\x00\xff"
    with pytest.raises(DhcpError):
        parse_duid(b"\x00\xff" + b"\x00" * 129)


def test_hostile_short_input_refused():
    for size in (0, 1, 2):
        with pytest.raises(DhcpError):
            parse_duid(b"\x00\x02\x00"[:size])


def test_uuid_must_be_16_octets_for_view_but_not_for_equality():
    good = parse_duid(b"\x00\x04" + bytes(range(16)))
    assert good.describe() == DuidUuid(bytes(range(16)))
    short = parse_duid(b"\x00\x04" + bytes(range(15)))
    assert short.describe() is None
    assert short == Duid(b"\x00\x04" + bytes(range(15)))


def test_llt_and_ll_views():
    llt = parse_duid(bytes.fromhex("00010001000000010011223344 55".replace(" ", "")))
    assert llt.describe() == DuidLlt(1, 1, bytes.fromhex("001122334455"))
    ll = parse_duid(bytes.fromhex("00030001001122334455"))
    assert ll.describe() == DuidLl(1, bytes.fromhex("001122334455"))


def test_short_known_types_describe_none_never_raise():
    for raw in (
        b"\x00\x01\x00\x01\x00\x00\x00\x01",
        b"\x00\x02\x00\x00\x00\x01",
        b"\x00\x03\x00\x01",
    ):
        assert parse_duid(raw).describe() is None


def test_llt_time_epoch_is_2000():
    epoch = datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC)
    assert duid_llt_time_to_datetime(0) == epoch
    assert duid_llt_time_to_datetime(86400) == epoch + datetime.timedelta(days=1)
    assert duid_llt_time_to_datetime(0xFFFFFFFF) == epoch + datetime.timedelta(seconds=0xFFFFFFFF)
    assert duid_llt_time_to_datetime(1 << 32) == epoch
