"""Typed readers for the RFC 2132 options.

RFC 2132 prints no byte vectors; each case below is the layout of the section it names, built by
hand from the figure and the paragraph that gives the length rule.
"""

from __future__ import annotations

import ipaddress
import re

import pytest

from leasespy._iana_dhcp import OPTIONS
from leasespy.errors import DhcpError
from leasespy.options4 import Option4
from leasespy.options4_typed import OptionKind, decode_typed, typed_kind

A = ipaddress.IPv4Address


def opt(code: int, *octets: int) -> Option4:
    return Option4(code, bytes(octets))


def test_subnet_mask_is_one_address_of_four_octets() -> None:
    """Section 3.3 paragraph 3."""
    assert decode_typed(opt(1, 255, 255, 255, 0)) == A("255.255.255.0")
    with pytest.raises(DhcpError, match=r"section 3\.3"):
        decode_typed(opt(1, 255, 255, 255))


def test_time_offset_is_a_twos_complement_32_bit_integer() -> None:
    """Section 3.4 paragraph 1: west of the zero meridian is negative."""
    assert decode_typed(opt(2, 0xFF, 0xFF, 0x8F, 0x80)) == -28800  # UTC-8
    assert decode_typed(opt(2, 0, 0, 0x0E, 0x10)) == 3600


@pytest.mark.parametrize("code", [3, 4, 5, 6, 7, 8, 9, 10, 11, 41, 42, 44, 45, 48, 49, 65])
def test_address_lists_need_a_multiple_of_four_and_at_least_one(code: int) -> None:
    """Sections 3.5 to 3.13 and 8.2 to 8.12: minimum 4, multiple of 4."""
    two = decode_typed(opt(code, 192, 0, 2, 1, 192, 0, 2, 2))
    assert two == [A("192.0.2.1"), A("192.0.2.2")]
    with pytest.raises(DhcpError):
        decode_typed(Option4(code, b""))
    with pytest.raises(DhcpError):
        decode_typed(opt(code, 192, 0, 2, 1, 9))


def test_option_68_may_be_empty_but_not_ragged() -> None:
    """Section 8.13 paragraph 2: minimum length 0, a multiple of 4."""
    assert decode_typed(Option4(68, b"")) == []
    assert decode_typed(opt(68, 10, 0, 0, 1)) == [A("10.0.0.1")]
    with pytest.raises(DhcpError):
        decode_typed(opt(68, 10, 0, 0))


def test_text_options_are_nvt_ascii_with_a_minimum_of_one_octet() -> None:
    assert decode_typed(Option4(12, b"printer-7")) == "printer-7"
    assert decode_typed(Option4(15, b"example.test")) == "example.test"
    with pytest.raises(DhcpError, match="at least one"):
        decode_typed(Option4(12, b""))
    with pytest.raises(DhcpError, match="NVT ASCII"):
        decode_typed(Option4(12, b"caf\xc3\xa9"))


def test_boot_file_size_is_an_unsigned_16_bit_count_of_512_octet_blocks() -> None:
    assert decode_typed(opt(13, 0x01, 0x00)) == 256  # section 3.15
    with pytest.raises(DhcpError):
        decode_typed(opt(13, 1))


@pytest.mark.parametrize("code", [19, 20, 27, 29, 30, 31, 34, 36, 39])
def test_switch_options_hold_zero_or_one(code: int) -> None:
    assert decode_typed(opt(code, 0)) is False
    assert decode_typed(opt(code, 1)) is True
    for bad in (bytes([2]), b"", bytes([0, 0])):
        with pytest.raises(DhcpError):
            decode_typed(Option4(code, bad))


def test_policy_filter_and_static_routes_are_pairs_of_four_octets() -> None:
    """Sections 4.3 and 5.8: minimum 8, a multiple of 8."""
    pairs = decode_typed(opt(21, 10, 0, 0, 0, 255, 0, 0, 0))
    assert pairs == [(A("10.0.0.0"), A("255.0.0.0"))]
    routes = decode_typed(opt(33, 198, 51, 100, 0, 192, 0, 2, 254))
    assert routes == [(A("198.51.100.0"), A("192.0.2.254"))]
    with pytest.raises(DhcpError):
        decode_typed(opt(33, 198, 51, 100, 0, 192, 0, 2))


def test_a_static_route_to_the_default_destination_is_illegal() -> None:
    """Section 5.8 paragraph 3."""
    with pytest.raises(DhcpError, match="default route"):
        decode_typed(opt(33, 0, 0, 0, 0, 192, 0, 2, 254))
    # The same octets are fine as a policy filter, which has no such rule.
    assert decode_typed(opt(21, 0, 0, 0, 0, 0, 0, 0, 0)) == [(A(0), A(0))]


def test_minimum_legal_values() -> None:
    """Sections 4.4, 4.5, 5.1, 7.1 and 9.10."""
    assert decode_typed(opt(22, 0x02, 0x40)) == 576
    with pytest.raises(DhcpError, match="minimum"):
        decode_typed(opt(22, 0x02, 0x3F))
    assert decode_typed(opt(26, 0, 68)) == 68
    with pytest.raises(DhcpError, match="minimum"):
        decode_typed(opt(26, 0, 67))
    assert decode_typed(opt(23, 64)) == 64
    with pytest.raises(DhcpError, match="minimum"):
        decode_typed(opt(23, 0))
    with pytest.raises(DhcpError, match="minimum"):
        decode_typed(opt(37, 0))
    assert decode_typed(opt(57, 0x05, 0xDC)) == 1500
    with pytest.raises(DhcpError, match="minimum"):
        decode_typed(opt(57, 0x02, 0x3F))


def test_path_mtu_plateau_table_is_ascending_and_at_least_68() -> None:
    """Section 4.7: 16-bit sizes, smallest to largest, none under 68."""
    table = decode_typed(opt(25, 0x00, 0x44, 0x02, 0x40, 0x05, 0xDC))
    assert table == [68, 576, 1500]
    with pytest.raises(DhcpError, match="smallest to largest"):
        decode_typed(opt(25, 0x05, 0xDC, 0x02, 0x40))
    with pytest.raises(DhcpError, match="minimum"):
        decode_typed(opt(25, 0x00, 0x43, 0x02, 0x40))
    with pytest.raises(DhcpError):
        decode_typed(opt(25, 0x00, 0x44, 0x02))


@pytest.mark.parametrize("code", [24, 35, 38, 51, 58, 59])
def test_time_options_are_unsigned_32_bit_seconds(code: int) -> None:
    assert decode_typed(opt(code, 0, 0, 0x0E, 0x10)) == 3600
    assert decode_typed(opt(code, 0xFF, 0xFF, 0xFF, 0xFF)) == 0xFFFFFFFF  # infinity, 2131 3.3
    with pytest.raises(DhcpError):
        decode_typed(opt(code, 0, 0, 1))


def test_netbios_node_type_is_one_of_the_four_listed_values() -> None:
    """Section 8.7 paragraph 2."""
    for value in (1, 2, 4, 8):
        assert decode_typed(opt(46, value)) == value
    for bad in (0, 3, 16):
        with pytest.raises(DhcpError):
            decode_typed(opt(46, bad))


def test_message_type_overload_and_parameter_request_list() -> None:
    assert decode_typed(opt(53, 5)) == 5  # section 9.6: DHCPACK
    assert decode_typed(opt(53, 10)) == 10  # a type a later RFC adds is not refused
    with pytest.raises(DhcpError):
        decode_typed(opt(53, 0))
    with pytest.raises(DhcpError):
        decode_typed(opt(53, 5, 5))
    assert decode_typed(opt(52, 3)) == 3  # section 9.3: 1, 2 or 3
    with pytest.raises(DhcpError):
        decode_typed(opt(52, 4))
    assert decode_typed(opt(55, 1, 3, 6, 15)) == [1, 3, 6, 15]  # section 9.8
    with pytest.raises(DhcpError, match="at least one"):
        decode_typed(Option4(55, b""))


def test_requested_address_and_server_identifier_are_addresses() -> None:
    assert decode_typed(opt(50, 192, 0, 2, 50)) == A("192.0.2.50")
    assert decode_typed(opt(54, 192, 0, 2, 1)) == A("192.0.2.1")


def test_vendor_options_are_opaque_but_not_empty() -> None:
    assert decode_typed(Option4(43, b"\x01\x02ab")) == b"\x01\x02ab"
    assert decode_typed(Option4(60, b"MSFT 5.0")) == b"MSFT 5.0"
    with pytest.raises(DhcpError):
        decode_typed(Option4(60, b""))


def test_an_option_this_module_does_not_decode_is_left_alone() -> None:
    for code in (61, 82, 121, 200, 0, 255):
        assert decode_typed(Option4(code, b"\x01")) is None
        assert typed_kind(code) is None


def test_every_decoded_code_is_a_code_iana_lists_for_rfc_2132() -> None:
    """The table cannot name a code that IANA does not credit to RFC 2132."""
    decoded = [code for code in range(256) if typed_kind(code) is not None]
    assert len(decoded) > 60
    for code in decoded:
        _name, _length, rfcs = OPTIONS[code]
        assert "RFC 2132" in rfcs, code


def test_every_decoded_fixed_length_agrees_with_the_length_iana_writes() -> None:
    """IANA's length column ("4", "2", "1", "N") is an independent check on the width table."""
    widths = {
        OptionKind.ADDRESS: "4",
        OptionKind.INT32: "4",
        OptionKind.UINT8: "1",
        OptionKind.UINT16: "2",
        OptionKind.UINT32: "4",
        OptionKind.BOOL: "1",
        OptionKind.NODE_TYPE: "1",
        OptionKind.OVERLOAD: "1",
        OptionKind.MESSAGE_TYPE: "1",
    }
    # Option 16 is the one disagreement: RFC 2132 section 3.18 paragraph 2 says "its length is 4",
    # IANA's table says "N". The RFC is the authority; the registry row is recorded as found.
    known_iana_disagreements = {16: "N"}
    for code in range(256):
        kind = typed_kind(code)
        if kind in widths:
            expected = known_iana_disagreements.get(code, widths[kind])
            assert OPTIONS[code][1] == expected, (code, OPTIONS[code])
    assert decode_typed(opt(16, 192, 0, 2, 9)) == A("192.0.2.9")
    with pytest.raises(DhcpError):
        decode_typed(opt(16, 192, 0, 2, 9, 192, 0, 2, 10))


def test_the_error_names_the_option_and_the_section() -> None:
    with pytest.raises(DhcpError) as caught:
        decode_typed(opt(28, 1, 2, 3))
    assert re.search(r"option 28 \(RFC 2132 section 5\.3\)", str(caught.value))
