"""DHCPv6 message headers (RFC 9915 sec. 7.3, sec. 8, sec. 9). Vectors are hand-built."""

from __future__ import annotations

import contextlib
import random

import pytest

from leasespy.errors import DhcpError
from leasespy.options import OPTION_RELAY_MSG, Option
from leasespy.wire import (
    ClientServerMessage,
    MsgType,
    RelayMessage,
    UnknownMessage,
    decode_v6,
    encode_v6,
    unwrap_relays,
)

LINK = bytes(range(16))
PEER = bytes(range(16, 32))


def test_client_server_header():
    wire = bytes.fromhex("01aabbcc00010003112233")
    message = decode_v6(wire)
    assert message == ClientServerMessage(
        MsgType.SOLICIT, b"\xaa\xbb\xcc", (Option(1, b"\x11\x22\x33"),)
    )
    assert encode_v6(message) == wire


def test_message_type_numbers_match_section_7_3():
    assert [int(t) for t in MsgType] == list(range(1, 14))
    assert MsgType.RELAY_FORW == 12
    assert MsgType.RELAY_REPL == 13
    assert MsgType.REPLY == 7


@pytest.mark.parametrize("kind", range(1, 12))
def test_roundtrip_each_of_the_eleven_client_server_types(kind):
    message = ClientServerMessage(MsgType(kind), b"\x01\x02\x03", (Option(8, b"\x00\x00"),))
    assert decode_v6(encode_v6(message)) == message


def test_relay_forward_header_is_34_octets():
    inner = bytes.fromhex("01aabbcc")
    message = RelayMessage(MsgType.RELAY_FORW, 2, LINK, PEER, (Option(OPTION_RELAY_MSG, inner),))
    wire = encode_v6(message)
    assert wire[:34] == bytes([12, 2]) + LINK + PEER
    assert wire[34:] == bytes.fromhex("00090004") + inner
    assert decode_v6(wire) == message


def test_hop_count_and_addresses_roundtrip():
    message = RelayMessage(MsgType.RELAY_REPL, 255, LINK, PEER, (Option(OPTION_RELAY_MSG, b"x"),))
    decoded = decode_v6(encode_v6(message))
    assert isinstance(decoded, RelayMessage)
    assert (decoded.msg_type, decoded.hop_count) == (MsgType.RELAY_REPL, 255)
    assert (decoded.link_address, decoded.peer_address) == (LINK, PEER)


@pytest.mark.parametrize("size", [0, 1, 2, 3])
def test_short_client_server_buffers_raise(size):
    with pytest.raises(DhcpError):
        decode_v6(b"\x01\x00\x00\x00"[:size])


@pytest.mark.parametrize("size", [1, 2, 17, 33])
def test_short_relay_buffers_raise(size):
    with pytest.raises(DhcpError):
        decode_v6((b"\x0c" + b"\x00" * 40)[:size])


def test_relay_without_relay_message_option_raises():
    with pytest.raises(DhcpError):
        decode_v6(bytes([12, 0]) + LINK + PEER)
    with pytest.raises(DhcpError):
        encode_v6(RelayMessage(MsgType.RELAY_FORW, 0, LINK, PEER, ()))


def test_unknown_msg_type_returned_not_raised():
    assert decode_v6(bytes.fromhex("ff0102")) == UnknownMessage(0xFF, b"\x01\x02")
    assert decode_v6(b"\x00") == UnknownMessage(0, b"")


def test_transaction_id_must_be_three_bytes_on_encode():
    with pytest.raises(DhcpError):
        encode_v6(ClientServerMessage(MsgType.SOLICIT, b"\x01\x02", ()))


def test_encode_refuses_mismatched_type_and_shape():
    with pytest.raises(DhcpError):
        encode_v6(ClientServerMessage(MsgType.RELAY_FORW, b"\x00\x00\x00", ()))
    with pytest.raises(DhcpError):
        encode_v6(RelayMessage(MsgType.SOLICIT, 0, LINK, PEER, (Option(9, b""),)))
    with pytest.raises(DhcpError):
        encode_v6(RelayMessage(MsgType.RELAY_FORW, 256, LINK, PEER, (Option(9, b""),)))
    with pytest.raises(DhcpError):
        encode_v6(RelayMessage(MsgType.RELAY_FORW, 0, b"short", PEER, (Option(9, b""),)))


def _wrap(inner: bytes, depth: int) -> bytes:
    for _ in range(depth):
        inner = encode_v6(RelayMessage(MsgType.RELAY_FORW, 0, LINK, PEER, (Option(9, inner),)))
    return inner


def test_unwrap_relays_peels_layers_outermost_first():
    client = encode_v6(ClientServerMessage(MsgType.SOLICIT, b"\x00\x00\x01", ()))
    layers, innermost = unwrap_relays(_wrap(client, 3))
    assert len(layers) == 3
    assert innermost == decode_v6(client)


def test_nested_depth_bound_raises_dhcperror_not_recursionerror():
    client = encode_v6(ClientServerMessage(MsgType.SOLICIT, b"\x00\x00\x01", ()))
    with pytest.raises(DhcpError):
        unwrap_relays(_wrap(client, 40))
    with pytest.raises(DhcpError):
        unwrap_relays(_wrap(client, 4), max_depth=3)
    assert len(unwrap_relays(_wrap(client, 3), max_depth=3)[0]) == 3


def test_fuzz_seeded_never_other_exception():
    rng = random.Random(0x1217)
    for _ in range(5000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 60)))
        if blob and rng.random() < 0.5:
            blob = bytes([rng.choice([1, 7, 11, 12, 13])]) + blob[1:]
        with contextlib.suppress(DhcpError):
            unwrap_relays(blob)
