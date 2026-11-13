"""DHCPv4 and DHCPv6 message formats (RFC 2131, RFC 9915 sec. 8, sec. 9).

DHCPv6 headers are implemented; DHCPv4 (:func:`decode_v4`) is not and still raises.

The codec does not apply the sec. 16 discard rules. An unknown message type is returned as
:class:`UnknownMessage` so :mod:`leasespy.validate` can make the discard decision.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .errors import DhcpError
from .options import OPTION_RELAY_MSG, Option, decode_options, encode_options

if TYPE_CHECKING:
    from typing import Any

    Bootp = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "ClientServerMessage",
    "Message",
    "MsgType",
    "RelayMessage",
    "UnknownMessage",
    "decode_v4",
    "decode_v6",
    "encode_v6",
    "unwrap_relays",
]


class MsgType(enum.IntEnum):
    """DHCPv6 message types (RFC 9915 sec. 7.3)."""

    SOLICIT = 1
    ADVERTISE = 2
    REQUEST = 3
    CONFIRM = 4
    RENEW = 5
    REBIND = 6
    REPLY = 7
    RELEASE = 8
    DECLINE = 9
    RECONFIGURE = 10
    INFORMATION_REQUEST = 11
    RELAY_FORW = 12
    RELAY_REPL = 13


_RELAY_TYPES = (MsgType.RELAY_FORW, MsgType.RELAY_REPL)
_CS_HEADER = struct.Struct("!B3s")
_RELAY_HEADER = struct.Struct("!BB16s16s")


@dataclass(frozen=True, slots=True)
class ClientServerMessage:
    """A client/server message: msg-type, 3-octet transaction-id, options (sec. 8)."""

    msg_type: MsgType
    transaction_id: bytes
    options: tuple[Option, ...] = ()


@dataclass(frozen=True, slots=True)
class RelayMessage:
    """A Relay-forward or Relay-reply message (sec. 9)."""

    msg_type: MsgType
    hop_count: int
    link_address: bytes
    peer_address: bytes
    options: tuple[Option, ...] = ()

    def relayed_message(self) -> bytes:
        """The data of the Relay Message option, which sec. 9.1 and sec. 9.2 require."""
        for option in self.options:
            if option.code == OPTION_RELAY_MSG:
                return option.data
        raise DhcpError("relay message without a Relay Message option")


@dataclass(frozen=True, slots=True)
class UnknownMessage:
    """A message whose msg-type is not one of sec. 7.3. The caller decides (sec. 16)."""

    msg_type: int
    payload: bytes


Message = ClientServerMessage | RelayMessage | UnknownMessage


def decode_v6(raw: bytes) -> Message:
    """Decode a DHCPv6 message (RFC 9915 sec. 8, sec. 9).

    Raises :class:`DhcpError` for a header that does not fit, for malformed options, and for
    a relay message without a Relay Message option (sec. 9.1 and sec. 9.2 say it MUST be there).
    """
    data = bytes(raw)
    if not data:
        raise DhcpError("empty DHCPv6 message")
    kind = data[0]
    if kind in _RELAY_TYPES:
        if len(data) < _RELAY_HEADER.size:
            raise DhcpError(f"relay message of {len(data)} octets is shorter than 34")
        _, hop_count, link, peer = _RELAY_HEADER.unpack_from(data)
        message = RelayMessage(
            MsgType(kind),
            hop_count,
            link,
            peer,
            tuple(decode_options(data[_RELAY_HEADER.size :])),
        )
        message.relayed_message()
        return message
    try:
        msg_type = MsgType(kind)
    except ValueError:
        return UnknownMessage(kind, data[1:])
    if len(data) < _CS_HEADER.size:
        raise DhcpError(f"client/server message of {len(data)} octets is shorter than 4")
    _, transaction_id = _CS_HEADER.unpack_from(data)
    return ClientServerMessage(
        msg_type, transaction_id, tuple(decode_options(data[_CS_HEADER.size :]))
    )


def encode_v6(msg: Message) -> bytes:
    """Encode a DHCPv6 message (RFC 9915 sec. 8, sec. 9)."""
    if isinstance(msg, ClientServerMessage):
        if msg.msg_type in _RELAY_TYPES:
            raise DhcpError("a relay msg-type needs a RelayMessage")
        if len(msg.transaction_id) != 3:
            raise DhcpError("transaction-id must be 3 octets")
        return _CS_HEADER.pack(int(msg.msg_type), msg.transaction_id) + encode_options(msg.options)
    if isinstance(msg, RelayMessage):
        if msg.msg_type not in _RELAY_TYPES:
            raise DhcpError("a RelayMessage must be RELAY-FORW or RELAY-REPL")
        if not 0 <= msg.hop_count <= 255:
            raise DhcpError("hop-count must fit in 1 octet")
        if len(msg.link_address) != 16 or len(msg.peer_address) != 16:
            raise DhcpError("link-address and peer-address must be 16 octets")
        msg.relayed_message()
        header = _RELAY_HEADER.pack(
            int(msg.msg_type), msg.hop_count, msg.link_address, msg.peer_address
        )
        return header + encode_options(msg.options)
    raise DhcpError("only decoded known messages can be encoded")


def unwrap_relays(raw: bytes, *, max_depth: int = 32) -> tuple[tuple[RelayMessage, ...], Message]:
    """Peel nested relay messages down to the innermost message (RFC 9915 sec. 9).

    Returns the relay layers outermost first and the innermost message. Iterative, and bounded
    by ``max_depth`` layers (a defensive limit chosen here, not a protocol value), so a hostile
    chain raises :class:`DhcpError` and never ``RecursionError``.
    """
    layers: list[RelayMessage] = []
    current = decode_v6(raw)
    while isinstance(current, RelayMessage):
        if len(layers) >= max_depth:
            raise DhcpError(f"relay nesting deeper than {max_depth}")
        layers.append(current)
        current = decode_v6(current.relayed_message())
    return tuple(layers), current


def decode_v4(raw: bytes) -> Bootp:
    """Pending behaviour defined by RFC 2131.

    Not implemented yet. See the ``wire.decode_v4()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_v4() is not implemented: RFC 2131")
