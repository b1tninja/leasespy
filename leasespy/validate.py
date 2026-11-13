"""message validation and error handling (RFC 9915 sec. 16).

A pure decision table over a decoded message. It answers "must this receiver discard it"; it does
not send the optional UnspecFail reply of sec. 16, verify authentication (sec. 20.4), or look at
anything below the option codes. An unknown option never causes a discard (sec. 16); an unknown
message type always does.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from .duid import Duid
from .options import OPTION_CLIENTID, OPTION_IA_NA, OPTION_IA_PD, OPTION_RECONF_MSG, OPTION_SERVERID
from .wire import ClientServerMessage, Message, MsgType, RelayMessage, UnknownMessage

__all__ = [
    "OPTION_AUTH",
    "Role",
    "Verdict",
    "check_message",
]

OPTION_AUTH = 11  # RFC 9915 sec. 21.11
_VALID_RECONF_TYPES = frozenset({MsgType.RENEW, MsgType.REBIND, MsgType.INFORMATION_REQUEST})


class Role(enum.Enum):
    """Who is receiving the message."""

    CLIENT = "client"
    SERVER = "server"
    RELAY = "relay"


@dataclass(frozen=True, slots=True)
class Verdict:
    """The decision, with the RFC 9915 section that justifies a discard."""

    accept: bool
    reason: str


def _accept(reason: str = "RFC 9915 sec. 16: no discard rule applies") -> Verdict:
    return Verdict(True, reason)


def _discard(reason: str) -> Verdict:
    return Verdict(False, "RFC 9915 " + reason)


def check_message(
    message: Message,
    role: Role,
    *,
    own_duid: Duid | None = None,
    sent_transaction_id: bytes | None = None,
    sent_client_id: Duid | None = None,
    was_unicast: bool | None = None,
    accept_unicast_from_clients: bool = False,
    extra_ia_codes: frozenset[int] = frozenset(),
) -> Verdict:
    """Apply the discard rules of RFC 9915 sec. 16 to one received message.

    ``own_duid`` is the receiver's own DUID: the client's, or the server's. ``sent_transaction_id``
    and ``sent_client_id`` describe the client's original message, for Advertise and Reply;
    ``sent_client_id`` is None when that message carried no Client Identifier. ``was_unicast``
    is None when unknown, in which case the transport rules are skipped, except that a
    Reconfigure needs it and raises ``ValueError`` without it. ``extra_ia_codes`` lets a caller
    add IA option codes beyond IA_NA and IA_PD for the Information-request check; the code of
    the obsolete IA_TA is not stated by RFC 9915, so it is not built in.
    """
    if isinstance(message, UnknownMessage):
        return _discard("sec. 16: unknown message type")
    kind = message.msg_type
    codes = {option.code for option in message.options}

    transport = _transport(message, kind, role, was_unicast, accept_unicast_from_clients)
    if transport is not None:
        return transport

    if isinstance(message, RelayMessage):
        if kind == MsgType.RELAY_FORW:
            if role is Role.CLIENT:
                return _discard("sec. 16.13: client received Relay-forward")
            return _accept()
        if role is not Role.RELAY:
            return _discard("sec. 16.14: only a relay agent accepts Relay-reply")
        return _accept()

    return _check_client_server(
        message,
        codes,
        role,
        own_duid,
        sent_transaction_id,
        sent_client_id,
        was_unicast,
        extra_ia_codes,
    )


def _transport(
    message: Message, kind: int, role: Role, was_unicast: bool | None, allow: bool
) -> Verdict | None:
    if was_unicast is None:
        return None
    from_client = not isinstance(message, RelayMessage) and kind != MsgType.RECONFIGURE
    if role is Role.CLIENT and not was_unicast and kind != MsgType.RECONFIGURE:
        return _discard("sec. 16: clients SHOULD NOT accept multicast messages")
    if role is Role.SERVER and was_unicast and from_client and not allow:
        return _discard("sec. 16: servers SHOULD NOT accept unicast traffic from clients")
    if role is Role.RELAY and was_unicast and from_client and not allow:
        return _discard("sec. 16: relay agents SHOULD NOT accept unicast messages from clients")
    return None


def _check_client_server(
    message: ClientServerMessage,
    codes: set[int],
    role: Role,
    own_duid: Duid | None,
    sent_transaction_id: bytes | None,
    sent_client_id: Duid | None,
    was_unicast: bool | None,
    extra_ia_codes: frozenset[int],
) -> Verdict:
    kind = message.msg_type
    has_server = OPTION_SERVERID in codes
    has_client = OPTION_CLIENTID in codes
    if role is Role.RELAY:
        # A relay agent never accepts a client/server message of any type from the link
        # except those it relays; sec. 16 only states the rule for Advertise, Reply, Reconfigure.
        if kind in (MsgType.ADVERTISE, MsgType.REPLY, MsgType.RECONFIGURE):
            return _discard(f"sec. 16: relay agents discard {kind.name} messages")
        return _accept()
    if role is Role.CLIENT:
        return _check_as_client(
            message,
            has_server,
            has_client,
            own_duid,
            sent_transaction_id,
            sent_client_id,
            was_unicast,
        )
    return _check_as_server(message, has_server, has_client, codes, own_duid, extra_ia_codes)


_CLIENT_DISCARDS = {
    MsgType.SOLICIT: "sec. 16.2",
    MsgType.REQUEST: "sec. 16.4",
    MsgType.CONFIRM: "sec. 16.5",
    MsgType.RENEW: "sec. 16.6",
    MsgType.REBIND: "sec. 16.7",
    MsgType.DECLINE: "sec. 16.8",
    MsgType.RELEASE: "sec. 16.9",
    MsgType.INFORMATION_REQUEST: "sec. 16.12",
}
_SERVER_DISCARDS = {
    MsgType.ADVERTISE: "sec. 16.3",
    MsgType.REPLY: "sec. 16.10",
    MsgType.RECONFIGURE: "sec. 16.11",
}
_NEEDS_SERVER_ID_MATCH = {
    MsgType.REQUEST: "sec. 16.4",
    MsgType.RENEW: "sec. 16.6",
    MsgType.DECLINE: "sec. 16.8",
    MsgType.RELEASE: "sec. 16.9",
}
_NEEDS_NO_SERVER_ID = {
    MsgType.SOLICIT: "sec. 16.2",
    MsgType.CONFIRM: "sec. 16.5",
    MsgType.REBIND: "sec. 16.7",
}


def _check_as_server(
    message: ClientServerMessage,
    has_server: bool,
    has_client: bool,
    codes: set[int],
    own_duid: Duid | None,
    extra_ia_codes: frozenset[int],
) -> Verdict:
    kind = message.msg_type
    if kind in _SERVER_DISCARDS:
        return _discard(f"{_SERVER_DISCARDS[kind]}: server received {kind.name}")
    if kind in _NEEDS_SERVER_ID_MATCH:
        section = _NEEDS_SERVER_ID_MATCH[kind]
        if not has_server:
            return _discard(f"{section}: {kind.name} without Server Identifier")
        if _server_id_differs(message, own_duid):
            return _discard(f"{section}: {kind.name} Server Identifier is not this server's")
        if not has_client:
            return _discard(f"{section}: {kind.name} without Client Identifier")
        return _accept()
    if kind in _NEEDS_NO_SERVER_ID:
        section = _NEEDS_NO_SERVER_ID[kind]
        if not has_client:
            return _discard(f"{section}: {kind.name} without Client Identifier")
        if has_server:
            return _discard(f"{section}: {kind.name} with a Server Identifier")
        return _accept()
    if kind is MsgType.INFORMATION_REQUEST:
        if has_server and _server_id_differs(message, own_duid):
            return _discard(
                "sec. 16.12: Information-request Server Identifier is not this server's"
            )
        if codes & ({OPTION_IA_NA, OPTION_IA_PD} | extra_ia_codes):
            return _discard("sec. 16.12: Information-request includes an IA option")
        return _accept()
    return _accept()


def _server_id_differs(message: ClientServerMessage, own_duid: Duid | None) -> bool:
    if own_duid is None:
        raise ValueError("a server role needs own_duid to compare the Server Identifier")
    server_id = next(option.data for option in message.options if option.code == OPTION_SERVERID)
    return server_id != own_duid.raw


def _client_id_of(message: ClientServerMessage) -> bytes | None:
    return next((o.data for o in message.options if o.code == OPTION_CLIENTID), None)


def _check_as_client(
    message: ClientServerMessage,
    has_server: bool,
    has_client: bool,
    own_duid: Duid | None,
    sent_transaction_id: bytes | None,
    sent_client_id: Duid | None,
    was_unicast: bool | None,
) -> Verdict:
    kind = message.msg_type
    if kind in _CLIENT_DISCARDS:
        return _discard(f"{_CLIENT_DISCARDS[kind]}: client received {kind.name}")
    if kind is MsgType.ADVERTISE:
        if not has_server:
            return _discard("sec. 16.3: Advertise without Server Identifier")
        if not has_client:
            return _discard("sec. 16.3: Advertise without Client Identifier")
        if own_duid is None or sent_transaction_id is None:
            raise ValueError("a client role needs own_duid and sent_transaction_id for Advertise")
        if _client_id_of(message) != own_duid.raw:
            return _discard("sec. 16.3: Advertise Client Identifier is not this client's DUID")
        if message.transaction_id != sent_transaction_id:
            return _discard("sec. 16.3: Advertise transaction-id does not match the Solicit")
        return _accept()
    if kind is MsgType.REPLY:
        if sent_transaction_id is None:
            raise ValueError("a client role needs sent_transaction_id for Reply")
        if not has_server:
            return _discard("sec. 16.10: Reply without Server Identifier")
        if message.transaction_id != sent_transaction_id:
            return _discard("sec. 16.10: Reply transaction-id does not match the original")
        if sent_client_id is not None:
            if not has_client:
                return _discard("sec. 16.10: Reply lacks the Client Identifier the original had")
            if _client_id_of(message) != sent_client_id.raw:
                return _discard("sec. 16.10: Reply Client Identifier does not match the client")
        elif has_client:
            return _discard("sec. 16.10: Reply has a Client Identifier the original did not")
        return _accept()
    if kind is MsgType.RECONFIGURE:
        return _check_reconfigure(message, has_server, has_client, own_duid, was_unicast)
    return _accept()


def _check_reconfigure(
    message: ClientServerMessage,
    has_server: bool,
    has_client: bool,
    own_duid: Duid | None,
    was_unicast: bool | None,
) -> Verdict:
    if was_unicast is None:
        raise ValueError("a Reconfigure needs was_unicast: it must have been unicast to the client")
    if not was_unicast:
        return _discard("sec. 16.11: Reconfigure was not unicast to the client")
    if not has_server:
        return _discard("sec. 16.11: Reconfigure without Server Identifier")
    if not has_client or own_duid is None or _client_id_of(message) != own_duid.raw:
        return _discard("sec. 16.11: Reconfigure Client Identifier is missing or not this client's")
    reconf = next((o for o in message.options if o.code == OPTION_RECONF_MSG), None)
    if reconf is None:
        return _discard("sec. 16.11: Reconfigure without a Reconfigure Message option")
    if len(reconf.data) != 1 or reconf.data[0] not in _VALID_RECONF_TYPES:
        return _discard("sec. 16.11: Reconfigure Message option msg-type is not valid")
    if not any(option.code == OPTION_AUTH for option in message.options):
        return _discard("sec. 16.11: Reconfigure without authentication")
    return _accept("RFC 9915 sec. 16.11: no discard rule applies; authentication not verified")
