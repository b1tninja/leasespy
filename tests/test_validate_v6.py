"""The sec. 16 discard rules of RFC 9915 as a decision table. Messages are hand-built."""

from __future__ import annotations

import pytest

from leasespy.duid import Duid, parse_duid
from leasespy.options import (
    OPTION_CLIENTID,
    OPTION_IA_NA,
    OPTION_IA_PD,
    OPTION_RECONF_MSG,
    OPTION_SERVERID,
    Option,
)
from leasespy.validate import OPTION_AUTH, Role, check_message
from leasespy.wire import ClientServerMessage, MsgType, RelayMessage, UnknownMessage

CLIENT = parse_duid(b"\x00\x03\x00\x01\x00\x11\x22\x33\x44\x55")
OTHER = parse_duid(b"\x00\x03\x00\x01\xaa\xbb\xcc\xdd\xee\xff")
SERVER = parse_duid(b"\x00\x02\x00\x00\x7e\xd9\x01")
XID = b"\x01\x02\x03"
LINK = bytes(16)


def opt(code: int, duid: Duid | None = None, data: bytes = b"") -> Option:
    return Option(code, duid.raw if duid else data)


def msg(kind: MsgType, *options: Option, xid: bytes = XID) -> ClientServerMessage:
    return ClientServerMessage(kind, xid, tuple(options))


CID = opt(OPTION_CLIENTID, CLIENT)
SID = opt(OPTION_SERVERID, SERVER)


def server(message, **kwargs):
    return check_message(message, Role.SERVER, own_duid=SERVER, **kwargs)


def client(message, **kwargs):
    kwargs.setdefault("own_duid", CLIENT)
    kwargs.setdefault("sent_transaction_id", XID)
    return check_message(message, Role.CLIENT, **kwargs)


def test_server_discards_request_without_server_id():
    assert not server(msg(MsgType.REQUEST, CID)).accept
    assert server(msg(MsgType.REQUEST, CID, SID)).accept


@pytest.mark.parametrize("kind", [MsgType.REQUEST, MsgType.RENEW, MsgType.DECLINE, MsgType.RELEASE])
def test_server_checks_server_id_and_client_id_for_four_types(kind):
    assert server(msg(kind, CID, SID)).accept
    assert not server(msg(kind, CID)).accept
    assert not server(msg(kind, CID, opt(OPTION_SERVERID, OTHER))).accept
    assert not server(msg(kind, SID)).accept


@pytest.mark.parametrize("kind", [MsgType.SOLICIT, MsgType.CONFIRM, MsgType.REBIND])
def test_server_needs_client_id_and_no_server_id_for_three_types(kind):
    assert server(msg(kind, CID)).accept
    assert not server(msg(kind)).accept
    assert not server(msg(kind, CID, SID)).accept


def test_server_discards_info_request_with_ia_na():
    assert not server(msg(MsgType.INFORMATION_REQUEST, opt(OPTION_IA_NA, data=bytes(12)))).accept
    assert not server(msg(MsgType.INFORMATION_REQUEST, opt(OPTION_IA_PD, data=bytes(12)))).accept
    assert server(msg(MsgType.INFORMATION_REQUEST)).accept
    assert server(msg(MsgType.INFORMATION_REQUEST, CID, SID)).accept


def test_info_request_with_foreign_server_id_discarded_and_extra_ia_codes():
    assert not server(msg(MsgType.INFORMATION_REQUEST, opt(OPTION_SERVERID, OTHER))).accept
    extra = frozenset({4242})
    assert not server(
        msg(MsgType.INFORMATION_REQUEST, Option(4242, b"")), extra_ia_codes=extra
    ).accept
    assert server(msg(MsgType.INFORMATION_REQUEST, Option(4242, b""))).accept


@pytest.mark.parametrize(
    "kind", [MsgType.ADVERTISE, MsgType.REPLY, MsgType.RECONFIGURE, MsgType.RELAY_REPL]
)
def test_server_discards_what_only_clients_or_relays_receive(kind):
    if kind is MsgType.RELAY_REPL:
        message = RelayMessage(kind, 0, LINK, LINK, (Option(9, b"x"),))
    else:
        message = msg(kind, CID, SID)
    assert not server(message).accept


def test_client_discards_message_types_only_servers_receive():
    for kind in (
        MsgType.SOLICIT,
        MsgType.REQUEST,
        MsgType.CONFIRM,
        MsgType.RENEW,
        MsgType.REBIND,
        MsgType.DECLINE,
        MsgType.RELEASE,
        MsgType.INFORMATION_REQUEST,
    ):
        assert not client(msg(kind, CID, SID)).accept, kind


def test_client_accepts_good_advertise():
    assert client(msg(MsgType.ADVERTISE, CID, SID)).accept


def test_client_discards_advertise_with_foreign_client_id():
    assert not client(msg(MsgType.ADVERTISE, opt(OPTION_CLIENTID, OTHER), SID)).accept


def test_client_discards_advertise_missing_ids_or_wrong_xid():
    assert not client(msg(MsgType.ADVERTISE, CID)).accept
    assert not client(msg(MsgType.ADVERTISE, SID)).accept
    assert not client(msg(MsgType.ADVERTISE, CID, SID, xid=b"\x09\x09\x09")).accept


def test_reply_rules_when_original_had_client_id():
    original = {"sent_client_id": CLIENT}
    assert client(msg(MsgType.REPLY, CID, SID), **original).accept
    assert not client(msg(MsgType.REPLY, SID), **original).accept
    assert not client(msg(MsgType.REPLY, opt(OPTION_CLIENTID, OTHER), SID), **original).accept
    assert not client(msg(MsgType.REPLY, CID), **original).accept
    assert not client(msg(MsgType.REPLY, CID, SID, xid=b"\x00\x00\x00"), **original).accept


def test_reply_without_client_id_when_request_had_none_accepted():
    assert client(msg(MsgType.REPLY, SID), sent_client_id=None).accept


def test_reply_with_client_id_when_request_had_none_rejected():
    assert not client(msg(MsgType.REPLY, CID, SID), sent_client_id=None).accept


RECONF_OK = (
    CID,
    SID,
    Option(OPTION_RECONF_MSG, bytes([5])),
    Option(OPTION_AUTH, b"\x00"),
)


def test_reconfigure_good_and_bad_variants():
    assert client(msg(MsgType.RECONFIGURE, *RECONF_OK), was_unicast=True).accept
    for kind in (5, 6, 11):
        reconf = Option(OPTION_RECONF_MSG, bytes([kind]))
        assert client(
            msg(MsgType.RECONFIGURE, CID, SID, reconf, RECONF_OK[3]), was_unicast=True
        ).accept
    bad_type = Option(OPTION_RECONF_MSG, bytes([7]))
    assert not client(
        msg(MsgType.RECONFIGURE, CID, SID, bad_type, RECONF_OK[3]), was_unicast=True
    ).accept
    assert not client(msg(MsgType.RECONFIGURE, CID, SID, RECONF_OK[3]), was_unicast=True).accept
    assert not client(msg(MsgType.RECONFIGURE, CID, SID, RECONF_OK[2]), was_unicast=True).accept
    assert not client(msg(MsgType.RECONFIGURE, SID, *RECONF_OK[2:]), was_unicast=True).accept
    assert not client(msg(MsgType.RECONFIGURE, CID, *RECONF_OK[2:]), was_unicast=True).accept
    other = opt(OPTION_CLIENTID, OTHER)
    assert not client(msg(MsgType.RECONFIGURE, other, SID, *RECONF_OK[2:]), was_unicast=True).accept


def test_reconfigure_multicast_rejected():
    assert not client(msg(MsgType.RECONFIGURE, *RECONF_OK), was_unicast=False).accept


def test_reconfigure_without_was_unicast_is_a_caller_error():
    with pytest.raises(ValueError, match="was_unicast"):
        client(msg(MsgType.RECONFIGURE, *RECONF_OK))


def test_relay_messages_by_role():
    forward = RelayMessage(MsgType.RELAY_FORW, 0, LINK, LINK, (Option(9, b"x"),))
    reply = RelayMessage(MsgType.RELAY_REPL, 0, LINK, LINK, (Option(9, b"x"),))
    assert not check_message(forward, Role.CLIENT).accept
    assert check_message(forward, Role.SERVER, own_duid=SERVER).accept
    assert check_message(forward, Role.RELAY).accept
    assert not check_message(reply, Role.CLIENT).accept
    assert not check_message(reply, Role.SERVER, own_duid=SERVER).accept
    assert check_message(reply, Role.RELAY).accept


def test_relay_discards_advertise_reply_reconfigure_but_relays_client_messages():
    for kind in (MsgType.ADVERTISE, MsgType.REPLY, MsgType.RECONFIGURE):
        assert not check_message(msg(kind, CID, SID), Role.RELAY).accept
    assert check_message(msg(MsgType.SOLICIT, CID), Role.RELAY).accept


def test_unknown_message_type_discarded_unknown_option_kept():
    for role in Role:
        assert not check_message(UnknownMessage(0xEE, b""), role).accept
    assert server(msg(MsgType.SOLICIT, CID, Option(0xBEEF, b"junk"))).accept


def test_transport_rules_are_should_not_and_overridable():
    solicit = msg(MsgType.SOLICIT, CID)
    assert not server(solicit, was_unicast=True).accept
    assert server(solicit, was_unicast=True, accept_unicast_from_clients=True).accept
    assert server(solicit, was_unicast=False).accept
    assert not check_message(solicit, Role.RELAY, was_unicast=True).accept
    assert not client(msg(MsgType.ADVERTISE, CID, SID), was_unicast=False).accept
    assert client(msg(MsgType.ADVERTISE, CID, SID), was_unicast=True).accept


def test_server_role_without_own_duid_is_a_caller_error():
    with pytest.raises(ValueError, match="own_duid"):
        check_message(msg(MsgType.REQUEST, CID, SID), Role.SERVER)


def test_every_message_type_times_every_role_has_a_verdict():
    for kind in MsgType:
        if kind in (MsgType.RELAY_FORW, MsgType.RELAY_REPL):
            message = RelayMessage(kind, 0, LINK, LINK, (Option(9, b"x"),))
        else:
            message = msg(kind, CID, SID, *RECONF_OK[2:])
        for role in Role:
            verdict = check_message(
                message,
                role,
                own_duid=SERVER if role is Role.SERVER else CLIENT,
                sent_transaction_id=XID,
                sent_client_id=CLIENT,
                was_unicast=True,
            )
            assert isinstance(verdict.accept, bool)


def test_reason_always_cites_a_section():
    for kind in MsgType:
        if kind in (MsgType.RELAY_FORW, MsgType.RELAY_REPL):
            message = RelayMessage(kind, 0, LINK, LINK, (Option(9, b"x"),))
        else:
            message = msg(kind)
        for role in Role:
            verdict = check_message(
                message,
                role,
                own_duid=SERVER if role is Role.SERVER else CLIENT,
                sent_transaction_id=XID,
                sent_client_id=CLIENT,
                was_unicast=True,
            )
            assert "RFC 9915 sec. 16" in verdict.reason
