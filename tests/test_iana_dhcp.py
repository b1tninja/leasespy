"""The generated IANA DHCP table: provenance, the codes the codec relies on, and drift."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import pytest

from leasespy import _iana_dhcp as table
from leasespy.options4 import (
    OPTION_CLIENT_ID,
    OPTION_END,
    OPTION_MAX_MESSAGE_SIZE,
    OPTION_MESSAGE_TYPE,
    OPTION_OVERLOAD,
    OPTION_PAD,
    message_type_name,
    option_name,
)
from leasespy.wire4 import DhcpMessageType


def test_snapshot_is_dated_and_hashed() -> None:
    source = {key: str(value) for key, value in table.SOURCE.items()}
    assert re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", source["registry_updated"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", source["fetched"])
    assert source["url"].startswith("https://www.iana.org/assignments/bootp-dhcp-parameters/")
    assert source["licence"] == "CC0-1.0"


def test_the_codes_the_codec_names_carry_iana_s_names() -> None:
    assert option_name(OPTION_PAD) == "Pad"
    assert option_name(OPTION_END) == "End"
    assert option_name(OPTION_OVERLOAD) == "Overload"
    assert option_name(OPTION_MESSAGE_TYPE) == "DHCP Msg Type"
    assert option_name(OPTION_MAX_MESSAGE_SIZE) == "DHCP Max Msg Size"
    assert option_name(OPTION_CLIENT_ID) == "Client Id"


def test_the_client_message_types_match_the_registry() -> None:
    for member in DhcpMessageType:
        assert message_type_name(member.value) == f"DHCP{member.name}"


def test_ranges_and_unknowns_are_named_not_invented() -> None:
    assert option_name(250) == "Reserved (Private Use)"
    assert option_name(1000) == "unassigned"
    assert message_type_name(200) == "unassigned"


def test_every_message_type_cites_an_rfc() -> None:
    assert all(refs for _, refs in table.MESSAGE_TYPES.values())


def test_the_committed_table_matches_a_local_primarysource_copy_when_there_is_one() -> None:
    home = os.environ.get("PRIMARYSOURCE_HOME")
    path = Path(home) / "iana" / "bootp-dhcp-parameters.xml" if home else None
    if path is None or not path.exists():
        pytest.skip("no primarysource copy of bootp-dhcp-parameters.xml")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == table.SOURCE["sha256"], "regenerate with tools/gen_iana_dhcp.py and review"
