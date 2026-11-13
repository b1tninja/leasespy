"""leasespy -- DHCP clients, servers and relays on asyncio.

DHCPv6 was reissued in January 2026 as RFC 9915, an Internet Standard (STD 102) that
obsoletes RFC 8415 and deliberately removes IA_TA and the server unicast option.
"""

from __future__ import annotations

from . import (
    apps,
    cli,
    clock,
    duid,
    failover,
    fsm,
    identity,
    leasequery,
    options,
    relay,
    validate,
    wire,
)
from .duid import parse_duid
from .failover import peer_transition
from .fsm import client_step
from .leasequery import build_query
from .options import decode_options, encode_option
from .relay import wrap_relay_forward
from .validate import check_message
from .wire import decode_v4, decode_v6, encode_v4, encode_v6

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "apps",
    "build_query",
    "check_message",
    "cli",
    "client_step",
    "clock",
    "decode_options",
    "decode_v4",
    "decode_v6",
    "duid",
    "encode_option",
    "encode_v4",
    "encode_v6",
    "failover",
    "fsm",
    "identity",
    "leasequery",
    "options",
    "parse_duid",
    "peer_transition",
    "relay",
    "validate",
    "wire",
    "wrap_relay_forward",
]
