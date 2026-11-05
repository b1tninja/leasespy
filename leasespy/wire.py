"""DHCPv4 and DHCPv6 message formats (RFC 2131, RFC 9915 sec. 8, sec. 9).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Bootp = Any  # placeholder: give it a real type in the milestone that needs it
    Message = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_v4",
    "decode_v6",
    "encode_v6",
]


def decode_v6(raw: bytes) -> Message:
    """Pending behaviour defined by RFC 9915 sec. 8.

    Not implemented yet. See the ``wire.decode_v6()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_v6() is not implemented: RFC 9915 sec. 8")


def encode_v6(msg: Message) -> bytes:
    """Pending behaviour defined by RFC 9915 sec. 8.

    Not implemented yet. See the ``wire.encode_v6()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_v6() is not implemented: RFC 9915 sec. 8")


def decode_v4(raw: bytes) -> Bootp:
    """Pending behaviour defined by RFC 2131.

    Not implemented yet. See the ``wire.decode_v4()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_v4() is not implemented: RFC 2131")
