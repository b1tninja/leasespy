"""relay forwarding and option 82 (RFC 9915 sec. 19, RFC 3046, RFC 6422).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Endpoint = Any  # placeholder: give it a real type in the milestone that needs it
    Message = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "wrap_relay_forward",
]


def wrap_relay_forward(peer: Endpoint, link: Endpoint, msg: Message) -> bytes:
    """Pending behaviour defined by RFC 9915 sec. 9.

    Not implemented yet. See the ``relay.wrap_relay_forward()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("wrap_relay_forward() is not implemented: RFC 9915 sec. 9")
