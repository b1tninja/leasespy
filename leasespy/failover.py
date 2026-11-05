"""peer protocol and states (RFC 8156).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    FailoverState = Any  # placeholder: give it a real type in the milestone that needs it
    PeerEvent = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "peer_transition",
]


def peer_transition(state: FailoverState, event: PeerEvent) -> FailoverState:
    """Pending behaviour defined by RFC 8156.

    Not implemented yet. See the ``failover.peer_transition()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("peer_transition() is not implemented: RFC 8156")
