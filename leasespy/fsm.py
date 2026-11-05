"""client and server state machines with retransmission (RFC 9915 sec. 14, sec. 15, sec. 18).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    ClientState = Any  # placeholder: give it a real type in the milestone that needs it
    Event = Any  # placeholder: give it a real type in the milestone that needs it
    Step = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "client_step",
]


def client_step(state: ClientState, event: Event, now: float) -> Step:
    """Pending behaviour defined by RFC 9915 sec. 18.

    Not implemented yet. See the ``fsm.client_step()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("client_step() is not implemented: RFC 9915 sec. 18")
