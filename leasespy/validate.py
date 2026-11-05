"""message validation and error handling (RFC 9915 sec. 16).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Message = Any  # placeholder: give it a real type in the milestone that needs it
    ServerContext = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "check_message",
]


def check_message(msg: Message, context: ServerContext) -> list:
    """Pending behaviour defined by RFC 9915 sec. 16.

    Not implemented yet. See the ``validate.check_message()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("check_message() is not implemented: RFC 9915 sec. 16")
