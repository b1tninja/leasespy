"""option registry, encoders and decoders (RFC 2132, RFC 9915 sec. 21).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Options = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "decode_options",
    "encode_option",
]


def encode_option(code: int, value: object) -> bytes:
    """Pending behaviour defined by RFC 2132, RFC 9915 sec. 21.

    Not implemented yet. See the ``options.encode_option()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("encode_option() is not implemented: RFC 2132, RFC 9915 sec. 21")


def decode_options(raw: bytes) -> Options:
    """Pending behaviour defined by RFC 9915 sec. 21.

    Not implemented yet. See the ``options.decode_options()`` row in ROADMAP.md; this
    stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("decode_options() is not implemented: RFC 9915 sec. 21")
