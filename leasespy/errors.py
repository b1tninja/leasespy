"""The one exception the decoders raise for input they refuse."""

from __future__ import annotations

__all__ = ["DhcpError"]


class DhcpError(ValueError):
    """Bytes or values that cannot be a DHCP structure.

    Decoders raise this and nothing else for hostile input. It subclasses ``ValueError`` so a
    caller that only knows the standard library still catches it.
    """
