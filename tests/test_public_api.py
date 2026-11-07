"""The shell contract: the surface exists, is documented, and refuses to lie.

These are the tests that must fail loudly if a stub ever starts returning a plausible
empty value instead of raising. That is how a protocol library quietly becomes wrong: a
decoder learns to return an empty object rather than refuse, and every caller downstream
reads confidence where there was only silence.
"""

from __future__ import annotations

import importlib

import pytest

import leasespy as package

SURFACE = [
    ("wire", "decode_v6", "RFC 9915 sec. 8"),
    ("wire", "encode_v6", "RFC 9915 sec. 8"),
    ("wire", "decode_v4", "RFC 2131"),
    ("options", "encode_option", "RFC 2132, RFC 9915 sec. 21"),
    ("options", "decode_options", "RFC 9915 sec. 21"),
    ("duid", "parse_duid", "RFC 9915 sec. 11"),
    ("fsm", "client_step", "RFC 9915 sec. 18"),
    ("validate", "check_message", "RFC 9915 sec. 16"),
    ("relay", "wrap_relay_forward", "RFC 9915 sec. 9"),
    ("leasequery", "build_query", "RFC 5007"),
    ("failover", "peer_transition", "RFC 8156"),
]


def test_version_is_a_string():
    assert isinstance(package.__version__, str)


def test_public_names_all_exist():
    missing = [name for name in package.__all__ if not hasattr(package, name)]
    assert not missing, "__all__ names things that do not exist: " + ", ".join(missing)


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_surface_is_documented(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    assert target.__doc__, fn + " needs a docstring"
    # Docstrings are wrapped, so a long citation can span a line break; compare words, not layout.
    assert " ".join(cite.split()) in " ".join(target.__doc__.split()), (
        fn + " must cite the document that defines it"
    )


@pytest.mark.parametrize(("module_name", "fn", "cite"), SURFACE)
def test_stubs_are_loud(module_name, fn, cite):
    module = importlib.import_module(package.__name__ + "." + module_name)
    target = getattr(module, fn)
    if "Not implemented yet" not in (target.__doc__ or ""):
        pytest.skip(fn + " is implemented; pin it with a real vector test now")
    with pytest.raises((NotImplementedError, TypeError)):
        target()
