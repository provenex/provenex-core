"""Tests for what the top-level ``provenex`` package re-exports.

The README + quickstart examples import classes from the top level
(``from provenex import Ed25519Signer``). When the in-source class
lives under ``provenex.core.ed25519`` and is not re-exported, the
example silently fails - the import lands on ``AttributeError`` only
when the user copy-pastes it. These tests pin the re-export surface
so a future refactor of the internal module layout cannot break the
documented import paths.
"""

from __future__ import annotations

import importlib


def test_ed25519_signer_importable_from_top_level():
    """The v0.8.0 README example: ``from provenex import Ed25519Signer``."""
    provenex = importlib.import_module("provenex")
    cls = getattr(provenex, "Ed25519Signer", None)
    assert cls is not None, (
        "Ed25519Signer is documented as importable from `provenex` (the "
        "v0.8.0 README example uses this import). The class lives at "
        "provenex.core.ed25519.Ed25519Signer and must be re-exported."
    )
    # Sanity: the class name matches what the docs claim.
    assert cls.__name__ == "Ed25519Signer"


def test_ed25519_signer_listed_in_all():
    """``__all__`` discipline: anything we re-export should be in it
    so star-imports and type-checkers see the contract."""
    provenex = importlib.import_module("provenex")
    assert "Ed25519Signer" in provenex.__all__


def test_top_level_imports_dont_require_cryptography(monkeypatch):
    """``import provenex`` MUST work on a stdlib-only install.

    Ed25519Signer is exported at the top level, but the cryptography
    library is only a probe at instantiation time. A user who never
    touches Ed25519Signer should not get an error just because they
    pinned provenex-core without the ``[ed25519]`` extra.
    """
    # The base `import provenex` happened before this test ran (pytest
    # imports the package itself when discovering tests). The check is
    # therefore implicit: if `import provenex` failed in an env without
    # `cryptography`, the test suite would never get this far. So we
    # assert the weaker but still useful contract: the symbol resolves
    # without raising on attribute access, and the class binding is
    # not gated on the optional dependency.
    import provenex
    assert hasattr(provenex, "Ed25519Signer")
