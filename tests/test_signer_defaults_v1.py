"""Tests for the v1.0.0 default-signer resolution.

The v1.0.0 default is Ed25519 (asymmetric, third-party verifiable).
``resolve_default_signer()`` reads ``PROVENEX_RECEIPT_PRIVATE_KEY_PATH``
first; falls back to ``PROVENEX_RECEIPT_SECRET`` (HMAC); refuses to
silently invent a transient keypair if neither is set.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from provenex import Ed25519Signer, HmacSha256Signer, resolve_default_signer


def _write_ed25519_key(path: Path) -> None:
    signer = Ed25519Signer.generate()
    path.write_bytes(signer.private_key_pem())


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Each test starts with no signer env vars; opts in explicitly."""
    monkeypatch.delenv("PROVENEX_RECEIPT_PRIVATE_KEY_PATH", raising=False)
    monkeypatch.delenv("PROVENEX_RECEIPT_SECRET", raising=False)
    monkeypatch.delenv("PROVENEX_SIGNING_SECRET", raising=False)
    yield


# --------------------------------------------------------------------------- #
# resolve_default_signer                                                      #
# --------------------------------------------------------------------------- #


def test_ed25519_pem_path_takes_precedence(monkeypatch, tmp_path):
    pem_path = tmp_path / "private.pem"
    _write_ed25519_key(pem_path)
    monkeypatch.setenv("PROVENEX_RECEIPT_PRIVATE_KEY_PATH", str(pem_path))
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", "fallback-secret")
    signer = resolve_default_signer()
    assert isinstance(signer, Ed25519Signer)
    assert signer.algorithm == "ed25519"


def test_hmac_secret_used_when_no_pem_path(monkeypatch):
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", "hmac-only-secret")
    signer = resolve_default_signer()
    assert isinstance(signer, HmacSha256Signer)
    assert signer.algorithm == "hmac-sha256"


def test_legacy_signing_secret_used_when_no_other_env(monkeypatch):
    monkeypatch.setenv("PROVENEX_SIGNING_SECRET", "legacy-shared-secret")
    signer = resolve_default_signer()
    assert isinstance(signer, HmacSha256Signer)


def test_no_env_raises_with_actionable_message():
    with pytest.raises(RuntimeError) as excinfo:
        resolve_default_signer()
    msg = str(excinfo.value)
    assert "provenex keys generate" in msg
    assert "PROVENEX_RECEIPT_PRIVATE_KEY_PATH" in msg
    assert "PROVENEX_RECEIPT_SECRET" in msg


def test_unreadable_pem_path_raises(monkeypatch, tmp_path):
    bad_path = tmp_path / "nonexistent.pem"
    monkeypatch.setenv("PROVENEX_RECEIPT_PRIVATE_KEY_PATH", str(bad_path))
    with pytest.raises(RuntimeError, match="PROVENEX_RECEIPT_PRIVATE_KEY_PATH"):
        resolve_default_signer()


def test_resolved_ed25519_signer_can_sign_and_verify(monkeypatch, tmp_path):
    pem_path = tmp_path / "private.pem"
    _write_ed25519_key(pem_path)
    monkeypatch.setenv("PROVENEX_RECEIPT_PRIVATE_KEY_PATH", str(pem_path))
    signer = resolve_default_signer()
    payload = b"some bytes to sign"
    signature = signer.sign(payload)
    assert signer.verify(payload, signature) is True
    assert signer.verify(b"different bytes", signature) is False


# --------------------------------------------------------------------------- #
# Ed25519Signer.from_env                                                      #
# --------------------------------------------------------------------------- #


def test_from_env_reads_pem_path(monkeypatch, tmp_path):
    pem_path = tmp_path / "private.pem"
    _write_ed25519_key(pem_path)
    monkeypatch.setenv("PROVENEX_RECEIPT_PRIVATE_KEY_PATH", str(pem_path))
    signer = Ed25519Signer.from_env()
    assert isinstance(signer, Ed25519Signer)


def test_from_env_raises_when_unset():
    with pytest.raises(RuntimeError, match="PROVENEX_RECEIPT_PRIVATE_KEY_PATH"):
        Ed25519Signer.from_env()


def test_from_env_raises_on_unreadable_file(monkeypatch, tmp_path):
    bad_path = tmp_path / "missing.pem"
    monkeypatch.setenv("PROVENEX_RECEIPT_PRIVATE_KEY_PATH", str(bad_path))
    with pytest.raises(RuntimeError, match="could not read"):
        Ed25519Signer.from_env()


# --------------------------------------------------------------------------- #
# HMAC is still selectable explicitly                                         #
# --------------------------------------------------------------------------- #


def test_hmac_signer_still_works_when_constructed_directly(monkeypatch):
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", "hello-world")
    signer = HmacSha256Signer()
    assert signer.algorithm == "hmac-sha256"
    signed = signer.sign(b"x")
    assert signer.verify(b"x", signed)
