"""Tests for ``provenex keys generate`` (v1.0.0)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from provenex.cli.main import main as cli_main
from provenex.core.ed25519 import Ed25519Signer


def _run(argv, capsys):
    rc = cli_main(argv)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_generates_keypair(tmp_path, capsys):
    out_dir = tmp_path / "keys"
    rc, out, err = _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    assert rc == 0, (out, err)
    private_pem = out_dir / "private.pem"
    public_pem = out_dir / "public.pem"
    assert private_pem.exists()
    assert public_pem.exists()
    # Both files contain PEM headers.
    assert b"-----BEGIN PRIVATE KEY-----" in private_pem.read_bytes()
    assert b"-----BEGIN PUBLIC KEY-----" in public_pem.read_bytes()


def test_next_step_hint_printed(tmp_path, capsys):
    out_dir = tmp_path / "keys"
    rc, out, _ = _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    assert rc == 0
    assert "PROVENEX_RECEIPT_PRIVATE_KEY_PATH=" in out


def test_private_key_mode_is_0600(tmp_path, capsys):
    """A private key with looser permissions is the canonical operator mistake."""
    out_dir = tmp_path / "keys"
    _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    mode = stat.S_IMODE(os.stat(out_dir / "private.pem").st_mode)
    assert mode == 0o600, oct(mode)


def test_public_key_mode_is_0644(tmp_path, capsys):
    out_dir = tmp_path / "keys"
    _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    mode = stat.S_IMODE(os.stat(out_dir / "public.pem").st_mode)
    assert mode == 0o644, oct(mode)


def test_refuses_to_overwrite_existing(tmp_path, capsys):
    out_dir = tmp_path / "keys"
    _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    # Second invocation without --force must fail.
    rc, _, err = _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    assert rc == 2
    assert "already exists" in err


def test_force_overwrites_existing(tmp_path, capsys):
    out_dir = tmp_path / "keys"
    _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    first_private = (out_dir / "private.pem").read_bytes()
    rc, _, _ = _run(
        ["keys", "generate", "--output-dir", str(out_dir), "--force"], capsys
    )
    assert rc == 0
    second_private = (out_dir / "private.pem").read_bytes()
    assert first_private != second_private  # fresh keypair


def test_creates_output_dir_when_missing(tmp_path, capsys):
    nested = tmp_path / "deeply" / "nested" / "keys"
    rc, _, _ = _run(["keys", "generate", "--output-dir", str(nested)], capsys)
    assert rc == 0
    assert (nested / "private.pem").exists()


def test_refuses_to_follow_symlink_at_private_key_path(tmp_path, capsys):
    """Pre-existing symlink at private.pem must not be followed (symlink attack)."""
    out_dir = tmp_path / "keys"
    out_dir.mkdir()
    target = tmp_path / "sensitive.txt"
    target.write_text("must not be overwritten")
    (out_dir / "private.pem").symlink_to(target)
    rc, _, err = _run(
        ["keys", "generate", "--output-dir", str(out_dir), "--force"], capsys
    )
    assert rc == 2
    assert target.read_text() == "must not be overwritten"


def test_generated_keypair_roundtrips(tmp_path, capsys):
    """A receipt signed with private.pem must verify against public.pem."""
    out_dir = tmp_path / "keys"
    _run(["keys", "generate", "--output-dir", str(out_dir)], capsys)
    private_pem = (out_dir / "private.pem").read_bytes()
    public_pem = (out_dir / "public.pem").read_bytes()
    signer = Ed25519Signer.from_private_key_pem(private_pem)
    verifier = Ed25519Signer.from_public_key_pem(public_pem)
    sig = signer.sign(b"payload bytes")
    assert verifier.verify(b"payload bytes", sig)
    assert not verifier.verify(b"different bytes", sig)
