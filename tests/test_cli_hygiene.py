"""CLI hygiene verbs: keys init, register, verify-absence, purge-mark.

Drives the CLI in-process through ``main()`` the way an agent runtime
(not a Python embedder) would drive the binary.
"""

from __future__ import annotations

import json

from provenex.cli.main import main
from provenex.core.absence import verify_absence_receipt
from provenex.core.ed25519 import Ed25519Signer
from provenex.index.base import VerificationOutcome
from provenex.index.sqlite_index import SQLiteProvenanceIndex


def _hygiene_home(tmp_path):
    keys_dir = tmp_path / "keys"
    assert main(["keys", "init", "--output-dir", str(keys_dir)]) == 0
    assert (keys_dir / "private.pem").exists()
    assert (keys_dir / "index_secret").exists()
    import stat

    assert stat.S_IMODE((keys_dir / "index_secret").stat().st_mode) == 0o600

    logs = tmp_path / "logs"
    logs.mkdir()
    config = {
        "index": "hygiene.db",
        "index_secret": "cli-hygiene-test",
        "receipt_private_key": "keys/private.pem",
        "stores": [
            {
                "store_id": "agent-logs",
                "path_globs": ["logs/*.log"],
                "class": "runtime-log",
                "owner": "agent-runtime",
                "links": ["checkout-1"],
            }
        ],
    }
    (tmp_path / "config.json").write_text(json.dumps(config))
    return keys_dir, logs


def test_cli_register_present_purge_absent_mark(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    keys_dir, logs = _hygiene_home(tmp_path)
    artifact = logs / "checkout.log"
    artifact.write_text("paid with card 4242 4242 4242 4242; otp SECRET-42-XYZ\n")

    code = main([
        "register", "--config", "config.json", "--file", "logs/checkout.log",
        "--doc-id", "checkout-1",
        "--value", "4242 4242 4242 4242", "--value", "SECRET-42-XYZ",
    ])
    assert code == 0

    present = tmp_path / "present.json"
    assert main([
        "verify-absence", "--config", "config.json",
        "--doc-id", "checkout-1", "--out", str(present),
    ]) == 10  # PRESENT

    artifact.unlink()

    absent = tmp_path / "absent.json"
    assert main([
        "verify-absence", "--config", "config.json",
        "--doc-id", "checkout-1", "--out", str(absent),
    ]) == 0  # ABSENT

    receipt = json.loads(absent.read_text())
    assert receipt["receipt_type"] == "absence_attestation"
    assert receipt["verdict"] == "ABSENT"
    verifier = Ed25519Signer.from_public_key_pem((keys_dir / "public.pem").read_bytes())
    assert verify_absence_receipt(receipt, verifier)

    assert main([
        "purge-mark", "--config", "config.json",
        "--receipt", str(absent), "--doc-id", "checkout-1",
    ]) == 0

    idx = SQLiteProvenanceIndex("hygiene.db", signing_secret=b"cli-hygiene-test")
    entries = idx.entries_for_document("checkout-1")
    assert len(entries) == 3
    assert all(
        idx.verify(e.fingerprint) == VerificationOutcome.PURGED for e in entries
    )


def test_purge_mark_refuses_non_absent_receipt(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _hygiene_home(tmp_path)
    (tmp_path / "present.json").write_text(json.dumps({"verdict": "PRESENT", "results": []}))
    code = main([
        "purge-mark", "--config", "config.json",
        "--receipt", "present.json", "--doc-id", "checkout-1",
    ])
    assert code == 2
    assert "not ABSENT" in capsys.readouterr().err
