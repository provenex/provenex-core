"""CLI tests for `provenex chain verify`."""

from __future__ import annotations

import json
import os

import pytest

from provenex import HmacSha256Signer, WitnessLog
from provenex.cli.main import main


SECRET_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SECRET = SECRET_HEX.encode("utf-8")


@pytest.fixture(autouse=True)
def _set_secret(monkeypatch):
    # Set the env var and use the same string-to-bytes encoding for the
    # signer; this keeps the test free of the latin-1 / utf-8 round-trip
    # fragility while exercising the env-resolution path.
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", SECRET_HEX)


def _populate_log(tmp_path, *, n_records: int = 3) -> str:
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    for i in range(n_records):
        log.append(tree_size=10 * (i + 1), tree_root="sha256:" + str(i) * 64)
    return log_path


def test_chain_verify_on_intact_log_exits_zero(tmp_path, capsys):
    log_path = _populate_log(tmp_path)
    rc = main(["chain", "verify", "--log", log_path])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "Chain integrity" in out
    assert "Checkpoints: 3" in out


def test_chain_verify_on_tampered_log_exits_nonzero(tmp_path, capsys):
    log_path = _populate_log(tmp_path)
    # Flip one byte in the first record's tree_root in place.
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    record = json.loads(lines[0])
    record["tree_root"] = "sha256:" + "f" * 64
    lines[0] = json.dumps(record) + "\n"
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    rc = main(["chain", "verify", "--log", log_path])
    assert rc != 0
    out = capsys.readouterr().out
    assert "FAIL" in out


def test_chain_verify_json_mode(tmp_path, capsys):
    log_path = _populate_log(tmp_path)
    rc = main(["chain", "verify", "--log", log_path, "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["chain_integrity"] is True
    assert payload["checkpoint_count"] == 3
    assert payload["signature_algorithm"] == "hmac-sha256"
    assert payload["overall_status"] == "PASS"
    assert payload["first_checkpoint"]["checkpoint_index"] == 0
    assert payload["latest_checkpoint"]["checkpoint_index"] == 2


def test_chain_verify_errors_when_log_missing(tmp_path, capsys):
    missing = str(tmp_path / "no-such-log.jsonl")
    rc = main(["chain", "verify", "--log", missing])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err


def test_chain_verify_errors_without_hmac_secret(tmp_path, capsys, monkeypatch):
    log_path = _populate_log(tmp_path)
    monkeypatch.delenv("PROVENEX_RECEIPT_SECRET", raising=False)
    monkeypatch.delenv("PROVENEX_SIGNING_SECRET", raising=False)
    rc = main(["chain", "verify", "--log", log_path])
    assert rc != 0
    err = capsys.readouterr().err
    assert "PROVENEX_RECEIPT_SECRET" in err


def test_chain_verify_with_live_index_match(tmp_path, capsys, monkeypatch):
    """When --index is supplied, the latest checkpoint must match live state."""
    from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex

    monkeypatch.setenv("PROVENEX_INDEX_SECRET", "index-secret-32-bytes-min!!!aaaa")
    index_path = str(tmp_path / "index.db")
    index = MerkleSQLiteProvenanceIndex(index_path)
    index.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    live_size = index.tree_size()
    live_root = index.tree_root()
    index.close()

    # Build a witness log whose latest checkpoint matches the index.
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    log.append(tree_size=live_size, tree_root=live_root)

    rc = main(["chain", "verify", "--log", log_path, "--index", index_path])
    assert rc == 0
    out = capsys.readouterr().out
    assert "PASS" in out
    assert "Matches latest checkpoint" in out


def test_chain_verify_with_live_index_mismatch_fails(tmp_path, capsys, monkeypatch):
    """A checkpoint whose tree_root no longer matches live state fails."""
    from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex

    monkeypatch.setenv("PROVENEX_INDEX_SECRET", "index-secret-32-bytes-min!!!aaaa")
    index_path = str(tmp_path / "index.db")
    index = MerkleSQLiteProvenanceIndex(index_path)
    index.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    index.close()

    # Witness log records a stale tree root that doesn't match the index.
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    log.append(tree_size=999, tree_root="sha256:" + "f" * 64)

    rc = main(["chain", "verify", "--log", log_path, "--index", index_path])
    assert rc != 0
    out = capsys.readouterr().out
    assert "FAIL" in out


def test_chain_verify_rejects_nonexistent_index(tmp_path, capsys):
    """--index pointing at a non-existent file must error, not create one.

    MerkleSQLiteProvenanceIndex would silently create a new empty DB
    at the given path; without this check, a typo'd --index would
    falsely report a mismatch instead of pointing at the typo.
    """
    log_path = _populate_log(tmp_path)
    missing_index = str(tmp_path / "no-such-index.db")
    rc = main(["chain", "verify", "--log", log_path, "--index", missing_index])
    assert rc == 2
    err = capsys.readouterr().err
    assert "does not exist" in err
    # And the index file must not have been created as a side effect.
    assert not os.path.exists(missing_index)


def test_chain_verify_rejects_non_merkle_sqlite_index(tmp_path, capsys, monkeypatch):
    """--index pointing at a plain SQLiteProvenanceIndex (no Merkle log) must error."""
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    monkeypatch.setenv("PROVENEX_INDEX_SECRET", "index-secret-32-bytes-min!!!aaaa")
    plain_index_path = str(tmp_path / "plain.db")
    plain = SQLiteProvenanceIndex(plain_index_path)
    plain.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    plain.close()

    log_path = _populate_log(tmp_path)
    rc = main(
        ["chain", "verify", "--log", log_path, "--index", plain_index_path]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "not a Merkle-backed index" in err
    assert "merkle_leaves" in err

    # And the plain DB must not have been mutated (no merkle_leaves added).
    import sqlite3

    conn = sqlite3.connect(plain_index_path)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='merkle_leaves'"
        ).fetchone()
    finally:
        conn.close()
    assert row is None


def test_chain_verify_rejects_log_with_mixed_algorithms(tmp_path, capsys):
    """A log containing records signed with different algorithms is rejected."""
    log_path = _populate_log(tmp_path, n_records=2)

    # Hand-craft a third line whose signature.algorithm differs.
    rogue = {
        "checkpoint_index": 2,
        "tree_size": 99,
        "tree_root": "sha256:" + "c" * 64,
        "issued_at": "2026-05-22T00:00:00.000Z",
        "previous_checkpoint_hash": "sha256:" + "0" * 64,
        "signature": {"algorithm": "ed25519", "value": "0" * 128},
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rogue) + "\n")

    rc = main(["chain", "verify", "--log", log_path])
    assert rc == 2
    err = capsys.readouterr().err
    assert "mixes signature algorithms" in err


def test_chain_verify_rejects_malformed_jsonl(tmp_path, capsys):
    """A line that isn't valid JSON produces a clear file+line error."""
    log_path = _populate_log(tmp_path, n_records=1)
    # Corrupt the first line.
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    lines.insert(0, "{not valid json\n")
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    rc = main(["chain", "verify", "--log", log_path])
    assert rc == 2
    err = capsys.readouterr().err
    assert "malformed JSON" in err
    assert "line 1" in err
