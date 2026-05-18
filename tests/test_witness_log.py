"""Tests for the OSS witness/checkpoint log (v0.8.0)."""

from __future__ import annotations

import json

import pytest

from provenex import HmacSha256Signer, WitnessLog


SECRET = b"witness-test-secret-32-bytes-min!"


def test_append_writes_chained_signed_records(tmp_path):
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)

    r0 = log.append(tree_size=10, tree_root="sha256:" + "0" * 64)
    r1 = log.append(tree_size=25, tree_root="sha256:" + "1" * 64)
    r2 = log.append(tree_size=42, tree_root="sha256:" + "2" * 64)

    assert r0.checkpoint_index == 0
    assert r0.previous_checkpoint_hash is None
    assert r1.checkpoint_index == 1
    assert r1.previous_checkpoint_hash == r0.record_hash()
    assert r2.checkpoint_index == 2
    assert r2.previous_checkpoint_hash == r1.record_hash()
    assert log.verify()


def test_verify_detects_signature_tampering(tmp_path):
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    log.append(tree_size=10, tree_root="sha256:" + "0" * 64)
    log.append(tree_size=25, tree_root="sha256:" + "1" * 64)

    # Tamper with a recorded tree_root in place.
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    record = json.loads(lines[0])
    record["tree_root"] = "sha256:" + "f" * 64
    lines[0] = json.dumps(record) + "\n"
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    fresh = WitnessLog(log_path, signer=signer)
    assert not fresh.verify()


def test_verify_detects_chain_break_after_retroactive_edit(tmp_path):
    """Edit an old record AND re-sign it -> next record's chain fails.

    An operator who can re-sign records can rewrite individual rows,
    but the chain link from the NEXT record commits to the previous
    record's hash. Re-signing the edited record changes its hash, so
    the next record's previous_checkpoint_hash no longer matches.
    """
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    log.append(tree_size=10, tree_root="sha256:" + "a" * 64)
    log.append(tree_size=25, tree_root="sha256:" + "b" * 64)
    log.append(tree_size=42, tree_root="sha256:" + "c" * 64)

    # Re-sign record 0 with a different tree_root.
    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    record0 = json.loads(lines[0])
    record0["tree_root"] = "sha256:" + "d" * 64
    payload = json.dumps(
        {k: v for k, v in record0.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    record0["signature"]["value"] = signer.sign(payload)
    lines[0] = json.dumps(record0) + "\n"
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    # Record 0 now self-verifies with the new tree_root, but record
    # 1's previous_checkpoint_hash was computed over the OLD record 0
    # and no longer matches. The chain catches the rewrite.
    fresh = WitnessLog(log_path, signer=signer)
    assert not fresh.verify()


def test_verify_detects_index_gap(tmp_path):
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    log.append(tree_size=10, tree_root="sha256:" + "a" * 64)
    log.append(tree_size=25, tree_root="sha256:" + "b" * 64)
    log.append(tree_size=42, tree_root="sha256:" + "c" * 64)

    with open(log_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    # Drop the middle record: chain still claims 0, 2 with an index
    # discontinuity (and a previous_hash mismatch).
    truncated = [lines[0], lines[2]]
    with open(log_path, "w", encoding="utf-8") as f:
        f.writelines(truncated)

    fresh = WitnessLog(log_path, signer=signer)
    assert not fresh.verify()


def test_latest_returns_most_recent_record(tmp_path):
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    assert log.latest() is None
    log.append(tree_size=10, tree_root="sha256:" + "0" * 64)
    log.append(tree_size=25, tree_root="sha256:" + "1" * 64)
    latest = log.latest()
    assert latest is not None
    assert latest.tree_size == 25


def test_empty_log_verifies_trivially(tmp_path):
    log_path = str(tmp_path / "witness.jsonl")
    signer = HmacSha256Signer(secret=SECRET)
    log = WitnessLog(log_path, signer=signer)
    assert log.verify()
