"""Tests for receipt building, JSON serialization, and signature verification."""

from __future__ import annotations

import json

from provenex.core.receipt import (
    HmacSha256Signer,
    ReceiptBuilder,
    verify_receipt_signature,
)
from provenex.index.base import IndexEntry, VerificationOutcome
from provenex.policy.policy import VerificationPolicy


SECRET = b"test-receipt-secret"


def make_entry() -> IndexEntry:
    return IndexEntry(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc_policy_v4",
        document_version="sha256:" + "b" * 64,
        ingested_at="2026-04-01T09:00:00.000Z",
        chunk_offset=1024,
        chunk_length=256,
        authorized=True,
        superseded=False,
        signature="deadbeef",
    )


def test_receipt_basic_schema():
    builder = ReceiptBuilder()
    builder.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=make_entry(),
        normalization_applied=["unicode_nfc", "whitespace_collapse"],
    )
    receipt = builder.finalize(output_text="The answer is 42.")
    d = receipt.to_dict()
    # Required top-level fields per the schema.
    assert "receipt_id" in d
    assert d["schema_version"] == "1.0.0"
    assert d["issuer"].startswith("provenex-core/")
    assert "issued_at" in d
    assert d["output"]["hash"].startswith("sha256:")
    assert d["output"]["hash_algorithm"] == "sha256"
    assert isinstance(d["sources"], list)
    assert d["sources"][0]["verification_outcome"] == "VERIFIED"
    assert d["sources"][0]["normalization_applied"] == [
        "unicode_nfc",
        "whitespace_collapse",
    ]
    assert "summary" in d
    assert "policy" in d
    # Unsigned receipt should not have a signature block.
    assert "signature" not in d


def test_receipt_id_unique():
    a = ReceiptBuilder().finalize(output_text="a")
    b = ReceiptBuilder().finalize(output_text="a")
    assert a.receipt_id != b.receipt_id


def test_receipt_summary_counts():
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    builder.add_source("sha256:" + "2" * 64, VerificationOutcome.VERIFIED)
    builder.add_source("sha256:" + "3" * 64, VerificationOutcome.STALE)
    builder.add_source("sha256:" + "4" * 64, VerificationOutcome.UNVERIFIED)
    receipt = builder.finalize(output_text="")
    s = receipt.summary
    assert s["total_chunks"] == 4
    assert s["verified"] == 2
    assert s["stale"] == 1
    assert s["unverified"] == 1
    assert s["unauthorized"] == 0
    assert s["tampered"] == 0


def test_receipt_overall_status_pass():
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="x")
    assert receipt.summary["overall_status"] == "PASS"


def test_receipt_overall_status_partial():
    builder = ReceiptBuilder(policy=VerificationPolicy(block_stale=False))
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    builder.add_source("sha256:" + "2" * 64, VerificationOutcome.STALE)
    receipt = builder.finalize(output_text="x")
    assert receipt.summary["overall_status"] == "PARTIAL"


def test_receipt_overall_status_fail():
    builder = ReceiptBuilder(policy=VerificationPolicy(block_unauthorized=True))
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.UNAUTHORIZED)
    receipt = builder.finalize(output_text="x")
    assert receipt.summary["overall_status"] == "FAIL"


def test_signature_roundtrip():
    """Signing and verifying with the same secret should succeed."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=make_entry(),
    )
    receipt = builder.finalize(output_text="hello", signer=signer)
    json_text = receipt.to_json()
    parsed = json.loads(json_text)
    assert parsed["signature"]["algorithm"] == "hmac-sha256"
    # Re-verify with the same key.
    assert verify_receipt_signature(parsed, signer) is True


def test_signature_fails_with_wrong_secret():
    signer = HmacSha256Signer(secret=SECRET)
    wrong = HmacSha256Signer(secret=b"wrong-secret")
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "a" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="hi", signer=signer)
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, wrong) is False


def test_signature_fails_after_tampering():
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "a" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="hi", signer=signer)
    parsed = json.loads(receipt.to_json())
    # Tamper with the output hash.
    parsed["output"]["hash"] = "sha256:" + "0" * 64
    assert verify_receipt_signature(parsed, signer) is False


def test_output_hash_uses_sha256_of_text():
    import hashlib

    expected = "sha256:" + hashlib.sha256(b"some output").hexdigest()
    receipt = ReceiptBuilder().finalize(output_text="some output")
    assert receipt.output_hash == expected


def test_unverified_source_has_null_document_metadata():
    builder = ReceiptBuilder()
    builder.add_source(
        fingerprint="sha256:" + "1" * 64,
        outcome=VerificationOutcome.UNVERIFIED,
        entry=None,
    )
    receipt = builder.finalize(output_text="")
    src = receipt.to_dict()["sources"][0]
    assert src["document_id"] is None
    assert src["document_version"] is None
    assert src["authorized"] is None
