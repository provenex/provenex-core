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
    assert d["schema_version"] == "1.1.0"
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


# --------------------------------------------------------------------------- #
# Schema 1.1.0: transparency log fields                                       #
# --------------------------------------------------------------------------- #


def test_receipt_omits_transparency_log_when_absent():
    """v1.1.0 receipts without log info must not emit the transparency_log
    field — old (v1.0-style) receipts remain a valid subset of v1.1.0."""
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="x")
    d = receipt.to_dict()
    assert "transparency_log" not in d
    assert "leaf_index" not in d["sources"][0]
    assert "inclusion_proof" not in d["sources"][0]


def test_receipt_includes_transparency_log_when_present():
    """When a transparency log is in use, both top-level head and per-source
    proofs appear in the JSON."""
    builder = ReceiptBuilder()
    builder.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=make_entry(),
        leaf_index=7,
        inclusion_proof=["sha256:" + "c" * 64, "sha256:" + "d" * 64],
    )
    receipt = builder.finalize(
        output_text="hello",
        transparency_log={
            "tree_size": 12,
            "tree_root": "sha256:" + "e" * 64,
        },
    )
    d = receipt.to_dict()
    assert d["transparency_log"]["tree_size"] == 12
    assert d["transparency_log"]["tree_root"] == "sha256:" + "e" * 64
    src = d["sources"][0]
    assert src["leaf_index"] == 7
    assert src["inclusion_proof"] == [
        "sha256:" + "c" * 64,
        "sha256:" + "d" * 64,
    ]


def test_transparency_log_is_covered_by_signature():
    """Tampering with the transparency_log block must invalidate the receipt
    signature — the log head is part of what's attested."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        leaf_index=0,
        inclusion_proof=[],
    )
    receipt = builder.finalize(
        output_text="hello",
        signer=signer,
        transparency_log={
            "tree_size": 1,
            "tree_root": "sha256:" + "a" * 64,
        },
    )
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, signer) is True
    # Tamper with the log root
    parsed["transparency_log"]["tree_root"] = "sha256:" + "0" * 64
    assert verify_receipt_signature(parsed, signer) is False


def test_end_to_end_receipt_with_merkle_index():
    """Integration: a receipt produced from MerkleSQLiteProvenanceIndex
    carries proofs that verify offline against the receipt's tree_root."""
    from provenex.core.merkle import verify_inclusion_proof
    from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex

    idx = MerkleSQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    fps = []
    for i in range(5):
        fp = "sha256:" + f"{i:064x}"
        idx.add(
            fingerprint=fp,
            document_id=f"doc{i}",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
        fps.append(fp)

    builder = ReceiptBuilder()
    for fp in fps:
        entry = idx.lookup(fp)
        leaf_bytes, leaf_index, proof = idx.inclusion_proof(fp)
        builder.add_source(
            fingerprint=fp,
            outcome=idx.verify(fp),
            entry=entry,
            leaf_index=leaf_index,
            inclusion_proof=proof,
        )

    receipt = builder.finalize(
        output_text="the model said this",
        transparency_log={
            "tree_size": idx.tree_size(),
            "tree_root": idx.tree_root(),
        },
    )
    d = receipt.to_dict()
    tree_size = d["transparency_log"]["tree_size"]
    tree_root = bytes.fromhex(
        d["transparency_log"]["tree_root"].removeprefix("sha256:")
    )

    for i, src in enumerate(d["sources"]):
        leaf, _idx_again, _proof_hex = idx.inclusion_proof(src["fingerprint"])
        proof = [
            bytes.fromhex(h.removeprefix("sha256:")) for h in src["inclusion_proof"]
        ]
        assert verify_inclusion_proof(
            leaf, src["leaf_index"], tree_size, proof, tree_root
        ), f"offline verification failed for chunk {i}"
    idx.close()
