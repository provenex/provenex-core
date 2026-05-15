"""Tests for the SQLite provenance index, including all five verification outcomes."""

from __future__ import annotations

import pytest

from provenex.index.base import VerificationOutcome
from provenex.index.sqlite_index import SQLiteProvenanceIndex


SECRET = b"test-secret-do-not-use-in-production"


def make_index() -> SQLiteProvenanceIndex:
    return SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)


def test_refuses_without_secret(monkeypatch):
    monkeypatch.delenv("PROVENEX_SIGNING_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        SQLiteProvenanceIndex(":memory:")


def test_accepts_secret_from_env(monkeypatch):
    monkeypatch.setenv("PROVENEX_SIGNING_SECRET", "from-env")
    idx = SQLiteProvenanceIndex(":memory:")
    assert idx is not None
    idx.close()


def test_add_and_lookup():
    idx = make_index()
    idx.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    entry = idx.lookup("sha256:" + "a" * 64)
    assert entry is not None
    assert entry.document_id == "doc1"
    assert entry.authorized is True
    assert entry.superseded is False
    idx.close()


def test_lookup_returns_none_for_missing():
    idx = make_index()
    assert idx.lookup("sha256:" + "c" * 64) is None
    idx.close()


def test_outcome_unverified():
    idx = make_index()
    assert idx.verify("sha256:" + "d" * 64) == VerificationOutcome.UNVERIFIED
    idx.close()


def test_outcome_verified():
    idx = make_index()
    fp = "sha256:" + "a" * 64
    idx.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert idx.verify(fp) == VerificationOutcome.VERIFIED
    idx.close()


def test_outcome_unauthorized():
    idx = make_index()
    fp = "sha256:" + "a" * 64
    idx.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    idx.set_authorization("doc1", False)
    assert idx.verify(fp) == VerificationOutcome.UNAUTHORIZED
    idx.close()


def test_outcome_stale_via_reingestion():
    idx = make_index()
    fp_v1 = "sha256:" + "a" * 64
    idx.add(
        fingerprint=fp_v1,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    # Re-ingest with a new version. The v1 fingerprint should now be STALE.
    fp_v2 = "sha256:" + "e" * 64
    idx.add(
        fingerprint=fp_v2,
        document_id="doc1",
        document_version="sha256:" + "f" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert idx.verify(fp_v1) == VerificationOutcome.STALE
    assert idx.verify(fp_v2) == VerificationOutcome.VERIFIED
    idx.close()


def test_outcome_tampered():
    """Directly mutate the SQLite row to simulate index tampering."""
    idx = make_index()
    fp = "sha256:" + "a" * 64
    idx.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    # Tamper with the offset field — the signature should no longer validate.
    idx._conn.execute(  # type: ignore[attr-defined]
        "UPDATE fingerprints SET chunk_offset = 9999 WHERE fingerprint = ?",
        (fp,),
    )
    idx._conn.commit()  # type: ignore[attr-defined]
    assert idx.verify(fp) == VerificationOutcome.TAMPERED
    idx.close()


def test_explicit_supersede():
    idx = make_index()
    fp_v1 = "sha256:" + "a" * 64
    idx.add(
        fingerprint=fp_v1,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    count = idx.supersede("doc1", "sha256:" + "f" * 64)
    assert count == 1
    assert idx.verify(fp_v1) == VerificationOutcome.STALE
    idx.close()


def test_rejects_malformed_fingerprint():
    idx = make_index()
    with pytest.raises(ValueError):
        idx.add(
            fingerprint="not-a-fingerprint",
            document_id="doc1",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
    idx.close()


def test_rejects_malformed_document_version():
    idx = make_index()
    with pytest.raises(ValueError):
        idx.add(
            fingerprint="sha256:" + "a" * 64,
            document_id="doc1",
            document_version="bad-version",
            chunk_offset=0,
            chunk_length=100,
        )
    idx.close()


@pytest.mark.parametrize(
    "doc_id",
    [
        "doc\nwith-newline",
        "doc\rwith-cr",
        "doc\x00with-null",
        "real-doc\nsha256:" + "f" * 64 + "\nsha256:" + "0" * 64 + "\n2026-01-01T00:00:00Z\n0\n0",
    ],
)
def test_rejects_signing_payload_ambiguity_in_document_id(doc_id):
    idx = make_index()
    with pytest.raises(ValueError, match="newline|carriage|null"):
        idx.add(
            fingerprint="sha256:" + "a" * 64,
            document_id=doc_id,
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
    idx.close()


def test_context_manager():
    with SQLiteProvenanceIndex(":memory:", signing_secret=SECRET) as idx:
        idx.add(
            fingerprint="sha256:" + "a" * 64,
            document_id="d",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=1,
        )
        assert idx.verify("sha256:" + "a" * 64) == VerificationOutcome.VERIFIED
