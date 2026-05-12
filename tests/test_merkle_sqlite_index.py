"""Tests for the Merkle-augmented SQLite provenance index.

This index keeps every property of :class:`SQLiteProvenanceIndex` (HMAC row
signatures, the five verification outcomes) and adds an RFC 6962
transparency log over the same rows. The leaf for each row is the same
canonical payload that the HMAC signs, so an inclusion proof shows that an
authentic row was committed to the log at a known position.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from provenex.core.merkle import verify_inclusion_proof
from provenex.index.base import VerificationOutcome
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex


SECRET = b"test-secret-do-not-use-in-production"


def make_index() -> MerkleSQLiteProvenanceIndex:
    return MerkleSQLiteProvenanceIndex(":memory:", signing_secret=SECRET)


# --------------------------------------------------------------------------- #
# Behaves like SQLiteProvenanceIndex                                          #
# --------------------------------------------------------------------------- #


def test_inherits_verification_outcomes():
    """All five outcomes still work — the Merkle layer is additive."""
    idx = make_index()
    fp_v1 = "sha256:" + "a" * 64
    fp_v2 = "sha256:" + "e" * 64

    # UNVERIFIED
    assert idx.verify("sha256:" + "0" * 64) == VerificationOutcome.UNVERIFIED

    # VERIFIED
    idx.add(
        fingerprint=fp_v1,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert idx.verify(fp_v1) == VerificationOutcome.VERIFIED

    # UNAUTHORIZED
    idx.set_authorization("doc1", False)
    assert idx.verify(fp_v1) == VerificationOutcome.UNAUTHORIZED
    idx.set_authorization("doc1", True)

    # STALE via re-ingestion
    idx.add(
        fingerprint=fp_v2,
        document_id="doc1",
        document_version="sha256:" + "f" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert idx.verify(fp_v1) == VerificationOutcome.STALE
    assert idx.verify(fp_v2) == VerificationOutcome.VERIFIED

    # TAMPERED
    idx._conn.execute(  # type: ignore[attr-defined]
        "UPDATE fingerprints SET chunk_offset = 9999 WHERE fingerprint = ?",
        (fp_v2,),
    )
    idx._conn.commit()  # type: ignore[attr-defined]
    assert idx.verify(fp_v2) == VerificationOutcome.TAMPERED
    idx.close()


# --------------------------------------------------------------------------- #
# Transparency log behavior                                                   #
# --------------------------------------------------------------------------- #


def test_empty_tree_state():
    idx = make_index()
    assert idx.tree_size() == 0
    # Empty-tree root is well-defined (SHA256 of empty string)
    import hashlib

    assert idx.tree_root() == "sha256:" + hashlib.sha256(b"").hexdigest()
    idx.close()


def test_add_appends_to_tree():
    idx = make_index()
    fp = "sha256:" + "a" * 64
    idx.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert idx.tree_size() == 1
    idx.close()


def test_tree_grows_with_each_add():
    idx = make_index()
    for i in range(5):
        idx.add(
            fingerprint="sha256:" + f"{i:064x}",
            document_id=f"doc{i}",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
    assert idx.tree_size() == 5
    idx.close()


def test_tree_root_changes_on_add():
    idx = make_index()
    r0 = idx.tree_root()
    idx.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    r1 = idx.tree_root()
    assert r0 != r1
    idx.close()


def test_inclusion_proof_verifies_against_root():
    """The headline property: every appended row gets a verifiable proof."""
    idx = make_index()
    fps = []
    for i in range(10):
        fp = "sha256:" + f"{i:064x}"
        idx.add(
            fingerprint=fp,
            document_id=f"doc{i}",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
        fps.append(fp)

    root_hex = idx.tree_root()
    assert root_hex.startswith("sha256:")
    root = bytes.fromhex(root_hex.removeprefix("sha256:"))
    size = idx.tree_size()

    for fp in fps:
        leaf, leaf_index, proof_hex = idx.inclusion_proof(fp)
        proof = [bytes.fromhex(h.removeprefix("sha256:")) for h in proof_hex]
        assert verify_inclusion_proof(leaf, leaf_index, size, proof, root), (
            f"proof failed to verify for {fp}"
        )
    idx.close()


def test_inclusion_proof_for_missing_fingerprint_raises():
    idx = make_index()
    with pytest.raises(KeyError):
        idx.inclusion_proof("sha256:" + "0" * 64)
    idx.close()


def test_leaf_bytes_match_hmac_canonical_payload():
    """The Merkle leaf must be the same canonical bytes that the HMAC signs.

    This is the security tie: a verified inclusion proof shows that the
    exact bytes the index HMAC'd were committed to the log at that index.
    """
    idx = make_index()
    fp = "sha256:" + "a" * 64
    idx.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=42,
        chunk_length=100,
    )
    leaf, _idx, _proof = idx.inclusion_proof(fp)
    entry = idx.lookup(fp)
    assert entry is not None
    # Re-derive the canonical payload the way SQLiteProvenanceIndex does it.
    from provenex.index.sqlite_index import _canonical_payload

    expected = _canonical_payload(
        fingerprint=entry.fingerprint,
        document_id=entry.document_id,
        document_version=entry.document_version,
        ingested_at=entry.ingested_at,
        chunk_offset=entry.chunk_offset,
        chunk_length=entry.chunk_length,
    )
    assert leaf == expected
    idx.close()


def test_persistence_across_reopen():
    """The tree must survive a close/reopen — leaves are persisted."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        idx = MerkleSQLiteProvenanceIndex(path, signing_secret=SECRET)
        for i in range(5):
            idx.add(
                fingerprint="sha256:" + f"{i:064x}",
                document_id=f"doc{i}",
                document_version="sha256:" + "b" * 64,
                chunk_offset=0,
                chunk_length=100,
            )
        root_before = idx.tree_root()
        size_before = idx.tree_size()
        idx.close()

        idx2 = MerkleSQLiteProvenanceIndex(path, signing_secret=SECRET)
        assert idx2.tree_size() == size_before
        assert idx2.tree_root() == root_before
        # And proofs still work after reopen.
        for i in range(5):
            fp = "sha256:" + f"{i:064x}"
            leaf, leaf_index, proof_hex = idx2.inclusion_proof(fp)
            root = bytes.fromhex(idx2.tree_root().removeprefix("sha256:"))
            proof = [bytes.fromhex(h.removeprefix("sha256:")) for h in proof_hex]
            assert verify_inclusion_proof(
                leaf, leaf_index, idx2.tree_size(), proof, root
            )
        idx2.close()
    finally:
        os.unlink(path)


def test_context_manager():
    with MerkleSQLiteProvenanceIndex(":memory:", signing_secret=SECRET) as idx:
        idx.add(
            fingerprint="sha256:" + "a" * 64,
            document_id="d",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=1,
        )
        assert idx.tree_size() == 1
