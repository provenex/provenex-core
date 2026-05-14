"""Tests for the Merkle-augmented Postgres provenance index.

Mirrors tests/test_merkle_sqlite_index.py against Postgres. SKIPPED unless
``PROVENEX_TEST_POSTGRES_DSN`` is set.
"""

from __future__ import annotations

import os
import uuid

import pytest

from provenex.core.merkle import verify_inclusion_proof
from provenex.index.base import VerificationOutcome

DSN = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    not DSN,
    reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping Postgres Merkle tests",
)

SECRET = b"test-secret-do-not-use-in-production"


def _schema_dsn() -> tuple[str, str]:
    """Allocate a fresh schema and return (test_dsn, schema_name)."""
    import psycopg

    schema = f"provenex_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in DSN else "?"
    return f"{DSN}{sep}options=-csearch_path%3D{schema}", schema


def _drop_schema(schema: str) -> None:
    import psycopg

    with psycopg.connect(DSN, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


@pytest.fixture
def index():
    from provenex.index.merkle_postgres_index import MerklePostgresProvenanceIndex

    test_dsn, schema = _schema_dsn()
    idx = MerklePostgresProvenanceIndex(dsn=test_dsn, signing_secret=SECRET)
    try:
        yield idx
    finally:
        idx.close()
        _drop_schema(schema)


def test_inherits_verification_outcomes(index):
    """All five outcomes still work — the Merkle layer is additive."""
    fp_v1 = "sha256:" + "a" * 64
    fp_v2 = "sha256:" + "e" * 64

    assert index.verify("sha256:" + "0" * 64) == VerificationOutcome.UNVERIFIED

    index.add(
        fingerprint=fp_v1,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert index.verify(fp_v1) == VerificationOutcome.VERIFIED

    index.set_authorization("doc1", False)
    assert index.verify(fp_v1) == VerificationOutcome.UNAUTHORIZED
    index.set_authorization("doc1", True)

    index.add(
        fingerprint=fp_v2,
        document_id="doc1",
        document_version="sha256:" + "f" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert index.verify(fp_v1) == VerificationOutcome.STALE
    assert index.verify(fp_v2) == VerificationOutcome.VERIFIED

    with index._pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE provenex_fingerprints SET chunk_offset = 9999 "
                "WHERE fingerprint = %s",
                (fp_v2,),
            )
        conn.commit()
    assert index.verify(fp_v2) == VerificationOutcome.TAMPERED


def test_empty_tree_state(index):
    import hashlib

    assert index.tree_size() == 0
    assert index.tree_root() == "sha256:" + hashlib.sha256(b"").hexdigest()


def test_add_appends_to_tree(index):
    index.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert index.tree_size() == 1


def test_tree_grows_with_each_add(index):
    for i in range(5):
        index.add(
            fingerprint="sha256:" + f"{i:064x}",
            document_id=f"doc{i}",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
    assert index.tree_size() == 5


def test_tree_root_changes_on_add(index):
    r0 = index.tree_root()
    index.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    r1 = index.tree_root()
    assert r0 != r1


def test_inclusion_proof_verifies_against_root(index):
    fps = []
    for i in range(10):
        fp = "sha256:" + f"{i:064x}"
        index.add(
            fingerprint=fp,
            document_id=f"doc{i}",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
        fps.append(fp)

    root_hex = index.tree_root()
    root = bytes.fromhex(root_hex.removeprefix("sha256:"))
    size = index.tree_size()

    for fp in fps:
        leaf, leaf_index, proof_hex = index.inclusion_proof(fp)
        proof = [bytes.fromhex(h.removeprefix("sha256:")) for h in proof_hex]
        assert verify_inclusion_proof(leaf, leaf_index, size, proof, root), (
            f"proof failed to verify for {fp}"
        )


def test_inclusion_proof_for_missing_fingerprint_raises(index):
    with pytest.raises(KeyError):
        index.inclusion_proof("sha256:" + "0" * 64)


def test_leaf_bytes_match_hmac_canonical_payload(index):
    """Merkle leaf bytes are the same canonical bytes the HMAC signs."""
    from provenex.index.sqlite_index import _canonical_payload

    fp = "sha256:" + "a" * 64
    index.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=42,
        chunk_length=100,
    )
    leaf, _, _ = index.inclusion_proof(fp)
    entry = index.lookup(fp)
    expected = _canonical_payload(
        fingerprint=entry.fingerprint,
        document_id=entry.document_id,
        document_version=entry.document_version,
        ingested_at=entry.ingested_at,
        chunk_offset=entry.chunk_offset,
        chunk_length=entry.chunk_length,
    )
    assert leaf == expected


def test_persistence_across_reopen():
    """Tree must survive a close/reopen — leaves are persisted in Postgres."""
    from provenex.index.merkle_postgres_index import MerklePostgresProvenanceIndex

    test_dsn, schema = _schema_dsn()
    try:
        idx = MerklePostgresProvenanceIndex(dsn=test_dsn, signing_secret=SECRET)
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

        idx2 = MerklePostgresProvenanceIndex(dsn=test_dsn, signing_secret=SECRET)
        try:
            assert idx2.tree_size() == size_before
            assert idx2.tree_root() == root_before
            for i in range(5):
                fp = "sha256:" + f"{i:064x}"
                leaf, leaf_index, proof_hex = idx2.inclusion_proof(fp)
                root = bytes.fromhex(idx2.tree_root().removeprefix("sha256:"))
                proof = [bytes.fromhex(h.removeprefix("sha256:")) for h in proof_hex]
                assert verify_inclusion_proof(
                    leaf, leaf_index, idx2.tree_size(), proof, root
                )
        finally:
            idx2.close()
    finally:
        _drop_schema(schema)
