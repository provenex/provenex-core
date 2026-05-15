"""Tests for the Postgres provenance index, including all five verification outcomes.

These tests mirror tests/test_sqlite_index.py and run against a real
Postgres instance. They are SKIPPED unless ``PROVENEX_TEST_POSTGRES_DSN``
is set in the environment.

Example::

    docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=test postgres:16
    export PROVENEX_TEST_POSTGRES_DSN=postgresql://postgres:test@localhost:5432/postgres
    pytest tests/test_postgres_index.py

Each test runs in an isolated schema so they can be parallelised in CI.
"""

from __future__ import annotations

import os
import uuid

import pytest

from provenex.index.base import VerificationOutcome

DSN = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")

pytestmark = pytest.mark.skipif(
    not DSN,
    reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping Postgres index tests",
)

SECRET = b"test-secret-do-not-use-in-production"


@pytest.fixture
def index():
    """Yield a PostgresProvenanceIndex pinned to a fresh per-test schema.

    Each test gets its own schema so concurrent test runs don't collide
    on the global ``provenex_*`` table names. The schema is dropped on
    teardown.
    """
    import psycopg

    from provenex.index.postgres_index import PostgresProvenanceIndex

    schema = f"provenex_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DSN, autocommit=True) as setup_conn:
        with setup_conn.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')

    # Append the per-test schema to search_path via DSN options
    sep = "&" if "?" in DSN else "?"
    test_dsn = f"{DSN}{sep}options=-csearch_path%3D{schema}"

    idx = PostgresProvenanceIndex(dsn=test_dsn, signing_secret=SECRET)
    try:
        yield idx
    finally:
        idx.close()
        with psycopg.connect(DSN, autocommit=True) as teardown_conn:
            with teardown_conn.cursor() as cur:
                cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


def test_refuses_without_secret(monkeypatch):
    from provenex.index.postgres_index import PostgresProvenanceIndex

    monkeypatch.delenv("PROVENEX_SIGNING_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        PostgresProvenanceIndex(dsn=DSN)


def test_rejects_both_dsn_and_pool(monkeypatch):
    from provenex.index.postgres_index import PostgresProvenanceIndex

    monkeypatch.setenv("PROVENEX_SIGNING_SECRET", "test")
    with pytest.raises(ValueError):
        PostgresProvenanceIndex(dsn=DSN, pool="not-a-pool")


def test_add_and_lookup(index):
    index.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    entry = index.lookup("sha256:" + "a" * 64)
    assert entry is not None
    assert entry.document_id == "doc1"
    assert entry.authorized is True
    assert entry.superseded is False


def test_lookup_returns_none_for_missing(index):
    assert index.lookup("sha256:" + "c" * 64) is None


def test_outcome_unverified(index):
    assert index.verify("sha256:" + "d" * 64) == VerificationOutcome.UNVERIFIED


def test_outcome_verified(index):
    fp = "sha256:" + "a" * 64
    index.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert index.verify(fp) == VerificationOutcome.VERIFIED


def test_outcome_unauthorized(index):
    fp = "sha256:" + "a" * 64
    index.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    index.set_authorization("doc1", False)
    assert index.verify(fp) == VerificationOutcome.UNAUTHORIZED


def test_outcome_stale_via_reingestion(index):
    fp_v1 = "sha256:" + "a" * 64
    index.add(
        fingerprint=fp_v1,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    fp_v2 = "sha256:" + "e" * 64
    index.add(
        fingerprint=fp_v2,
        document_id="doc1",
        document_version="sha256:" + "f" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    assert index.verify(fp_v1) == VerificationOutcome.STALE
    assert index.verify(fp_v2) == VerificationOutcome.VERIFIED


def test_outcome_tampered(index):
    """Directly mutate the row to simulate index tampering."""
    fp = "sha256:" + "a" * 64
    index.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    with index._pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE provenex_fingerprints SET chunk_offset = 9999 "
                "WHERE fingerprint = %s",
                (fp,),
            )
        conn.commit()
    assert index.verify(fp) == VerificationOutcome.TAMPERED


def test_explicit_supersede(index):
    fp_v1 = "sha256:" + "a" * 64
    index.add(
        fingerprint=fp_v1,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    count = index.supersede("doc1", "sha256:" + "f" * 64)
    assert count == 1
    assert index.verify(fp_v1) == VerificationOutcome.STALE


def test_rejects_malformed_fingerprint(index):
    with pytest.raises(ValueError):
        index.add(
            fingerprint="not-a-fingerprint",
            document_id="doc1",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
        )


def test_rejects_malformed_document_version(index):
    with pytest.raises(ValueError):
        index.add(
            fingerprint="sha256:" + "a" * 64,
            document_id="doc1",
            document_version="bad-version",
            chunk_offset=0,
            chunk_length=100,
        )


def test_context_manager():
    """A fresh schema, used via `with`, drops cleanly."""
    import psycopg

    from provenex.index.postgres_index import PostgresProvenanceIndex

    schema = f"provenex_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DSN, autocommit=True) as setup_conn:
        with setup_conn.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in DSN else "?"
    test_dsn = f"{DSN}{sep}options=-csearch_path%3D{schema}"

    try:
        with PostgresProvenanceIndex(dsn=test_dsn, signing_secret=SECRET) as idx:
            idx.add(
                fingerprint="sha256:" + "a" * 64,
                document_id="d",
                document_version="sha256:" + "b" * 64,
                chunk_offset=0,
                chunk_length=1,
            )
            assert idx.verify("sha256:" + "a" * 64) == VerificationOutcome.VERIFIED
    finally:
        with psycopg.connect(DSN, autocommit=True) as teardown_conn:
            with teardown_conn.cursor() as cur:
                cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


def test_concurrent_add_serialises_on_document_id(index):
    """Two threads adding the same document_id concurrently must not race.

    Before the pg_advisory_xact_lock guard, the SELECT FOR UPDATE returned
    NULL for new documents (no row to lock) and two concurrent inserts
    could disagree on the authorization bit. With the advisory lock,
    one of them wins cleanly and the other observes the winner's state.
    """
    import threading

    fp_a = "sha256:" + "a" * 64
    fp_b = "sha256:" + "b" * 64
    doc_id = "race-doc"
    doc_version = "sha256:" + "0" * 64

    errors: list[BaseException] = []

    def add(fingerprint: str, authorized: bool) -> None:
        try:
            index.add(
                fingerprint=fingerprint,
                document_id=doc_id,
                document_version=doc_version,
                chunk_offset=0,
                chunk_length=10,
                authorized=authorized,
            )
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=add, args=(fp_a, True))
    t2 = threading.Thread(target=add, args=(fp_b, False))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"concurrent add() raised: {errors!r}"

    # Both fingerprints land under the same document_id. The authorization
    # bit is whichever writer committed last — the important property is
    # that the document row is consistent (one current_version, one
    # authorized flag) rather than partially-applied.
    entry_a = index.lookup(fp_a)
    entry_b = index.lookup(fp_b)
    assert entry_a is not None and entry_b is not None
    assert entry_a.document_id == doc_id == entry_b.document_id
    assert entry_a.document_version == doc_version == entry_b.document_version
    # Both fingerprint rows observe the same authorization bit (the
    # winner's), not split state.
    assert entry_a.authorized == entry_b.authorized


def test_signature_portable_with_sqlite_backend(index):
    """A row written via Postgres must verify under the same HMAC payload SQLite uses.

    This is the property that makes receipts portable across backends:
    the canonical payload and the HMAC keying are identical.
    """
    from provenex.index.sqlite_index import _canonical_payload, _sign

    fp = "sha256:" + "a" * 64
    index.add(
        fingerprint=fp,
        document_id="doc1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    entry = index.lookup(fp)
    expected = _sign(
        _canonical_payload(
            fingerprint=entry.fingerprint,
            document_id=entry.document_id,
            document_version=entry.document_version,
            ingested_at=entry.ingested_at,
            chunk_offset=entry.chunk_offset,
            chunk_length=entry.chunk_length,
        ),
        SECRET,
    )
    assert entry.signature == expected
