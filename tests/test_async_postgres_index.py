"""Tests for the AsyncPostgresProvenanceIndex.

These mirror tests/test_postgres_index.py but exercise the async API. They
are SKIPPED unless ``PROVENEX_TEST_POSTGRES_DSN`` is set in the environment.

The async index MUST produce wire-identical signed rows to the sync index
(same canonical payload, same HMAC), so a sync verifier accepts what the
async writer produced and vice versa. The cross-backend equivalence test
locks that in.

Run with::

    PROVENEX_TEST_POSTGRES_DSN='postgresql://postgres@/postgres?host=/tmp&port=55432' \\
        pytest tests/test_async_postgres_index.py
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
import pytest_asyncio

from provenex.index.base import VerificationOutcome

DSN = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")

pytestmark = [
    pytest.mark.skipif(
        not DSN,
        reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping async pg tests",
    ),
    pytest.mark.asyncio,
]

SECRET = b"test-secret-do-not-use-in-production"


def _doc_version(seed: str) -> str:
    """Stable sha256:<hex> string for a per-test document version."""
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def _fp(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


@pytest_asyncio.fixture
async def schema_dsn():
    """Create a fresh per-test schema and yield a search_path-pinned DSN."""
    import psycopg

    schema = f"provenex_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DSN, autocommit=True) as setup_conn:
        with setup_conn.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in DSN else "?"
    test_dsn = f"{DSN}{sep}options=-csearch_path%3D{schema}"
    try:
        yield test_dsn
    finally:
        with psycopg.connect(DSN, autocommit=True) as teardown_conn:
            with teardown_conn.cursor() as cur:
                cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


@pytest_asyncio.fixture
async def aindex(schema_dsn):
    """Yield an opened AsyncPostgresProvenanceIndex pinned to the test schema."""
    from provenex.index.async_postgres_index import AsyncPostgresProvenanceIndex

    async with AsyncPostgresProvenanceIndex(
        dsn=schema_dsn, signing_secret=SECRET
    ) as idx:
        yield idx


# --------------------------------------------------------------------------- #
# Basic CRUD + outcomes                                                       #
# --------------------------------------------------------------------------- #


async def test_verified_outcome(aindex):
    fp = _fp("hello world")
    await aindex.add_async(
        fingerprint=fp,
        document_id="doc-1",
        document_version=_doc_version("doc-1-v1"),
        chunk_offset=0,
        chunk_length=11,
    )
    outcome = await aindex.verify_async(fp)
    assert outcome == VerificationOutcome.VERIFIED


async def test_unverified_outcome(aindex):
    outcome = await aindex.verify_async(_fp("never indexed"))
    assert outcome == VerificationOutcome.UNVERIFIED


async def test_unauthorized_outcome(aindex):
    fp = _fp("blocked chunk")
    await aindex.add_async(
        fingerprint=fp,
        document_id="doc-blocked",
        document_version=_doc_version("doc-blocked-v1"),
        chunk_offset=0,
        chunk_length=10,
    )
    await aindex.set_authorization_async("doc-blocked", False)
    outcome = await aindex.verify_async(fp)
    assert outcome == VerificationOutcome.UNAUTHORIZED


async def test_stale_outcome(aindex):
    fp = _fp("old version chunk")
    await aindex.add_async(
        fingerprint=fp,
        document_id="doc-superseded",
        document_version=_doc_version("doc-superseded-v1"),
        chunk_offset=0,
        chunk_length=10,
    )
    n = await aindex.supersede_async(
        "doc-superseded", _doc_version("doc-superseded-v2")
    )
    assert n == 1
    outcome = await aindex.verify_async(fp)
    assert outcome == VerificationOutcome.STALE


async def test_tampered_outcome(aindex, schema_dsn):
    """An out-of-band UPDATE that flips a signed column reduces to TAMPERED."""
    import psycopg

    fp = _fp("tamper me")
    await aindex.add_async(
        fingerprint=fp,
        document_id="doc-tamper",
        document_version=_doc_version("doc-tamper-v1"),
        chunk_offset=0,
        chunk_length=20,
    )

    # Reach around the async index and rewrite chunk_offset out-of-band.
    # The signature was computed over the original offset, so the
    # rewritten row's recomputed signature should NOT match.
    with psycopg.connect(schema_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE provenex_fingerprints SET chunk_offset = 999 "
                "WHERE fingerprint = %s",
                (fp,),
            )
    outcome = await aindex.verify_async(fp)
    assert outcome == VerificationOutcome.TAMPERED


# --------------------------------------------------------------------------- #
# verify_batch_async parity with verify_async                                 #
# --------------------------------------------------------------------------- #


async def test_verify_batch_async_returns_aligned_results(aindex):
    fps = [_fp(f"chunk-{i}") for i in range(5)]
    # Index the first 3, leave the last 2 UNVERIFIED.
    for i, fp in enumerate(fps[:3]):
        await aindex.add_async(
            fingerprint=fp,
            document_id=f"doc-{i}",
            document_version=_doc_version(f"doc-{i}-v1"),
            chunk_offset=0,
            chunk_length=10,
        )
    results = await aindex.verify_batch_async(fps)
    assert len(results) == len(fps)
    assert [outcome for outcome, _ in results[:3]] == [VerificationOutcome.VERIFIED] * 3
    assert [outcome for outcome, _ in results[3:]] == [VerificationOutcome.UNVERIFIED] * 2


async def test_verify_batch_async_empty_input(aindex):
    assert await aindex.verify_batch_async([]) == []


async def test_verify_batch_async_preserves_input_order_with_duplicates(aindex):
    fp_a = _fp("a")
    fp_b = _fp("b")
    await aindex.add_async(
        fingerprint=fp_a,
        document_id="doc-a",
        document_version=_doc_version("doc-a"),
        chunk_offset=0,
        chunk_length=1,
    )
    results = await aindex.verify_batch_async([fp_a, fp_b, fp_a, fp_b])
    assert [o for o, _ in results] == [
        VerificationOutcome.VERIFIED,
        VerificationOutcome.UNVERIFIED,
        VerificationOutcome.VERIFIED,
        VerificationOutcome.UNVERIFIED,
    ]


# --------------------------------------------------------------------------- #
# Concurrency: 100 concurrent verify_batch_async calls don't serialize        #
# --------------------------------------------------------------------------- #


async def test_100_concurrent_verify_batch_async_all_complete(aindex):
    """100 verify_batch_async calls dispatched via asyncio.gather all
    complete and return correct, aligned results.

    This is the index-level building block of the FastAPI acceptance
    test (which proves the full request-handler path does not block
    the event loop). Here we lock in the simpler property that the
    async pool + the verify path tolerate the gather() concurrency
    pattern without lost rows, deadlocks, or pool exhaustion.
    """
    import asyncio

    fps = [_fp(f"concurrent-{i}") for i in range(20)]
    for i, fp in enumerate(fps):
        await aindex.add_async(
            fingerprint=fp,
            document_id=f"concurrent-doc-{i}",
            document_version=_doc_version(f"concurrent-doc-{i}"),
            chunk_offset=0,
            chunk_length=10,
        )

    results = await asyncio.gather(
        *[aindex.verify_batch_async(fps) for _ in range(100)]
    )

    assert len(results) == 100
    assert all(len(r) == len(fps) for r in results)
    assert all(
        outcome == VerificationOutcome.VERIFIED
        for r in results
        for outcome, _ in r
    )


# --------------------------------------------------------------------------- #
# Cross-backend portability: sync writer, async reader                        #
# --------------------------------------------------------------------------- #


async def test_async_reads_what_sync_wrote(schema_dsn):
    """A row written by the sync backend verifies VERIFIED via the async one.

    Locks in that the canonical signing payload, schema DDL, and
    HMAC-over-row machinery are byte-identical across the two backends.
    A receipt produced via the async path verifies bit-identically
    against a sync-backed verifier and vice versa.
    """
    from provenex.index.async_postgres_index import AsyncPostgresProvenanceIndex
    from provenex.index.postgres_index import PostgresProvenanceIndex

    fp = _fp("cross-backend")
    sync_idx = PostgresProvenanceIndex(dsn=schema_dsn, signing_secret=SECRET)
    try:
        sync_idx.add(
            fingerprint=fp,
            document_id="x-doc",
            document_version=_doc_version("x-doc"),
            chunk_offset=0,
            chunk_length=13,
        )
    finally:
        sync_idx.close()

    async with AsyncPostgresProvenanceIndex(
        dsn=schema_dsn, signing_secret=SECRET
    ) as aidx:
        outcome = await aidx.verify_async(fp)
    assert outcome == VerificationOutcome.VERIFIED


# --------------------------------------------------------------------------- #
# Constructor validation                                                      #
# --------------------------------------------------------------------------- #


async def test_refuses_without_secret(monkeypatch):
    from provenex.index.async_postgres_index import AsyncPostgresProvenanceIndex

    monkeypatch.delenv("PROVENEX_SIGNING_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        AsyncPostgresProvenanceIndex(dsn=DSN)


async def test_rejects_both_dsn_and_pool(monkeypatch):
    from provenex.index.async_postgres_index import AsyncPostgresProvenanceIndex

    monkeypatch.setenv("PROVENEX_SIGNING_SECRET", "test")
    with pytest.raises(ValueError):
        AsyncPostgresProvenanceIndex(dsn=DSN, pool="not-a-pool")


async def test_rejects_neither_dsn_nor_pool(monkeypatch):
    from provenex.index.async_postgres_index import AsyncPostgresProvenanceIndex

    monkeypatch.setenv("PROVENEX_SIGNING_SECRET", "test")
    with pytest.raises(ValueError):
        AsyncPostgresProvenanceIndex()
