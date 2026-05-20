"""Tests for ``ProvenanceIndex.verify_batch`` (Phase 1.1).

``verify_batch(fingerprints)`` returns ``[(outcome, entry), ...]`` aligned to
the input list. The ABC ships a default loop implementation so every backend
inherits a correct fallback; SQLite and Postgres override it with a single
``IN`` / ``ANY`` query that collapses the per-chunk round-trips on a
multi-chunk retrieval.

Test-first per the project conventions: this file lands before the
implementation. The first run shows N failures, which the implementation
in :mod:`provenex.index.{base,sqlite_index,postgres_index}` then drives to
green.
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

import pytest

from provenex.index.base import (
    ENTRY_KIND_WHOLE_CHUNK,
    ENTRY_KIND_WINDOW,
    IndexEntry,
    ProvenanceIndex,
    VerificationOutcome,
)
from provenex.index.sqlite_index import SQLiteProvenanceIndex


SECRET = b"test-secret-do-not-use-in-production"

DSN = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")
_postgres_skip = pytest.mark.skipif(
    not DSN, reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping Postgres tests"
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _hex(c: str) -> str:
    return "sha256:" + c * 64


def _seed_known_index(idx: ProvenanceIndex) -> dict:
    """Seed an index with a handful of fingerprints exercising every outcome.

    Returns a dict mapping a friendly name → fingerprint string for the tests
    below to reference.
    """
    fps = {
        "verified_a": _hex("a"),
        "verified_b": _hex("b"),
        "stale_old": _hex("c"),
        "unauthorized": _hex("d"),
        "window_locator": _hex("e"),
        "unknown": _hex("f"),  # never added — UNVERIFIED expected
        "tampered": _hex("1"),
    }

    # Two VERIFIED whole-chunk entries on the same authorized document.
    idx.add(
        fingerprint=fps["verified_a"],
        document_id="doc_authorized",
        document_version=_hex("0"),
        chunk_offset=0,
        chunk_length=64,
    )
    idx.add(
        fingerprint=fps["verified_b"],
        document_id="doc_authorized",
        document_version=_hex("0"),
        chunk_offset=64,
        chunk_length=64,
    )

    # STALE: a chunk whose document version has been superseded.
    idx.add(
        fingerprint=fps["stale_old"],
        document_id="doc_stale",
        document_version=_hex("2"),
        chunk_offset=0,
        chunk_length=32,
    )
    idx.supersede("doc_stale", _hex("3"))

    # UNAUTHORIZED: chunk on a revoked document.
    idx.add(
        fingerprint=fps["unauthorized"],
        document_id="doc_revoked",
        document_version=_hex("4"),
        chunk_offset=0,
        chunk_length=32,
    )
    idx.set_authorization("doc_revoked", False)

    # Window locator → UNVERIFIED (with a locator entry returned, NOT None).
    idx.add(
        fingerprint=fps["window_locator"],
        document_id="doc_authorized",
        document_version=_hex("0"),
        chunk_offset=128,
        chunk_length=128,
        entry_kind=ENTRY_KIND_WINDOW,
    )

    # TAMPERED: add a row, then corrupt the signature byte in storage.
    idx.add(
        fingerprint=fps["tampered"],
        document_id="doc_tampered",
        document_version=_hex("5"),
        chunk_offset=0,
        chunk_length=32,
    )
    _corrupt_signature(idx, fps["tampered"])

    return fps


def _corrupt_signature(idx: ProvenanceIndex, fingerprint: str) -> None:
    """Flip the row signature to force a TAMPERED outcome on the next verify."""
    if isinstance(idx, SQLiteProvenanceIndex):
        with idx._lock:  # noqa: SLF001 — testing internals deliberately
            idx._conn.execute(
                "UPDATE fingerprints SET signature = 'deadbeef' "
                "WHERE fingerprint = ?",
                (fingerprint,),
            )
            idx._conn.commit()
        return
    # Postgres path (kept import-local so the SQLite-only suite stays
    # stdlib-only when psycopg is absent).
    from provenex.index.postgres_index import PostgresProvenanceIndex

    if isinstance(idx, PostgresProvenanceIndex):
        with idx._pool.connection() as conn:  # noqa: SLF001
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE provenex_fingerprints SET signature = 'deadbeef' "
                    "WHERE fingerprint = %s",
                    (fingerprint,),
                )
            conn.commit()
        return
    raise NotImplementedError(
        f"_corrupt_signature does not know how to reach into {type(idx).__name__}"
    )


def _serial_baseline(
    idx: ProvenanceIndex, fingerprints: List[str]
) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
    """Reference result: call the existing verify+lookup pair per fingerprint."""
    return [(idx.verify(fp), idx.lookup(fp)) for fp in fingerprints]


# --------------------------------------------------------------------------- #
# SQLite-backed behaviour                                                     #
# --------------------------------------------------------------------------- #


@pytest.fixture
def sqlite_index():
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    yield idx
    idx.close()


def test_verify_batch_matches_serial_on_sqlite(sqlite_index):
    fps = _seed_known_index(sqlite_index)
    inputs = [
        fps["verified_a"],
        fps["unknown"],
        fps["stale_old"],
        fps["unauthorized"],
        fps["window_locator"],
        fps["tampered"],
        fps["verified_b"],
    ]
    serial = _serial_baseline(sqlite_index, inputs)
    batch = sqlite_index.verify_batch(inputs)
    assert len(batch) == len(inputs)
    for (s_outcome, s_entry), (b_outcome, b_entry) in zip(serial, batch):
        assert b_outcome == s_outcome
        # entry may be None on UNVERIFIED-no-row; otherwise compare structurally.
        if s_entry is None:
            assert b_entry is None
        else:
            assert b_entry is not None
            assert b_entry.fingerprint == s_entry.fingerprint
            assert b_entry.document_id == s_entry.document_id
            assert b_entry.entry_kind == s_entry.entry_kind
            assert b_entry.authorized == s_entry.authorized
            assert b_entry.superseded == s_entry.superseded


def test_verify_batch_preserves_input_order(sqlite_index):
    fps = _seed_known_index(sqlite_index)
    inputs = [fps["unknown"], fps["verified_a"], fps["unknown"], fps["verified_b"]]
    out = sqlite_index.verify_batch(inputs)
    assert out[0][0] == VerificationOutcome.UNVERIFIED
    assert out[1][0] == VerificationOutcome.VERIFIED
    assert out[2][0] == VerificationOutcome.UNVERIFIED
    assert out[3][0] == VerificationOutcome.VERIFIED


def test_verify_batch_handles_duplicates(sqlite_index):
    fps = _seed_known_index(sqlite_index)
    inputs = [fps["verified_a"]] * 5
    out = sqlite_index.verify_batch(inputs)
    assert len(out) == 5
    for outcome, entry in out:
        assert outcome == VerificationOutcome.VERIFIED
        assert entry is not None
        assert entry.fingerprint == fps["verified_a"]


def test_verify_batch_handles_empty_input(sqlite_index):
    assert sqlite_index.verify_batch([]) == []


def test_verify_batch_window_locator_returns_locator_entry_not_none(sqlite_index):
    """An UNVERIFIED outcome from a window-locator match still carries the
    locator entry, so the receipt's source record can record where the
    bytes came from. ``verify_batch`` must preserve that semantics."""
    fps = _seed_known_index(sqlite_index)
    [(outcome, entry)] = sqlite_index.verify_batch([fps["window_locator"]])
    assert outcome == VerificationOutcome.UNVERIFIED
    assert entry is not None
    assert entry.entry_kind == ENTRY_KIND_WINDOW


def test_verify_batch_tampered_entry_is_returned(sqlite_index):
    """TAMPERED rows must still surface the entry so an auditor can see
    which row was flagged."""
    fps = _seed_known_index(sqlite_index)
    [(outcome, entry)] = sqlite_index.verify_batch([fps["tampered"]])
    assert outcome == VerificationOutcome.TAMPERED
    assert entry is not None


# --------------------------------------------------------------------------- #
# Default ABC implementation                                                  #
# --------------------------------------------------------------------------- #


class _FakeIndex(ProvenanceIndex):
    """Minimal in-memory ProvenanceIndex that does NOT override verify_batch.

    Exercises the ABC's default loop implementation: every backend gets a
    correct (if not necessarily fast) ``verify_batch`` for free.
    """

    def __init__(self) -> None:
        self._entries: dict[str, IndexEntry] = {}

    def add(self, *args, **kwargs) -> None:  # not used
        raise NotImplementedError

    def lookup(self, fingerprint: str) -> Optional[IndexEntry]:
        return self._entries.get(fingerprint)

    def set_authorization(self, document_id: str, authorized: bool) -> None:
        raise NotImplementedError

    def supersede(self, document_id: str, new_version: str) -> int:
        raise NotImplementedError

    def verify(self, fingerprint: str) -> VerificationOutcome:
        entry = self._entries.get(fingerprint)
        if entry is None:
            return VerificationOutcome.UNVERIFIED
        if entry.entry_kind == ENTRY_KIND_WINDOW:
            return VerificationOutcome.UNVERIFIED
        return VerificationOutcome.VERIFIED

    def close(self) -> None:
        pass


def test_verify_batch_default_impl_via_abc():
    idx = _FakeIndex()
    idx._entries[_hex("a")] = IndexEntry(
        fingerprint=_hex("a"),
        document_id="d",
        document_version=_hex("0"),
        ingested_at="2026-01-01T00:00:00.000Z",
        chunk_offset=0,
        chunk_length=32,
        authorized=True,
        superseded=False,
        signature="x",
        entry_kind=ENTRY_KIND_WHOLE_CHUNK,
    )
    out = idx.verify_batch([_hex("a"), _hex("z"), _hex("a")])
    assert [o for o, _ in out] == [
        VerificationOutcome.VERIFIED,
        VerificationOutcome.UNVERIFIED,
        VerificationOutcome.VERIFIED,
    ]
    assert out[0][1] is not None and out[0][1].fingerprint == _hex("a")
    assert out[1][1] is None
    assert out[2][1] is not None


# --------------------------------------------------------------------------- #
# Postgres backend (skipped without DSN)                                      #
# --------------------------------------------------------------------------- #


@pytest.fixture
def postgres_index():
    import uuid

    import psycopg

    from provenex.index.postgres_index import PostgresProvenanceIndex

    schema = f"provenex_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DSN, autocommit=True) as setup_conn:
        with setup_conn.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')

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


@_postgres_skip
def test_verify_batch_matches_serial_on_postgres(postgres_index):
    fps = _seed_known_index(postgres_index)
    inputs = [
        fps["verified_a"],
        fps["unknown"],
        fps["stale_old"],
        fps["unauthorized"],
        fps["window_locator"],
        fps["tampered"],
        fps["verified_b"],
    ]
    serial = _serial_baseline(postgres_index, inputs)
    batch = postgres_index.verify_batch(inputs)
    assert len(batch) == len(inputs)
    for (s_outcome, s_entry), (b_outcome, b_entry) in zip(serial, batch):
        assert b_outcome == s_outcome
        if s_entry is None:
            assert b_entry is None
        else:
            assert b_entry is not None
            assert b_entry.fingerprint == s_entry.fingerprint
            assert b_entry.document_id == s_entry.document_id
            assert b_entry.entry_kind == s_entry.entry_kind


@_postgres_skip
def test_verify_batch_postgres_single_query(postgres_index, monkeypatch):
    """The override must use a single SQL round-trip for N inputs, not N.

    We count ``cursor.execute`` calls during a ``verify_batch(N)`` on a
    fresh Postgres connection. The expectation: one SELECT against
    ``provenex_fingerprints``, plus whatever pool / connection setup the
    pool does. We're strict only about the fingerprint SELECT count.
    """
    fps = _seed_known_index(postgres_index)
    inputs = [fps["verified_a"], fps["verified_b"], fps["unknown"]] * 3

    import psycopg

    seen: list[str] = []
    orig_execute = psycopg.Cursor.execute

    def spy(self, query, params=None, *a, **kw):
        text = query if isinstance(query, str) else str(query)
        if "provenex_fingerprints" in text and "SELECT" in text.upper():
            seen.append(text)
        return orig_execute(self, query, params, *a, **kw)

    monkeypatch.setattr(psycopg.Cursor, "execute", spy)
    out = postgres_index.verify_batch(inputs)
    assert len(out) == len(inputs)
    # Exactly one SELECT against provenex_fingerprints for the whole batch.
    assert len(seen) == 1, (
        f"verify_batch must use a single SELECT against provenex_fingerprints; "
        f"got {len(seen)}: {seen}"
    )


# --------------------------------------------------------------------------- #
# verify_chunks integration: must route through verify_batch                  #
# --------------------------------------------------------------------------- #


def test_verify_chunks_calls_verify_batch_once(sqlite_index, monkeypatch):
    """``verify_chunks`` is the framework-agnostic entrypoint that all
    framework wrappers delegate to. On a multi-chunk call it must make
    exactly one ``verify_batch`` call, not N pairs of verify+lookup.
    """
    from provenex import HmacSha256Signer
    from provenex.core import verify as verify_mod

    fps = _seed_known_index(sqlite_index)

    # Add the chunk texts whose fingerprints we seeded. The texts must
    # normalise+fingerprint to ``fps["verified_a"]`` and ``fps["verified_b"]``,
    # but we don't know those preimages. Instead, exercise the call path
    # by passing arbitrary chunks (they'll come back UNVERIFIED) and
    # asserting batch-routing on call counts only.
    chunks = ["chunk one", "chunk two", "chunk three"]

    call_counts = {"verify_batch": 0, "verify": 0, "lookup": 0}
    orig_verify_batch = sqlite_index.verify_batch
    orig_verify = sqlite_index.verify
    orig_lookup = sqlite_index.lookup

    def spy_verify_batch(fps_list):
        call_counts["verify_batch"] += 1
        return orig_verify_batch(fps_list)

    def spy_verify(fp):
        call_counts["verify"] += 1
        return orig_verify(fp)

    def spy_lookup(fp):
        call_counts["lookup"] += 1
        return orig_lookup(fp)

    monkeypatch.setattr(sqlite_index, "verify_batch", spy_verify_batch)
    monkeypatch.setattr(sqlite_index, "verify", spy_verify)
    monkeypatch.setattr(sqlite_index, "lookup", spy_lookup)

    verify_mod.verify_chunks(
        chunks=chunks,
        index=sqlite_index,
        signer=HmacSha256Signer(secret=b"phase-1-1-receipt-secret"),
    )
    assert call_counts["verify_batch"] == 1
    # verify_chunks must not also call verify() or lookup() per chunk.
    assert call_counts["verify"] == 0
    assert call_counts["lookup"] == 0
