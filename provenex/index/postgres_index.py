"""PostgreSQL implementation of :class:`ProvenanceIndex`.

This is the production-grade backend for multi-node deployments. Multiple
application pods can share a single Postgres index safely — concurrent
ingest is serialized only on the per-document supersession path (row lock
on the ``documents`` row), and verify is a point-lookup that scales
horizontally across read replicas.

Suitable for:
    - Multi-pod / multi-cluster enterprise deployments
    - Self-hosted on-prem (point at your own Postgres)
    - Managed Postgres (RDS, Cloud SQL, Aurora, Crunchy, Supabase)

For single-node development the :class:`SQLiteProvenanceIndex` is simpler
and stdlib-only.

Signing-payload portability
---------------------------
The canonical HMAC payload is identical to the SQLite backend
(:func:`provenex.index.sqlite_index._canonical_payload`). A receipt
produced against a SQLite-backed index verifies bit-identically against
a Postgres-backed index and vice versa. Receipts are portable across
backends.

Privacy property: same as SQLite — fingerprints and metadata only. No
document text is ever written.

Install
-------
``pip install "provenex-core[postgres]"``

The core remains stdlib-only without this extra; psycopg is imported
lazily and raises a clear error if missing.
"""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, Tuple

from .base import (
    ENTRY_KIND_WHOLE_CHUNK,
    ENTRY_KIND_WINDOW,
    VALID_ENTRY_KINDS,
    IndexEntry,
    ProvenanceIndex,
    VerificationOutcome,
)
from .sqlite_index import (
    _canonical_payload,
    _now_utc_iso,
    _reduce_entry_to_outcome,
    _resolve_index_secret,
    _sign,
)


def _require_psycopg():
    """Import psycopg lazily so the core stays stdlib-only without the extra."""
    try:
        import psycopg  # noqa: F401
        from psycopg_pool import ConnectionPool
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "PostgresProvenanceIndex requires the 'postgres' extra. "
            'Install with: pip install "provenex-core[postgres]"'
        ) from exc
    return ConnectionPool


# v0.8.0: ``entry_kind`` distinguishes whole-chunk entries
# (VERIFIED-eligible) from window locator entries (never
# VERIFIED-eligible). Covered by the canonical signing payload so
# flipping it out-of-band fails the row signature.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS provenex_documents (
    document_id TEXT PRIMARY KEY,
    authorized BOOLEAN NOT NULL DEFAULT TRUE,
    current_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provenex_fingerprints (
    fingerprint TEXT NOT NULL,
    document_id TEXT NOT NULL REFERENCES provenex_documents(document_id),
    document_version TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    chunk_offset INTEGER NOT NULL,
    chunk_length INTEGER NOT NULL,
    superseded BOOLEAN NOT NULL DEFAULT FALSE,
    signature TEXT NOT NULL,
    entry_kind TEXT NOT NULL DEFAULT 'whole_chunk'
        CHECK (entry_kind IN ('whole_chunk','window')),
    PRIMARY KEY (fingerprint, document_id, document_version, entry_kind)
);

CREATE INDEX IF NOT EXISTS idx_provenex_fingerprint
    ON provenex_fingerprints(fingerprint);
CREATE INDEX IF NOT EXISTS idx_provenex_doc
    ON provenex_fingerprints(document_id, document_version);
"""


class PostgresProvenanceIndex(ProvenanceIndex):
    """Postgres-backed provenance index for multi-node deployments.

    Two construction modes:

        1. DSN: ``PostgresProvenanceIndex(dsn="postgresql://...", ...)``
           creates an internal :class:`psycopg_pool.ConnectionPool`.

        2. Bring-your-own pool:
           ``PostgresProvenanceIndex(pool=existing_pool, ...)`` for
           applications that already manage their own pool. The pool is
           not closed by :meth:`close` in this mode.

    Args:
        dsn: PostgreSQL connection string. Mutually exclusive with ``pool``.
        pool: An existing :class:`psycopg_pool.ConnectionPool`. Mutually
            exclusive with ``dsn``.
        signing_secret: HMAC key (bytes). Falls back to
            ``PROVENEX_SIGNING_SECRET`` env var. The index refuses to
            operate without a signing secret.
        min_size: Minimum pool size when constructed from a DSN.
        max_size: Maximum pool size when constructed from a DSN.

    Raises:
        RuntimeError: If no signing secret is supplied.
        ValueError: If neither (or both) of ``dsn`` and ``pool`` is set.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        pool=None,
        signing_secret: bytes | None = None,
        min_size: int = 1,
        max_size: int = 10,
    ) -> None:
        if signing_secret is None:
            signing_secret = _resolve_index_secret()
        self._secret = signing_secret

        if (dsn is None) == (pool is None):
            raise ValueError(
                "PostgresProvenanceIndex requires exactly one of 'dsn' or "
                "'pool' to be provided."
            )

        ConnectionPool = _require_psycopg()

        if pool is None:
            # Force UTF8 client_encoding on every new connection. On a
            # SQL_ASCII cluster (macOS initdb default), psycopg3 returns
            # text columns as bytes instead of str — _canonical_payload
            # then blows up at HMAC time. UTF8 is the only safe choice
            # for a backend that signs over text-typed rows.
            def _configure_utf8(conn) -> None:
                with conn.cursor() as cur:
                    cur.execute("SET client_encoding = 'UTF8'")
                # psycopg defaults to non-autocommit; the SET opens an
                # implicit transaction the pool requires us to close
                # before handing the connection out (otherwise it's
                # discarded with a "left in status INTRANS" warning).
                conn.commit()

            self._pool = ConnectionPool(
                conninfo=dsn,
                min_size=min_size,
                max_size=max_size,
                configure=_configure_utf8,
                open=True,
            )
            self._owns_pool = True
        else:
            self._pool = pool
            self._owns_pool = False

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                self._refuse_legacy_schema(cur)
                cur.execute(_SCHEMA)
            conn.commit()

    def _refuse_legacy_schema(self, cur) -> None:
        """Fail fast if opening a pre-v0.8.0 Postgres index.

        v0.8.0 added the ``entry_kind`` column to
        ``provenex_fingerprints``. Existing rows in a pre-v0.8.0 index
        were signed without that field, so silently auto-upgrading
        would either downgrade safety or make every row TAMPERED.
        """
        cur.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'provenex_fingerprints' LIMIT 1"
        )
        if cur.fetchone() is None:
            return
        cur.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'provenex_fingerprints' "
            "AND column_name = 'entry_kind' LIMIT 1"
        )
        if cur.fetchone() is None:
            raise RuntimeError(
                "This Provenex index was created by a pre-v0.8.0 release. "
                "v0.8.0 closed the window-aligned splice gap by adding an "
                "entry_kind column to the canonical signing payload, which "
                "is not present in this index. Re-ingest your documents "
                "with the v0.8.0 CLI / SDK against a fresh index to upgrade."
            )

    # ------------------------------------------------------------------ add

    def add(
        self,
        fingerprint: str,
        document_id: str,
        document_version: str,
        chunk_offset: int,
        chunk_length: int,
        authorized: bool = True,
        entry_kind: str = ENTRY_KIND_WHOLE_CHUNK,
    ) -> None:
        if not fingerprint.startswith("sha256:"):
            raise ValueError(
                f"fingerprint must be in the form 'sha256:<hex>', got {fingerprint!r}"
            )
        if not document_version.startswith("sha256:"):
            raise ValueError(
                "document_version must be in the form 'sha256:<hex>', got "
                f"{document_version!r}"
            )
        if entry_kind not in VALID_ENTRY_KINDS:
            raise ValueError(
                f"entry_kind must be one of {VALID_ENTRY_KINDS}, got "
                f"{entry_kind!r}"
            )

        ingested_at = _now_utc_iso()
        signature = _sign(
            _canonical_payload(
                fingerprint=fingerprint,
                document_id=document_id,
                document_version=document_version,
                ingested_at=ingested_at,
                chunk_offset=chunk_offset,
                chunk_length=chunk_length,
                entry_kind=entry_kind,
            ),
            self._secret,
        )

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # Take a transaction-scoped advisory lock keyed on
                # document_id BEFORE the SELECT. SELECT ... FOR UPDATE
                # alone does not serialise the new-document case
                # (returns no row to lock), so two concurrent inserts
                # with the same document_id could race past it and
                # disagree on authorization. hashtext() collapses to a
                # 32-bit int; collisions are false contention, not
                # safety. The lock auto-releases on commit/rollback.
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)",
                    (document_id,),
                )
                cur.execute(
                    "SELECT current_version FROM provenex_documents "
                    "WHERE document_id = %s FOR UPDATE",
                    (document_id,),
                )
                row = cur.fetchone()

                if row is None:
                    cur.execute(
                        "INSERT INTO provenex_documents "
                        "(document_id, authorized, current_version) "
                        "VALUES (%s, %s, %s) "
                        "ON CONFLICT (document_id) DO NOTHING",
                        (document_id, authorized, document_version),
                    )
                else:
                    current_version = row[0]
                    if current_version != document_version:
                        cur.execute(
                            "UPDATE provenex_fingerprints SET superseded = TRUE "
                            "WHERE document_id = %s AND document_version != %s",
                            (document_id, document_version),
                        )
                        cur.execute(
                            "UPDATE provenex_documents "
                            "SET current_version = %s, authorized = %s "
                            "WHERE document_id = %s",
                            (document_version, authorized, document_id),
                        )
                    else:
                        cur.execute(
                            "UPDATE provenex_documents SET authorized = %s "
                            "WHERE document_id = %s",
                            (authorized, document_id),
                        )

                cur.execute(
                    "INSERT INTO provenex_fingerprints "
                    "(fingerprint, document_id, document_version, ingested_at, "
                    " chunk_offset, chunk_length, superseded, signature, "
                    " entry_kind) "
                    "VALUES (%s, %s, %s, %s, %s, %s, FALSE, %s, %s) "
                    "ON CONFLICT "
                    "(fingerprint, document_id, document_version, entry_kind) "
                    "DO NOTHING",
                    (
                        fingerprint,
                        document_id,
                        document_version,
                        ingested_at,
                        chunk_offset,
                        chunk_length,
                        signature,
                        entry_kind,
                    ),
                )
            conn.commit()

    # --------------------------------------------------------------- lookup

    def lookup(self, fingerprint: str) -> IndexEntry | None:
        # Prefer a whole-chunk row over a window row when both exist for
        # the same fingerprint. See the SQLite analog for rationale.
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT f.fingerprint, f.document_id, f.document_version, "
                    "       f.ingested_at, f.chunk_offset, f.chunk_length, "
                    "       f.superseded, f.signature, d.authorized, "
                    "       f.entry_kind "
                    "FROM provenex_fingerprints f "
                    "JOIN provenex_documents d ON d.document_id = f.document_id "
                    "WHERE f.fingerprint = %s "
                    "ORDER BY CASE f.entry_kind WHEN 'whole_chunk' THEN 0 ELSE 1 END ASC, "
                    "         f.superseded ASC, f.ingested_at DESC "
                    "LIMIT 1",
                    (fingerprint,),
                )
                row = cur.fetchone()
        if row is None:
            return None
        return IndexEntry(
            fingerprint=row[0],
            document_id=row[1],
            document_version=row[2],
            ingested_at=row[3],
            chunk_offset=row[4],
            chunk_length=row[5],
            authorized=bool(row[8]),
            superseded=bool(row[6]),
            signature=row[7],
            entry_kind=row[9],
        )

    # ------------------------------------------------------ set_authorization

    def set_authorization(self, document_id: str, authorized: bool) -> None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # Same advisory lock as add() so a concurrent add() and
                # set_authorization() cannot race on the same document.
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)",
                    (document_id,),
                )
                cur.execute(
                    "UPDATE provenex_documents SET authorized = %s "
                    "WHERE document_id = %s",
                    (authorized, document_id),
                )
                if cur.rowcount == 0:
                    # Silent no-op would let a typo'd revocation appear to
                    # succeed while the real document remains authorized.
                    conn.rollback()
                    raise KeyError(document_id)
            conn.commit()

    # ---------------------------------------------------------- supersede

    def supersede(self, document_id: str, new_version: str) -> int:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # Same advisory lock as add() / set_authorization() so
                # supersession cannot race against a concurrent add().
                cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)",
                    (document_id,),
                )
                cur.execute(
                    "UPDATE provenex_documents SET current_version = %s "
                    "WHERE document_id = %s",
                    (new_version, document_id),
                )
                if cur.rowcount == 0:
                    conn.rollback()
                    raise KeyError(document_id)
                cur.execute(
                    "UPDATE provenex_fingerprints SET superseded = TRUE "
                    "WHERE document_id = %s AND document_version != %s",
                    (document_id, new_version),
                )
                rowcount = cur.rowcount
            conn.commit()
            return rowcount

    # ----------------------------------------------------------- verify

    def verify(self, fingerprint: str) -> VerificationOutcome:
        return _reduce_entry_to_outcome(self.lookup(fingerprint), self._secret)

    # ------------------------------------------------------- verify_batch

    def verify_batch(
        self,
        fingerprints: Sequence[str],
    ) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
        """One ``WHERE fingerprint = ANY(%s)`` query instead of N round-trips.

        Mirrors the SQLite override exactly: same row-selection rule,
        same per-fingerprint HMAC reduction. The single-query collapse
        on a top-10 retrieval drops the number of Postgres round-trips
        from 20 (lookup+verify per chunk) to 1.
        """
        if not fingerprints:
            return []
        unique = list(dict.fromkeys(fingerprints))
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT f.fingerprint, f.document_id, f.document_version, "
                    "       f.ingested_at, f.chunk_offset, f.chunk_length, "
                    "       f.superseded, f.signature, d.authorized, "
                    "       f.entry_kind "
                    "FROM provenex_fingerprints f "
                    "JOIN provenex_documents d ON d.document_id = f.document_id "
                    "WHERE f.fingerprint = ANY(%s) "
                    "ORDER BY f.fingerprint, "
                    "         CASE f.entry_kind WHEN 'whole_chunk' THEN 0 ELSE 1 END ASC, "
                    "         f.superseded ASC, f.ingested_at DESC",
                    (unique,),
                )
                rows = cur.fetchall()

        preferred: dict[str, IndexEntry] = {}
        for row in rows:
            fp = row[0]
            if fp in preferred:
                continue
            preferred[fp] = IndexEntry(
                fingerprint=fp,
                document_id=row[1],
                document_version=row[2],
                ingested_at=row[3],
                chunk_offset=row[4],
                chunk_length=row[5],
                authorized=bool(row[8]),
                superseded=bool(row[6]),
                signature=row[7],
                entry_kind=row[9],
            )

        out: List[Tuple[VerificationOutcome, Optional[IndexEntry]]] = []
        for fp in fingerprints:
            entry = preferred.get(fp)
            out.append((_reduce_entry_to_outcome(entry, self._secret), entry))
        return out

    # ----------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_pool:
            self._pool.close()

    def __enter__(self) -> PostgresProvenanceIndex:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
