"""Async PostgreSQL implementation of :class:`AsyncProvenanceIndex`.

Mirrors :class:`provenex.index.postgres_index.PostgresProvenanceIndex` shape
for shape, but built on ``psycopg.AsyncConnection`` and
``psycopg_pool.AsyncConnectionPool`` so the verify hot path can run inside
a FastAPI / Starlette / aiohttp request handler without blocking the event
loop.

The canonical signing payload, schema DDL, and refusal-of-legacy-schema
logic are imported from the sync backend, so a receipt produced through
the async path verifies bit-identically against a sync-backed verifier
and vice versa.

Install
-------
``pip install "provenex-core[postgres]"`` (same extra as the sync backend).

Usage
-----

    import asyncio
    from provenex import AsyncPostgresProvenanceIndex, verify_chunks_async

    async def main():
        async with AsyncPostgresProvenanceIndex(dsn="postgresql://...") as idx:
            await idx.add_async(
                fingerprint="sha256:...",
                document_id="doc-1",
                document_version="sha256:...",
                chunk_offset=0,
                chunk_length=42,
            )
            result = await verify_chunks_async(
                chunks=["chunk text"], index=idx,
            )

    asyncio.run(main())
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from .base import (
    ENTRY_KIND_WHOLE_CHUNK,
    VALID_ENTRY_KINDS,
    IndexEntry,
    VerificationOutcome,
)
from .postgres_index import _SCHEMA
from .sqlite_index import (
    _canonical_payload,
    _now_utc_iso,
    _reduce_entry_to_outcome,
    _resolve_index_secret,
    _sign,
)


def _require_async_psycopg():
    """Import the async pool class lazily so the core stays stdlib-only."""
    try:
        import psycopg  # noqa: F401
        from psycopg_pool import AsyncConnectionPool
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "AsyncPostgresProvenanceIndex requires the 'postgres' extra. "
            'Install with: pip install "provenex-core[postgres]"'
        ) from exc
    return AsyncConnectionPool


class AsyncPostgresProvenanceIndex:
    """Async Postgres-backed provenance index.

    Two construction modes mirror the sync backend:

        1. DSN: ``AsyncPostgresProvenanceIndex(dsn="postgresql://...", ...)``.
           Creates an internal :class:`psycopg_pool.AsyncConnectionPool`.
           Call :meth:`open_async` (or use ``async with``) before the
           first index operation.

        2. Bring-your-own pool:
           ``AsyncPostgresProvenanceIndex(pool=existing_pool, ...)`` for
           apps that manage their own async pool. The pool is not closed
           by :meth:`close_async` in this mode.

    Args:
        dsn: PostgreSQL connection string. Mutually exclusive with
            ``pool``.
        pool: An existing :class:`psycopg_pool.AsyncConnectionPool`.
            Mutually exclusive with ``dsn``. **The caller is
            responsible for opening this pool** (via ``await pool.open()``
            or its async-context-manager form) BEFORE any verify_async
            / add_async call. When a ``pool`` is supplied here, the
            index assumes it is already open and will not call
            ``open()`` on it; a first verify against an unopened pool
            will fail with the underlying psycopg error.
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
                "AsyncPostgresProvenanceIndex requires exactly one of 'dsn' "
                "or 'pool' to be provided."
            )

        AsyncConnectionPool = _require_async_psycopg()

        if pool is None:
            # Same UTF8 client_encoding configure-on-connect that the sync
            # backend uses: on a SQL_ASCII cluster psycopg returns text
            # columns as bytes, which breaks _canonical_payload's HMAC
            # input. See postgres_index.py for the full discussion.
            async def _configure_utf8(conn) -> None:
                async with conn.cursor() as cur:
                    await cur.execute("SET client_encoding = 'UTF8'")
                await conn.commit()

            self._pool = AsyncConnectionPool(
                conninfo=dsn,
                min_size=min_size,
                max_size=max_size,
                configure=_configure_utf8,
                open=False,
            )
            self._owns_pool = True
        else:
            self._pool = pool
            self._owns_pool = False

        self._schema_ready = False
        self._pool_opened = not self._owns_pool

    async def open_async(self) -> "AsyncPostgresProvenanceIndex":
        """Open the pool and ensure the index schema is present.

        Idempotent: subsequent calls are no-ops. Most callers use the
        async-context-manager form (``async with``) and never invoke
        this directly.
        """
        if self._owns_pool and not self._pool_opened:
            await self._pool.open()
            self._pool_opened = True
        if not self._schema_ready:
            async with self._pool.connection() as conn:
                async with conn.cursor() as cur:
                    await self._refuse_legacy_schema(cur)
                    await cur.execute(_SCHEMA)
                await conn.commit()
            self._schema_ready = True
        return self

    async def _refuse_legacy_schema(self, cur) -> None:
        await cur.execute(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'provenex_fingerprints' LIMIT 1"
        )
        if await cur.fetchone() is None:
            return
        await cur.execute(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'provenex_fingerprints' "
            "AND column_name = 'entry_kind' LIMIT 1"
        )
        if await cur.fetchone() is None:
            raise RuntimeError(
                "This Provenex index was created by a pre-v0.8.0 release. "
                "v0.8.0 closed the window-aligned splice gap by adding an "
                "entry_kind column to the canonical signing payload, which "
                "is not present in this index. Re-ingest your documents "
                "with the v0.8.0 CLI / SDK against a fresh index to upgrade."
            )

    # ----------------------------------------------------------------- add

    async def add_async(
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

        await self._ensure_open()
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)",
                    (document_id,),
                )
                await cur.execute(
                    "SELECT current_version FROM provenex_documents "
                    "WHERE document_id = %s FOR UPDATE",
                    (document_id,),
                )
                row = await cur.fetchone()

                if row is None:
                    await cur.execute(
                        "INSERT INTO provenex_documents "
                        "(document_id, authorized, current_version) "
                        "VALUES (%s, %s, %s) "
                        "ON CONFLICT (document_id) DO NOTHING",
                        (document_id, authorized, document_version),
                    )
                else:
                    current_version = row[0]
                    if current_version != document_version:
                        await cur.execute(
                            "UPDATE provenex_fingerprints SET superseded = TRUE "
                            "WHERE document_id = %s AND document_version != %s",
                            (document_id, document_version),
                        )
                        await cur.execute(
                            "UPDATE provenex_documents "
                            "SET current_version = %s, authorized = %s "
                            "WHERE document_id = %s",
                            (document_version, authorized, document_id),
                        )
                    else:
                        await cur.execute(
                            "UPDATE provenex_documents SET authorized = %s "
                            "WHERE document_id = %s",
                            (authorized, document_id),
                        )

                await cur.execute(
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
            await conn.commit()

    # -------------------------------------------------------------- lookup

    async def lookup_async(self, fingerprint: str) -> Optional[IndexEntry]:
        await self._ensure_open()
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
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
                row = await cur.fetchone()
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

    # ---------------------------------------------------- set_authorization

    async def set_authorization_async(
        self, document_id: str, authorized: bool
    ) -> None:
        await self._ensure_open()
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)",
                    (document_id,),
                )
                await cur.execute(
                    "UPDATE provenex_documents SET authorized = %s "
                    "WHERE document_id = %s",
                    (authorized, document_id),
                )
            await conn.commit()

    # ------------------------------------------------------------ supersede

    async def supersede_async(self, document_id: str, new_version: str) -> int:
        await self._ensure_open()
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)",
                    (document_id,),
                )
                await cur.execute(
                    "UPDATE provenex_fingerprints SET superseded = TRUE "
                    "WHERE document_id = %s AND document_version != %s",
                    (document_id, new_version),
                )
                rowcount = cur.rowcount
                await cur.execute(
                    "UPDATE provenex_documents SET current_version = %s "
                    "WHERE document_id = %s",
                    (new_version, document_id),
                )
            await conn.commit()
            return rowcount

    # --------------------------------------------------------------- verify

    async def verify_async(self, fingerprint: str) -> VerificationOutcome:
        entry = await self.lookup_async(fingerprint)
        return _reduce_entry_to_outcome(entry, self._secret)

    # ---------------------------------------------------------- verify_batch

    async def verify_batch_async(
        self,
        fingerprints: Sequence[str],
    ) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
        """One ``WHERE fingerprint = ANY(%s)`` query in async form.

        Same row-selection rule and same per-fingerprint HMAC reduction
        as the sync backend's ``verify_batch``. The async wrapper is
        what unblocks the event loop on a FastAPI / Starlette handler;
        the SQL is byte-identical so the warm-cache numbers in
        ``docs/scaling.md`` carry over.
        """
        if not fingerprints:
            return []
        unique = list(dict.fromkeys(fingerprints))
        await self._ensure_open()
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
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
                rows = await cur.fetchall()

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

    # ----------------------------------------------------------------- close

    async def close_async(self) -> None:
        if self._owns_pool and self._pool_opened:
            await self._pool.close()
            self._pool_opened = False

    # --------------------------------------------------- context-manager API

    async def __aenter__(self) -> "AsyncPostgresProvenanceIndex":
        await self.open_async()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close_async()

    # ------------------------------------------------------------- internals

    async def _ensure_open(self) -> None:
        """Lazily open the pool / install the schema on first use.

        Lets callers do ``idx = AsyncPostgresProvenanceIndex(dsn=...)``
        and call ``await idx.verify_batch_async(...)`` directly without
        also requiring an ``await idx.open_async()`` line in the happy
        path. The async-context-manager form (``async with``) is still
        the recommended shape because it guarantees the pool is closed
        on exit.
        """
        if not self._schema_ready:
            await self.open_async()
