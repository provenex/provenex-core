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

from .base import IndexEntry, ProvenanceIndex, VerificationOutcome
from .sqlite_index import _canonical_payload, _now_utc_iso, _sign


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
    PRIMARY KEY (fingerprint, document_id, document_version)
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
            env_secret = os.environ.get("PROVENEX_SIGNING_SECRET")
            if not env_secret:
                raise RuntimeError(
                    "PostgresProvenanceIndex requires a signing_secret argument "
                    "or the PROVENEX_SIGNING_SECRET environment variable to be "
                    "set. The index refuses to operate without one because it "
                    "would be impossible to detect tampering."
                )
            signing_secret = env_secret.encode("utf-8")
        self._secret = signing_secret

        if (dsn is None) == (pool is None):
            raise ValueError(
                "PostgresProvenanceIndex requires exactly one of 'dsn' or "
                "'pool' to be provided."
            )

        ConnectionPool = _require_psycopg()

        if pool is None:
            self._pool = ConnectionPool(
                conninfo=dsn,
                min_size=min_size,
                max_size=max_size,
                open=True,
            )
            self._owns_pool = True
        else:
            self._pool = pool
            self._owns_pool = False

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(_SCHEMA)
            conn.commit()

    # ------------------------------------------------------------------ add

    def add(
        self,
        fingerprint: str,
        document_id: str,
        document_version: str,
        chunk_offset: int,
        chunk_length: int,
        authorized: bool = True,
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

        ingested_at = _now_utc_iso()
        signature = _sign(
            _canonical_payload(
                fingerprint=fingerprint,
                document_id=document_id,
                document_version=document_version,
                ingested_at=ingested_at,
                chunk_offset=chunk_offset,
                chunk_length=chunk_length,
            ),
            self._secret,
        )

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                # Lock the document row (if any) to serialize concurrent
                # supersession against this document_id. New documents take
                # no lock; the unique PK protects against duplicate inserts.
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
                    " chunk_offset, chunk_length, superseded, signature) "
                    "VALUES (%s, %s, %s, %s, %s, %s, FALSE, %s) "
                    "ON CONFLICT (fingerprint, document_id, document_version) "
                    "DO NOTHING",
                    (
                        fingerprint,
                        document_id,
                        document_version,
                        ingested_at,
                        chunk_offset,
                        chunk_length,
                        signature,
                    ),
                )
            conn.commit()

    # --------------------------------------------------------------- lookup

    def lookup(self, fingerprint: str) -> IndexEntry | None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT f.fingerprint, f.document_id, f.document_version, "
                    "       f.ingested_at, f.chunk_offset, f.chunk_length, "
                    "       f.superseded, f.signature, d.authorized "
                    "FROM provenex_fingerprints f "
                    "JOIN provenex_documents d ON d.document_id = f.document_id "
                    "WHERE f.fingerprint = %s "
                    "ORDER BY f.superseded ASC, f.ingested_at DESC "
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
        )

    # ------------------------------------------------------ set_authorization

    def set_authorization(self, document_id: str, authorized: bool) -> None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE provenex_documents SET authorized = %s "
                    "WHERE document_id = %s",
                    (authorized, document_id),
                )
            conn.commit()

    # ---------------------------------------------------------- supersede

    def supersede(self, document_id: str, new_version: str) -> int:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE provenex_fingerprints SET superseded = TRUE "
                    "WHERE document_id = %s AND document_version != %s",
                    (document_id, new_version),
                )
                rowcount = cur.rowcount
                cur.execute(
                    "UPDATE provenex_documents SET current_version = %s "
                    "WHERE document_id = %s",
                    (new_version, document_id),
                )
            conn.commit()
            return rowcount

    # ----------------------------------------------------------- verify

    def verify(self, fingerprint: str) -> VerificationOutcome:
        entry = self.lookup(fingerprint)
        if entry is None:
            return VerificationOutcome.UNVERIFIED

        import hmac

        expected = _sign(
            _canonical_payload(
                fingerprint=entry.fingerprint,
                document_id=entry.document_id,
                document_version=entry.document_version,
                ingested_at=entry.ingested_at,
                chunk_offset=entry.chunk_offset,
                chunk_length=entry.chunk_length,
            ),
            self._secret,
        )
        if not hmac.compare_digest(expected, entry.signature):
            return VerificationOutcome.TAMPERED

        if not entry.authorized:
            return VerificationOutcome.UNAUTHORIZED

        if entry.superseded:
            return VerificationOutcome.STALE

        return VerificationOutcome.VERIFIED

    # ----------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_pool:
            self._pool.close()

    def __enter__(self) -> PostgresProvenanceIndex:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
