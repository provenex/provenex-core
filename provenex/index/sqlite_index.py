"""SQLite implementation of :class:`ProvenanceIndex`.

This is the open source index. It stores fingerprints in a local SQLite
database with HMAC-SHA256 signatures on every row to detect tampering with
the index file itself.

Suitable for development, single-node deployments, and self-hosted use.
For high-throughput multi-node deployments, see the Provenex commercial
hosted index (which implements the same :class:`ProvenanceIndex` interface).

Privacy property: this index stores fingerprints and metadata only. Document
text is never written here. The fingerprint is one-way; you cannot recover
document content from the index.
"""

from __future__ import annotations

import hmac
import os
import sqlite3
import threading
from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional

from .base import IndexEntry, ProvenanceIndex, VerificationOutcome


_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    authorized INTEGER NOT NULL DEFAULT 1,
    current_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint TEXT NOT NULL,
    document_id TEXT NOT NULL,
    document_version TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    chunk_offset INTEGER NOT NULL,
    chunk_length INTEGER NOT NULL,
    superseded INTEGER NOT NULL DEFAULT 0,
    signature TEXT NOT NULL,
    PRIMARY KEY (fingerprint, document_id, document_version),
    FOREIGN KEY (document_id) REFERENCES documents(document_id)
);

CREATE INDEX IF NOT EXISTS idx_fingerprint ON fingerprints(fingerprint);
CREATE INDEX IF NOT EXISTS idx_doc ON fingerprints(document_id, document_version);
"""


def _now_utc_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with millisecond precision."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _canonical_payload(
    fingerprint: str,
    document_id: str,
    document_version: str,
    ingested_at: str,
    chunk_offset: int,
    chunk_length: int,
) -> bytes:
    """Build the canonical bytes that get HMAC'd for a fingerprint row.

    The canonicalization is deterministic: a fixed-order, newline-separated
    sequence of fields. Any change to field values produces a different MAC.
    """
    return "\n".join(
        [
            fingerprint,
            document_id,
            document_version,
            ingested_at,
            str(chunk_offset),
            str(chunk_length),
        ]
    ).encode("utf-8")


def _sign(payload: bytes, secret: bytes) -> str:
    """HMAC-SHA256 a payload, returned as hex."""
    return hmac.new(secret, payload, sha256).hexdigest()


class SQLiteProvenanceIndex(ProvenanceIndex):
    """SQLite-backed provenance index.

    Args:
        db_path: Filesystem path to the SQLite database. Use ``":memory:"``
            for an ephemeral in-memory index (useful in tests). The file is
            created if it does not exist.
        signing_secret: Bytes used as the HMAC key for row signatures. If
            ``None``, the value of the ``PROVENEX_SIGNING_SECRET`` environment
            variable is used. If neither is set, a :class:`RuntimeError` is
            raised — the index refuses to operate without a signing secret
            because that would make tamper detection impossible.

    Raises:
        RuntimeError: If no signing secret is provided or available in the
            environment.
    """

    def __init__(
        self,
        db_path: str,
        signing_secret: Optional[bytes] = None,
    ) -> None:
        if signing_secret is None:
            env_secret = os.environ.get("PROVENEX_SIGNING_SECRET")
            if not env_secret:
                raise RuntimeError(
                    "SQLiteProvenanceIndex requires a signing_secret argument "
                    "or the PROVENEX_SIGNING_SECRET environment variable to "
                    "be set. The index refuses to operate without one because "
                    "it would be impossible to detect tampering."
                )
            signing_secret = env_secret.encode("utf-8")
        self._secret = signing_secret
        self._db_path = db_path
        # SQLite connections are not thread-safe across threads by default; we
        # serialize access through a lock and create the connection with
        # check_same_thread=False so a single connection can serve multiple
        # threads under the lock.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

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

        with self._lock:
            cur = self._conn.cursor()
            # Upsert the document row. If this is a new version of an existing
            # document_id, mark the older versions as superseded.
            existing = cur.execute(
                "SELECT current_version FROM documents WHERE document_id = ?",
                (document_id,),
            ).fetchone()

            if existing is None:
                cur.execute(
                    "INSERT INTO documents (document_id, authorized, current_version) "
                    "VALUES (?, ?, ?)",
                    (document_id, 1 if authorized else 0, document_version),
                )
            else:
                if existing["current_version"] != document_version:
                    cur.execute(
                        "UPDATE fingerprints SET superseded = 1 "
                        "WHERE document_id = ? AND document_version != ?",
                        (document_id, document_version),
                    )
                    cur.execute(
                        "UPDATE documents SET current_version = ?, authorized = ? "
                        "WHERE document_id = ?",
                        (document_version, 1 if authorized else 0, document_id),
                    )
                else:
                    # Same version re-ingestion — just refresh authorization.
                    cur.execute(
                        "UPDATE documents SET authorized = ? WHERE document_id = ?",
                        (1 if authorized else 0, document_id),
                    )

            cur.execute(
                "INSERT OR IGNORE INTO fingerprints "
                "(fingerprint, document_id, document_version, ingested_at, "
                " chunk_offset, chunk_length, superseded, signature) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
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
            self._conn.commit()

    # --------------------------------------------------------------- lookup

    def lookup(self, fingerprint: str) -> Optional[IndexEntry]:
        with self._lock:
            row = self._conn.execute(
                "SELECT f.fingerprint, f.document_id, f.document_version, "
                "       f.ingested_at, f.chunk_offset, f.chunk_length, "
                "       f.superseded, f.signature, d.authorized "
                "FROM fingerprints f "
                "JOIN documents d ON d.document_id = f.document_id "
                "WHERE f.fingerprint = ? "
                "ORDER BY f.superseded ASC, f.ingested_at DESC "
                "LIMIT 1",
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        return IndexEntry(
            fingerprint=row["fingerprint"],
            document_id=row["document_id"],
            document_version=row["document_version"],
            ingested_at=row["ingested_at"],
            chunk_offset=row["chunk_offset"],
            chunk_length=row["chunk_length"],
            authorized=bool(row["authorized"]),
            superseded=bool(row["superseded"]),
            signature=row["signature"],
        )

    # ------------------------------------------------------ set_authorization

    def set_authorization(self, document_id: str, authorized: bool) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE documents SET authorized = ? WHERE document_id = ?",
                (1 if authorized else 0, document_id),
            )
            self._conn.commit()

    # ---------------------------------------------------------- supersede

    def supersede(self, document_id: str, new_version: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE fingerprints SET superseded = 1 "
                "WHERE document_id = ? AND document_version != ?",
                (document_id, new_version),
            )
            self._conn.execute(
                "UPDATE documents SET current_version = ? WHERE document_id = ?",
                (new_version, document_id),
            )
            self._conn.commit()
            return cur.rowcount

    # ----------------------------------------------------------- verify

    def verify(self, fingerprint: str) -> VerificationOutcome:
        entry = self.lookup(fingerprint)
        if entry is None:
            return VerificationOutcome.UNVERIFIED

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
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SQLiteProvenanceIndex":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
