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
import warnings
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .base import (
    ENTRY_KIND_WHOLE_CHUNK,
    ENTRY_KIND_WINDOW,
    VALID_ENTRY_KINDS,
    IndexEntry,
    ProvenanceIndex,
    VerificationOutcome,
)


# Module-level guard so the legacy-shared-secret warning fires at most
# once per process.
_warned_about_shared_index_secret = False


def _resolve_index_secret() -> bytes:
    """Resolve the index-row HMAC secret from the environment.

    Resolution order:

    1. ``PROVENEX_INDEX_SECRET`` — the role-specific env (preferred).
    2. ``PROVENEX_SIGNING_SECRET`` — the legacy shared env (fallback).
       Emits a one-time ``DeprecationWarning``; see
       :func:`provenex.core.receipt._resolve_receipt_secret` for the
       receipt-side mirror.

    Raises:
        RuntimeError: If neither env var is set.
    """
    env_secret = os.environ.get("PROVENEX_INDEX_SECRET")
    if env_secret:
        return env_secret.encode("utf-8")
    secret_file = os.environ.get("PROVENEX_INDEX_SECRET_FILE")
    if secret_file:
        # Written by ``provenex keys init``: hex of 32 random bytes,
        # mode 0600. Plain (non-hex) contents are used as-is.
        raw = Path(secret_file).read_bytes().strip()
        try:
            return bytes.fromhex(raw.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            return raw
    env_secret = os.environ.get("PROVENEX_SIGNING_SECRET")
    if env_secret:
        global _warned_about_shared_index_secret
        if not _warned_about_shared_index_secret:
            warnings.warn(
                "Provenex index secret resolved via legacy "
                "PROVENEX_SIGNING_SECRET. For key separation between the "
                "index-row HMAC and the receipt HMAC, set "
                "PROVENEX_INDEX_SECRET (and PROVENEX_RECEIPT_SECRET) "
                "separately. This warning fires once per process.",
                DeprecationWarning,
                stacklevel=3,
            )
            _warned_about_shared_index_secret = True
        return env_secret.encode("utf-8")
    raise RuntimeError(
        "ProvenanceIndex requires a signing_secret argument, or one of "
        "the PROVENEX_INDEX_SECRET / PROVENEX_SIGNING_SECRET "
        "environment variables to be set. The index refuses to operate "
        "without one because it would be impossible to detect tampering."
    )


# v0.8.0 schema. ``entry_kind`` distinguishes operator-authorized
# whole-chunk entries (VERIFIED-eligible) from sliding-window
# locator-only entries (NEVER VERIFIED-eligible). The column is NOT
# NULL with a CHECK constraint so a malformed write fails at the
# storage layer, and it is covered by the row signature so flipping
# the value out-of-band is tamper-evident.
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
    entry_kind TEXT NOT NULL DEFAULT 'whole_chunk'
        CHECK (entry_kind IN ('whole_chunk','window')),
    PRIMARY KEY (fingerprint, document_id, document_version, entry_kind),
    FOREIGN KEY (document_id) REFERENCES documents(document_id)
);

CREATE INDEX IF NOT EXISTS idx_fingerprint ON fingerprints(fingerprint);
CREATE INDEX IF NOT EXISTS idx_doc ON fingerprints(document_id, document_version);

-- Deletion-attestation tombstones (additive; created on open for
-- pre-existing indexes too). A row here means the operator attested
-- that copies registered under this fingerprint were purged. The
-- fingerprint row itself is kept: index history records the purge.
CREATE TABLE IF NOT EXISTS purged_fingerprints (
    fingerprint TEXT PRIMARY KEY,
    purged_at TEXT NOT NULL,
    receipt_ref TEXT
);
"""


def _now_utc_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with millisecond precision."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


_FORBIDDEN_FIELD_CHARS = ("\n", "\r", "\x00")


def _validate_signing_field(name: str, value: str) -> None:
    """Reject characters that would create signing-payload ambiguity.

    The canonical payload is a newline-joined sequence; any field containing
    a literal newline, carriage return, or null byte could be confused with
    a different field tuple under the same HMAC.
    """
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    for c in _FORBIDDEN_FIELD_CHARS:
        if c in value:
            raise ValueError(
                f"{name} must not contain newline, carriage return, or "
                f"null byte; these would create signing-payload ambiguity"
            )


def _canonical_payload(
    fingerprint: str,
    document_id: str,
    document_version: str,
    ingested_at: str,
    chunk_offset: int,
    chunk_length: int,
    entry_kind: str = ENTRY_KIND_WHOLE_CHUNK,
) -> bytes:
    """Build the canonical bytes that get HMAC'd for a fingerprint row.

    The canonicalization is deterministic: a fixed-order, newline-separated
    sequence of fields. Any change to field values produces a different MAC.
    Fields are validated to contain no newline / CR / null byte, so the
    join is unambiguous.

    v0.8.0: ``entry_kind`` is included in the payload so the
    whole-chunk-vs-window classification is tamper-evident; an attacker
    cannot flip ``window`` to ``whole_chunk`` (promoting a locator to
    VERIFIED-eligible) without invalidating the signature.
    """
    if entry_kind not in VALID_ENTRY_KINDS:
        raise ValueError(
            f"entry_kind must be one of {VALID_ENTRY_KINDS}, got "
            f"{entry_kind!r}"
        )
    _validate_signing_field("fingerprint", fingerprint)
    _validate_signing_field("document_id", document_id)
    _validate_signing_field("document_version", document_version)
    _validate_signing_field("ingested_at", ingested_at)
    return "\n".join(
        [
            fingerprint,
            document_id,
            document_version,
            ingested_at,
            str(chunk_offset),
            str(chunk_length),
            entry_kind,
        ]
    ).encode("utf-8")


def _sign(payload: bytes, secret: bytes) -> str:
    """HMAC-SHA256 a payload, returned as hex."""
    return hmac.new(secret, payload, sha256).hexdigest()


def _reduce_entry_to_outcome(
    entry: Optional[IndexEntry], secret: bytes
) -> VerificationOutcome:
    """Map an :class:`IndexEntry` to its :class:`VerificationOutcome`.

    Centralised so the per-row ``verify()`` path and the batched
    ``verify_batch()`` path apply identical rules: HMAC re-derivation,
    then the entry_kind / authorized / superseded ladder. Used by both
    the SQLite and Postgres backends (Postgres imports it).
    """
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
            entry_kind=entry.entry_kind,
        ),
        secret,
    )
    if not hmac.compare_digest(expected, entry.signature):
        return VerificationOutcome.TAMPERED
    if entry.entry_kind == ENTRY_KIND_WINDOW:
        if not entry.authorized:
            return VerificationOutcome.UNAUTHORIZED
        return VerificationOutcome.UNVERIFIED
    if not entry.authorized:
        return VerificationOutcome.UNAUTHORIZED
    if entry.superseded:
        return VerificationOutcome.STALE
    return VerificationOutcome.VERIFIED


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
            signing_secret = _resolve_index_secret()
        self._secret = signing_secret
        self._db_path = db_path
        # SQLite connections are not thread-safe across threads by default; we
        # serialize access through a lock and create the connection with
        # check_same_thread=False so a single connection can serve multiple
        # threads under the lock.
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # Enforce the FOREIGN KEY declared on fingerprints.document_id so a
        # fingerprint row cannot reference a missing document, and DELETE on
        # documents fails loudly while child fingerprints exist. SQLite has
        # FK enforcement off by default and the pragma is per-connection.
        self._conn.execute("PRAGMA foreign_keys = ON")
        with self._lock:
            self._refuse_legacy_schema()
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def _refuse_legacy_schema(self) -> None:
        """Fail fast if opening a pre-v0.8.0 index.

        v0.8.0 added ``entry_kind`` to the ``fingerprints`` table and to
        the canonical signing payload. An index created by an older
        Provenex version lacks the column; opening it under v0.8.0 code
        would either silently downgrade behavior (if we backfill with
        DEFAULT 'whole_chunk') or produce confusing TAMPERED outcomes
        on every row. The right behavior is to refuse to open it and
        tell the operator to re-ingest.
        """
        row = self._conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='fingerprints'"
        ).fetchone()
        if row is None:
            # Brand new DB; nothing to refuse.
            return
        cols = self._conn.execute(
            "PRAGMA table_info(fingerprints)"
        ).fetchall()
        names = {c["name"] for c in cols}
        if "entry_kind" not in names:
            raise RuntimeError(
                "This Provenex index was created by a pre-v0.8.0 release. "
                "v0.8.0 closed the window-aligned splice gap by adding an "
                "entry_kind column to the canonical signing payload, which "
                "is not present in this index. Re-ingest your documents "
                "with the v0.8.0 CLI / SDK against a fresh index to upgrade. "
                "(Path: " + self._db_path + ")"
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
                " chunk_offset, chunk_length, superseded, signature, "
                " entry_kind) "
                "VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
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
            self._conn.commit()

    # --------------------------------------------------------------- lookup

    def lookup(self, fingerprint: str) -> Optional[IndexEntry]:
        # Prefer a whole-chunk row over a window row when both exist for
        # the same fingerprint (rare but possible: an operator
        # explicitly ingested a chunk text that also happens to coincide
        # with one of the document's sliding-window offsets). The
        # whole-chunk row is the operator-authorized intent; verify()
        # can promote it to VERIFIED. Otherwise prefer non-superseded
        # then most-recently-ingested.
        with self._lock:
            row = self._conn.execute(
                "SELECT f.fingerprint, f.document_id, f.document_version, "
                "       f.ingested_at, f.chunk_offset, f.chunk_length, "
                "       f.superseded, f.signature, d.authorized, "
                "       f.entry_kind "
                "FROM fingerprints f "
                "JOIN documents d ON d.document_id = f.document_id "
                "WHERE f.fingerprint = ? "
                "ORDER BY CASE f.entry_kind WHEN 'whole_chunk' THEN 0 ELSE 1 END ASC, "
                "         f.superseded ASC, f.ingested_at DESC "
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
            entry_kind=row["entry_kind"],
        )

    # ------------------------------------------------------ set_authorization

    def set_authorization(self, document_id: str, authorized: bool) -> None:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE documents SET authorized = ? WHERE document_id = ?",
                (1 if authorized else 0, document_id),
            )
            if cur.rowcount == 0:
                # Silent no-op would let a typo'd revocation appear to succeed
                # while the real document remains authorized. Raise so the
                # caller has to acknowledge the missing-doc case explicitly.
                self._conn.rollback()
                raise KeyError(document_id)
            self._conn.commit()

    # ---------------------------------------------------------- supersede

    def supersede(self, document_id: str, new_version: str) -> int:
        with self._lock:
            doc_cur = self._conn.execute(
                "UPDATE documents SET current_version = ? WHERE document_id = ?",
                (new_version, document_id),
            )
            if doc_cur.rowcount == 0:
                self._conn.rollback()
                raise KeyError(document_id)
            cur = self._conn.execute(
                "UPDATE fingerprints SET superseded = 1 "
                "WHERE document_id = ? AND document_version != ?",
                (document_id, new_version),
            )
            self._conn.commit()
            return cur.rowcount

    # -------------------------------------------------- tombstones (purged)

    def mark_purged(
        self,
        fingerprint: str,
        *,
        at: str | None = None,
        receipt_ref: str | None = None,
    ) -> None:
        with self._lock:
            exists = self._conn.execute(
                "SELECT 1 FROM fingerprints WHERE fingerprint = ? LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if exists is None:
                raise KeyError(fingerprint)
            self._conn.execute(
                "INSERT OR REPLACE INTO purged_fingerprints "
                "(fingerprint, purged_at, receipt_ref) VALUES (?, ?, ?)",
                (fingerprint, at or _now_utc_iso(), receipt_ref),
            )
            self._conn.commit()

    def purged_info(self, fingerprint: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT purged_at, receipt_ref FROM purged_fingerprints "
                "WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        return {"purged_at": row["purged_at"], "receipt_ref": row["receipt_ref"]}

    def _purged_set(self, fingerprints: Sequence[str]) -> set:
        if not fingerprints:
            return set()
        placeholders = ",".join("?" * len(fingerprints))
        with self._lock:
            rows = self._conn.execute(
                "SELECT fingerprint FROM purged_fingerprints "
                f"WHERE fingerprint IN ({placeholders})",
                list(fingerprints),
            ).fetchall()
        return {r["fingerprint"] for r in rows}

    def _outcome(self, entry: Optional[IndexEntry], purged: bool) -> VerificationOutcome:
        outcome = _reduce_entry_to_outcome(entry, self._secret)
        # A validly-signed row with a tombstone is PURGED. TAMPERED still
        # wins: a forged row must not hide behind a purge record.
        if purged and entry is not None and outcome != VerificationOutcome.TAMPERED:
            return VerificationOutcome.PURGED
        return outcome

    def entries_for_document(self, document_id: str) -> List[IndexEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT f.fingerprint, f.document_id, f.document_version, "
                "       f.ingested_at, f.chunk_offset, f.chunk_length, "
                "       f.superseded, f.signature, d.authorized, "
                "       f.entry_kind "
                "FROM fingerprints f "
                "JOIN documents d ON d.document_id = f.document_id "
                "WHERE f.document_id = ? AND f.superseded = 0 "
                "ORDER BY f.chunk_offset, f.fingerprint",
                (document_id,),
            ).fetchall()
        return [
            IndexEntry(
                fingerprint=r["fingerprint"],
                document_id=r["document_id"],
                document_version=r["document_version"],
                ingested_at=r["ingested_at"],
                chunk_offset=r["chunk_offset"],
                chunk_length=r["chunk_length"],
                authorized=bool(r["authorized"]),
                superseded=bool(r["superseded"]),
                signature=r["signature"],
                entry_kind=r["entry_kind"],
            )
            for r in rows
        ]

    # ----------------------------------------------------------- verify

    def verify(self, fingerprint: str) -> VerificationOutcome:
        entry = self.lookup(fingerprint)
        return self._outcome(entry, fingerprint in self._purged_set([fingerprint]))

    # ------------------------------------------------------- verify_batch

    def verify_batch(
        self,
        fingerprints: Sequence[str],
    ) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
        """One ``WHERE fingerprint IN (...)`` query instead of N round-trips.

        Selection rule mirrors :meth:`lookup` exactly: prefer whole-chunk
        over window, then non-superseded, then most-recently-ingested. The
        HMAC check and the entry_kind / authorized / superseded reduction
        then run locally per fingerprint, identical to :meth:`verify`.

        Duplicates in the input list yield duplicate outputs without
        re-querying. An empty input list short-circuits with no SQL.
        """
        if not fingerprints:
            return []
        # DISTINCT keeps the IN-list small when the caller passes
        # duplicates; we rebuild per-input-position output below.
        unique = list(dict.fromkeys(fingerprints))
        placeholders = ",".join("?" * len(unique))
        with self._lock:
            rows = self._conn.execute(
                "SELECT f.fingerprint, f.document_id, f.document_version, "
                "       f.ingested_at, f.chunk_offset, f.chunk_length, "
                "       f.superseded, f.signature, d.authorized, "
                "       f.entry_kind "
                "FROM fingerprints f "
                "JOIN documents d ON d.document_id = f.document_id "
                f"WHERE f.fingerprint IN ({placeholders}) "
                "ORDER BY f.fingerprint, "
                "         CASE f.entry_kind WHEN 'whole_chunk' THEN 0 ELSE 1 END ASC, "
                "         f.superseded ASC, f.ingested_at DESC",
                unique,
            ).fetchall()

        # Keep the first row per fingerprint after the ORDER BY — that's
        # the preferred candidate, matching lookup()'s LIMIT 1 semantics.
        preferred: dict[str, IndexEntry] = {}
        for row in rows:
            fp = row["fingerprint"]
            if fp in preferred:
                continue
            preferred[fp] = IndexEntry(
                fingerprint=fp,
                document_id=row["document_id"],
                document_version=row["document_version"],
                ingested_at=row["ingested_at"],
                chunk_offset=row["chunk_offset"],
                chunk_length=row["chunk_length"],
                authorized=bool(row["authorized"]),
                superseded=bool(row["superseded"]),
                signature=row["signature"],
                entry_kind=row["entry_kind"],
            )

        purged = self._purged_set(unique)
        out: List[Tuple[VerificationOutcome, Optional[IndexEntry]]] = []
        for fp in fingerprints:
            entry = preferred.get(fp)
            out.append((self._outcome(entry, fp in purged), entry))
        return out

    # ----------------------------------------------------------- close

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SQLiteProvenanceIndex":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
