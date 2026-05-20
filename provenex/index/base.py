"""Abstract base class for the provenance index.

The provenance index stores fingerprint -> document metadata mappings. It is
the single component that has different implementations across the open
source / commercial split:

    - :class:`provenex.index.sqlite_index.SQLiteProvenanceIndex` is the open
      source local-file implementation. Suitable for development, single-node
      deployments, and self-hosted use.

    - The Provenex commercial hosted index (not in this repo) implements the
      same interface against a distributed, signed, append-only backend with
      Bloom filter acceleration and cross-enterprise provenance graph
      features.

Because both implementations share this interface, switching from open source
to commercial requires changing one line — the class you instantiate.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Protocol, Sequence, Tuple, runtime_checkable


class VerificationOutcome(str, Enum):
    """The five verification outcomes for a retrieved chunk.

    Values are stable strings (the enum is a ``str`` subclass) so they can be
    serialized directly to JSON on the provenance receipt.
    """

    VERIFIED = "VERIFIED"
    """Chunk present in the index, document current and authorized."""

    STALE = "STALE"
    """Chunk present but the document version has been superseded."""

    UNAUTHORIZED = "UNAUTHORIZED"
    """Chunk present but the document is not authorized for this context."""

    UNVERIFIED = "UNVERIFIED"
    """Chunk fingerprint not found in the index (not ingested via Provenex)."""

    TAMPERED = "TAMPERED"
    """Fingerprint found but its stored metadata signature fails verification."""


# Schema 2.4.0 / v0.8.0: index entries are tagged with a "kind". Only
# ``whole_chunk`` entries are eligible for promotion to VERIFIED at
# verify time; ``window`` entries (sliding-window fingerprints written
# during ingest) are retained for structural locating only and never
# promote on a whole-chunk SHA-256 match. This closes the
# window-aligned splice gap: a 128-codepoint substring of an authorized
# document is no longer a VERIFIED chunk on its own.
ENTRY_KIND_WHOLE_CHUNK = "whole_chunk"
ENTRY_KIND_WINDOW = "window"
VALID_ENTRY_KINDS = (ENTRY_KIND_WHOLE_CHUNK, ENTRY_KIND_WINDOW)


# Schema 2.4.0 / v0.8.0: explicit precedence so an auditor reading a
# denied chunk knows which condition shadowed which when multiple
# could apply. Higher-precedence outcomes mask lower ones. UNVERIFIED
# is the absent-entry sentinel and only applies when no row matched.
# Read as a left-to-right priority list: TAMPERED beats UNAUTHORIZED
# beats STALE beats VERIFIED for a row that exists; UNVERIFIED is the
# fall-through for a row that does not.
OUTCOME_PRECEDENCE = (
    VerificationOutcome.TAMPERED,
    VerificationOutcome.UNAUTHORIZED,
    VerificationOutcome.STALE,
    VerificationOutcome.UNVERIFIED,
    VerificationOutcome.VERIFIED,
)


def reduce_outcomes(candidates) -> VerificationOutcome:
    """Pick the highest-precedence outcome from a set of candidates.

    Used by ``verify()`` implementations and exposed publicly so any
    caller can reason about the precedence the same way the engine
    does. Returns VERIFIED if no candidates are passed (the "all clear"
    default), which is the right neutral element because adding more
    candidates can only lower the result.
    """
    cs = set(candidates)
    for outcome in OUTCOME_PRECEDENCE:
        if outcome in cs:
            return outcome
    return VerificationOutcome.VERIFIED


@dataclass(frozen=True)
class IndexEntry:
    """A single row in the provenance index.

    Attributes:
        fingerprint: The SHA-256 fingerprint string (``"sha256:<hex>"``).
        document_id: Stable identifier for the source document (caller-chosen).
        document_version: SHA-256 over the normalized document content. When a
            document is re-ingested with edits, the version changes.
        ingested_at: ISO-8601 UTC timestamp of when this fingerprint was
            written to the index.
        chunk_offset: Character offset of the chunk within the normalized
            document.
        chunk_length: Length of the chunk in characters.
        authorized: Whether this document is currently authorized for
            retrieval.
        superseded: Whether this fingerprint's document version has been
            superseded by a newer version. (In the open source core this is
            set by re-ingestion of the same document_id; the commercial
            version supports richer supersession graphs.)
        signature: HMAC-SHA256 over a canonical serialization of the other
            fields, keyed by the index's signing secret. Used to detect
            tampering with the index itself.
        entry_kind: One of :data:`ENTRY_KIND_WHOLE_CHUNK` or
            :data:`ENTRY_KIND_WINDOW` (schema 2.4.0 / v0.8.0). Whole-chunk
            entries are the operator-authorized chunk texts; only they
            are eligible for promotion to ``VERIFIED`` at verify time.
            Window entries are sliding-window fingerprints written during
            document ingestion for structural locating; they NEVER
            promote to VERIFIED on a whole-chunk SHA-256 match. The
            field is covered by ``signature`` so it is tamper-evident.
    """

    fingerprint: str
    document_id: str
    document_version: str
    ingested_at: str
    chunk_offset: int
    chunk_length: int
    authorized: bool
    superseded: bool
    signature: str
    entry_kind: str = ENTRY_KIND_WHOLE_CHUNK


class ProvenanceIndex(ABC):
    """Abstract interface for fingerprint storage and lookup.

    Implementations MUST:

        1. Reject writes for fingerprints that already exist with conflicting
           document_id (the same fingerprint MAY be associated with the same
           document_id more than once — that's just re-ingestion).
        2. Sign each entry on write using HMAC-SHA256 over a canonical
           serialization, keyed by an implementation-provided secret. The
           signature is checked on lookup to detect tampering.
        3. Maintain authorization state per (document_id) so that
           :meth:`set_authorization` can toggle it without rewriting
           fingerprints.
        4. Mark old fingerprints as superseded when a new version of the same
           ``document_id`` is added.

    Implementations MAY add additional features (Bloom filter pre-checks,
    distributed replication, signed audit logs, etc.) as long as the four
    requirements above are preserved.
    """

    @abstractmethod
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
        """Insert a fingerprint into the index.

        Args:
            fingerprint: The SHA-256 fingerprint string.
            document_id: Stable identifier for the source document.
            document_version: SHA-256 over the normalized document content.
            chunk_offset: Character offset of the chunk in the normalized
                document.
            chunk_length: Chunk length in characters.
            authorized: Initial authorization state for the chunk's document.
                Applied to the document_id; subsequent calls with the same
                document_id will use the latest authorization state.
            entry_kind: ``ENTRY_KIND_WHOLE_CHUNK`` (default) or
                ``ENTRY_KIND_WINDOW``. The default is whole-chunk: any
                caller adding an operator-authorized chunk gets the
                VERIFIED-eligible behavior. The ``window`` kind is for
                sliding-window fingerprints written during document
                ingestion to support structural locating; window entries
                NEVER promote to VERIFIED at verify time, regardless of
                whether their hash matches a chunk's whole-chunk SHA-256.

        Raises:
            ValueError: If the fingerprint or document version is malformed,
                or if ``entry_kind`` is not one of the allowed values.
        """

    @abstractmethod
    def lookup(self, fingerprint: str) -> Optional[IndexEntry]:
        """Look up the most recent (non-superseded) entry for a fingerprint.

        Args:
            fingerprint: The SHA-256 fingerprint string to look up.

        Returns:
            The matching :class:`IndexEntry`, or ``None`` if not present.

        Note:
            If the same fingerprint appears for multiple document versions
            (rare but possible — e.g. an unchanged passage in an updated
            document), the non-superseded entry is returned.
        """

    @abstractmethod
    def set_authorization(self, document_id: str, authorized: bool) -> None:
        """Toggle authorization for all fingerprints of a document.

        Args:
            document_id: The document whose authorization state should change.
            authorized: New authorization state.
        """

    @abstractmethod
    def supersede(self, document_id: str, new_version: str) -> int:
        """Mark all fingerprints of older versions of a document as superseded.

        Args:
            document_id: The document being re-ingested.
            new_version: The new document version hash. All entries with this
                document_id but a different version will be marked superseded.

        Returns:
            The number of entries marked as superseded.
        """

    @abstractmethod
    def verify(self, fingerprint: str) -> VerificationOutcome:
        """Verify a fingerprint and return the verification outcome.

        Args:
            fingerprint: The SHA-256 fingerprint string to verify.

        Returns:
            One of :class:`VerificationOutcome`. The mapping is:

                * UNVERIFIED - fingerprint not in index, OR the only
                  matching row is a window (locator-only) entry. A
                  window entry CANNOT promote a chunk to VERIFIED
                  even if its hash matches the chunk's whole-chunk
                  SHA-256; window fingerprints are for structural
                  locating only.
                * TAMPERED - fingerprint in index (whole-chunk entry)
                  but signature check failed.
                * UNAUTHORIZED - fingerprint in index, signature ok,
                  but document_id is not authorized.
                * STALE - fingerprint in index, signature ok,
                  authorized, but the document version has been
                  superseded.
                * VERIFIED - all checks pass AND the matching row
                  is a whole-chunk entry.

            Precedence among outcomes that could apply simultaneously
            is fixed by :data:`OUTCOME_PRECEDENCE` (TAMPERED >
            UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED).
        """

    def verify_batch(
        self,
        fingerprints: Sequence[str],
    ) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
        """Verify many fingerprints in one call.

        Returns ``[(outcome, entry), ...]`` aligned with the input order.
        ``entry`` is the matched row (or ``None`` for an UNVERIFIED
        no-row case); for UNVERIFIED window-locator matches and
        TAMPERED rows, the entry IS still returned so the caller can
        record the locator metadata on the receipt.

        The default implementation loops :meth:`verify` and :meth:`lookup`
        sequentially - correct for every backend, but pays one round-trip
        per fingerprint. Backends override this when a single multi-key
        query is meaningfully cheaper (SQLite ``IN (...)`` / Postgres
        ``WHERE fingerprint = ANY(%s)``).

        Args:
            fingerprints: Sequence of ``"sha256:<hex>"`` strings. The same
                fingerprint MAY appear more than once; each occurrence
                yields its own entry in the output.

        Returns:
            One ``(outcome, entry)`` tuple per input fingerprint, in
            input order.
        """
        return [(self.verify(fp), self.lookup(fp)) for fp in fingerprints]

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the index (file handles, sockets)."""


@runtime_checkable
class AsyncProvenanceIndex(Protocol):
    """Structural counterpart of :class:`ProvenanceIndex` for asyncio callers.

    Mirrors the sync interface method-for-method, with ``_async`` suffix
    and ``await``-able semantics. A concrete implementation
    (:class:`provenex.index.async_postgres_index.AsyncPostgresProvenanceIndex`)
    wraps ``psycopg.AsyncConnection`` so a FastAPI / Starlette / aiohttp
    handler can call into the verify path without blocking the event loop.

    This is a :class:`typing.Protocol`, not an ABC, so any class with the
    right method signatures is accepted. The hot path used by
    :func:`provenex.verify_chunks_async` consults only
    ``verify_batch_async``; the other methods exist so async ingest and
    operator code paths have a complete async surface.

    All async methods carry the same contract as their sync counterparts
    in :class:`ProvenanceIndex`. Same five outcomes; same precedence;
    same canonical signing payload (so a receipt produced via the async
    path verifies bit-identically against a sync-backed verifier).
    """

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
        ...

    async def lookup_async(self, fingerprint: str) -> Optional[IndexEntry]:
        ...

    async def set_authorization_async(
        self, document_id: str, authorized: bool
    ) -> None:
        ...

    async def supersede_async(self, document_id: str, new_version: str) -> int:
        ...

    async def verify_async(self, fingerprint: str) -> VerificationOutcome:
        ...

    async def verify_batch_async(
        self,
        fingerprints: Sequence[str],
    ) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
        ...

    async def close_async(self) -> None:
        ...
