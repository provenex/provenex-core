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
from typing import Optional


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

        Raises:
            ValueError: If the fingerprint or document version is malformed.
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

                * UNVERIFIED — fingerprint not in index
                * TAMPERED — fingerprint in index but signature check failed
                * UNAUTHORIZED — fingerprint in index, signature ok, but
                  document_id is not authorized
                * STALE — fingerprint in index, signature ok, authorized, but
                  the document version has been superseded
                * VERIFIED — all checks pass
        """

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the index (file handles, sockets)."""
