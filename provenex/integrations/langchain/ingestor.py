"""LangChain ingestor: register documents into a provenance index.

The ingestor takes LangChain ``Document`` objects (or any duck-typed
equivalent with ``page_content`` and ``metadata`` attributes), fingerprints
each one using the configured :class:`Fingerprinter`, and writes the
fingerprints to a :class:`ProvenanceIndex`.

Existing vector stores (Chroma, FAISS, Pinecone, Weaviate, etc.) are not
touched — Provenex runs alongside them as a parallel signed index. The vector
store keeps doing semantic similarity; Provenex provides cryptographic
identity.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional

from ...core.fingerprinter import Fingerprinter, FingerprinterConfig
from ...index.base import ProvenanceIndex


@dataclass
class IngestionResult:
    """Summary of an ingestion call.

    Attributes:
        document_id: The document ID that was ingested.
        document_version: The SHA-256 over the normalized full document text.
        fingerprint_count: Total fingerprints written.
        chunk_count: Number of input chunks that were processed.
    """

    document_id: str
    document_version: str
    fingerprint_count: int
    chunk_count: int


class ProvenexIngestor:
    """Fingerprints LangChain documents and writes them to a provenance index.

    Args:
        index: The provenance index to write to.
        fingerprinter: Optional :class:`Fingerprinter`. Must match the
            configuration used at verification time, or retrieved chunks will
            appear UNVERIFIED.

    Example:
        >>> index = SQLiteProvenanceIndex("provenance.db")
        >>> ingestor = ProvenexIngestor(index=index)
        >>> ingestor.ingest(documents, doc_id="policy_v4", authorized=True)
    """

    def __init__(
        self,
        index: ProvenanceIndex,
        fingerprinter: Optional[Fingerprinter] = None,
    ) -> None:
        self._index = index
        self._fingerprinter = fingerprinter or Fingerprinter(FingerprinterConfig())

    @staticmethod
    def _document_text(document: Any) -> str:
        """Extract text from a LangChain Document or string."""
        if hasattr(document, "page_content"):
            return document.page_content
        if isinstance(document, str):
            return document
        raise TypeError(
            "Cannot extract text: expected a LangChain Document or string"
        )

    def ingest(
        self,
        documents: Iterable[Any],
        doc_id: str,
        authorized: bool = True,
    ) -> IngestionResult:
        """Ingest a collection of LangChain documents under a single document ID.

        All input chunks are treated as belonging to the same logical
        document. Two semantics are supported and produce identical receipts:

            * Pass the whole document as one element of ``documents`` and
              let the sliding-window fingerprinter chunk it.
            * Pass pre-chunked documents (e.g. from
              ``RecursiveCharacterTextSplitter``) and the ingestor will
              fingerprint each chunk as-is using the same window function.

        Args:
            documents: Iterable of LangChain ``Document`` objects (or
                strings, or any object with ``page_content``).
            doc_id: Stable identifier for the logical document. Re-ingesting
                with the same ``doc_id`` and a different content hash marks
                the older fingerprints as superseded.
            authorized: Initial authorization state. Default True.

        Returns:
            An :class:`IngestionResult` summarizing what was written.
        """
        docs: List[Any] = list(documents)
        # Build full normalized text by joining chunk contents with a single
        # newline. The document_version hash is computed over this normalized
        # join so it's stable across re-chunking.
        joined = "\n".join(self._document_text(d) for d in docs)
        full_result = self._fingerprinter.fingerprint(joined)

        document_version = full_result.document_version
        total = 0

        # For storage, fingerprint each chunk individually so that retrieval
        # at query time (which sees chunk-sized text from the vector store)
        # produces matching fingerprints.
        for chunk in docs:
            text = self._document_text(chunk)
            chunk_fp = self._fingerprinter.fingerprint_chunk(text)
            chunk_length = len(text)
            self._index.add(
                fingerprint=chunk_fp,
                document_id=doc_id,
                document_version=document_version,
                chunk_offset=0,
                chunk_length=chunk_length,
                authorized=authorized,
            )
            total += 1

            # Also store the sliding-window fingerprints. These let
            # verification succeed even when the retriever returns text that
            # was further re-chunked or trimmed, as long as a window of W
            # consecutive characters matches.
            per_chunk = self._fingerprinter.fingerprint(text)
            for fp in per_chunk.fingerprints:
                # Avoid writing the same fingerprint twice in this loop.
                if fp.fingerprint == chunk_fp:
                    continue
                self._index.add(
                    fingerprint=fp.fingerprint,
                    document_id=doc_id,
                    document_version=document_version,
                    chunk_offset=fp.offset,
                    chunk_length=fp.length,
                    authorized=authorized,
                )
                total += 1

        return IngestionResult(
            document_id=doc_id,
            document_version=document_version,
            fingerprint_count=total,
            chunk_count=len(docs),
        )
