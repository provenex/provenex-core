"""LlamaIndex ingestor: register documents into a provenance index.

Mirrors :class:`provenex.integrations.langchain.ProvenexIngestor` exactly,
differing only in how text is pulled out of the input objects. LlamaIndex
``Document`` and ``TextNode`` expose ``.text`` (and ``.get_content()`` on
node types) rather than LangChain's ``.page_content``.

Existing vector stores (Pinecone, Weaviate, Milvus, FAISS, Chroma, ...)
are not touched. Provenex runs alongside them as a parallel signed
index. The vector store keeps doing semantic similarity; Provenex
provides cryptographic identity.
"""

from __future__ import annotations

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
    """Fingerprints LlamaIndex documents/nodes and writes them to a provenance index.

    Args:
        index: The provenance index to write to.
        fingerprinter: Optional :class:`Fingerprinter`. Must match the
            configuration used at verification time, or retrieved chunks
            will appear UNVERIFIED.

    Example:
        >>> from llama_index.core import Document
        >>> index = SQLiteProvenanceIndex("provenance.db")
        >>> ingestor = ProvenexIngestor(index=index)
        >>> ingestor.ingest(
        ...     [Document(text="...")],
        ...     doc_id="policy_v4",
        ...     authorized=True,
        ... )
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
        """Pull text from a LlamaIndex Document, TextNode, or string.

        LlamaIndex's BaseNode exposes ``get_content()`` which is the most
        thorough accessor (handles metadata-embedding modes). Document and
        TextNode also expose plain ``.text``. We try ``get_content`` first
        because it's the most reliable on rich node types, then fall back
        to ``.text``, then to raw strings for the test path.
        """
        if hasattr(document, "get_content"):
            try:
                return document.get_content()
            except TypeError:
                # Some node types require a `metadata_mode` argument. The
                # default is fine for our purposes, but if a stub or older
                # version doesn't accept it, fall through.
                pass
        if hasattr(document, "text"):
            return document.text
        if isinstance(document, str):
            return document
        raise TypeError(
            "Cannot extract text: expected a LlamaIndex Document/TextNode "
            "(with .get_content() or .text) or a string"
        )

    def ingest(
        self,
        documents: Iterable[Any],
        doc_id: str,
        authorized: bool = True,
    ) -> IngestionResult:
        """Ingest a collection of LlamaIndex documents under a single document ID.

        All input chunks are treated as belonging to the same logical
        document. Two semantics are supported and produce identical
        receipts:

            * Pass the whole document as one element of ``documents`` and
              let the sliding-window fingerprinter chunk it.
            * Pass pre-chunked nodes (e.g. from ``SentenceSplitter`` or
              ``TokenTextSplitter``) and the ingestor will fingerprint
              each chunk as-is using the same window function.

        Args:
            documents: Iterable of LlamaIndex ``Document`` or ``TextNode``
                objects (or strings, or any object with ``.text`` /
                ``.get_content()``).
            doc_id: Stable identifier for the logical document. Re-ingesting
                with the same ``doc_id`` and different content marks the
                older fingerprints as superseded.
            authorized: Initial authorization state. Default True.

        Returns:
            An :class:`IngestionResult` summarizing what was written.
        """
        docs: List[Any] = list(documents)
        joined = "\n".join(self._document_text(d) for d in docs)
        full_result = self._fingerprinter.fingerprint(joined)
        document_version = full_result.document_version
        total = 0

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

            # Sliding windows let verification succeed even when the
            # retriever returns chunks that have been further re-chunked
            # or trimmed downstream.
            per_chunk = self._fingerprinter.fingerprint(text)
            for fp in per_chunk.fingerprints:
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
