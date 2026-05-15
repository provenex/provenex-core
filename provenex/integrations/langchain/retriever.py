"""LangChain retriever middleware.

Wraps any existing LangChain retriever, transparently verifies every retrieved
chunk against a :class:`ProvenanceIndex`, applies a policy, and produces a
signed provenance receipt alongside the retrieved documents.

LangChain is an optional dependency. This module imports it lazily so the rest
of provenex-core works without it installed.

Drop-in usage with an existing pipeline:

    from provenex.integrations.langchain import ProvenexRetriever
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    index = SQLiteProvenanceIndex("provenance.db")
    retriever = ProvenexRetriever(base_retriever=your_existing_retriever, index=index)
    result = retriever.get_relevant_documents_with_receipt("your query")
    print(result.receipt.to_json())
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from ...core.fingerprinter import Fingerprinter, FingerprinterConfig
from ...core.receipt import ProvenanceReceipt, ReceiptBuilder, ReceiptSigner
from ...core.trajectory import TrajectoryContext
from ...index.base import ProvenanceIndex
from ...policy.policy import VerificationPolicy


@dataclass
class RetrievalResult:
    """The output of a Provenex-wrapped retrieval call.

    Attributes:
        documents: The retrieved LangChain documents, with any policy-blocked
            chunks already removed.
        blocked: The documents that were retrieved but removed by policy.
            Surfaced so the caller can log them or surface them in a UI.
        receipt: The signed provenance receipt covering ALL retrieved chunks
            (both kept and blocked), so the receipt is a complete record.
    """

    documents: List[Any]
    blocked: List[Any]
    receipt: ProvenanceReceipt


class ProvenexRetriever:
    """LangChain retriever wrapper that verifies chunks and emits receipts.

    Args:
        base_retriever: Any LangChain retriever (BaseRetriever subclass). The
            wrapper delegates retrieval to it untouched and then verifies the
            results.
        index: The provenance index to verify against.
        policy: Verification policy. Defaults to a sensible production policy
            (block unauthorized, flag everything).
        signer: Optional :class:`ReceiptSigner`. If ``None``, receipts are
            unsigned. Production deployments should always provide a signer.
        fingerprinter: Optional :class:`Fingerprinter`. Must match the
            configuration used at ingestion time, otherwise fingerprints will
            not match and every chunk will appear UNVERIFIED.

    Example:
        >>> retriever = ProvenexRetriever(
        ...     base_retriever=chroma_retriever,
        ...     index=index,
        ...     policy=VerificationPolicy(block_stale=True),
        ...     signer=HmacSha256Signer(),
        ... )
        >>> result = retriever.get_relevant_documents_with_receipt("question")
        >>> result.receipt.summary["overall_status"]
        'PASS'
    """

    def __init__(
        self,
        base_retriever: Any,
        index: ProvenanceIndex,
        policy: Optional[VerificationPolicy] = None,
        signer: Optional[ReceiptSigner] = None,
        fingerprinter: Optional[Fingerprinter] = None,
        sink: Any = None,
    ) -> None:
        self._base_retriever = base_retriever
        self._index = index
        self._policy = policy or VerificationPolicy()
        self._signer = signer
        self._fingerprinter = fingerprinter or Fingerprinter(FingerprinterConfig())
        self._sink = sink

    @property
    def base_retriever(self) -> Any:
        """The underlying LangChain retriever this wraps."""
        return self._base_retriever

    def _retrieve(self, query: str) -> List[Any]:
        """Call the underlying retriever using whichever API it exposes.

        LangChain has had a few generations of retriever APIs. We try them in
        order of recency.
        """
        # New-style runnable interface (LangChain 0.1+): invoke()
        if hasattr(self._base_retriever, "invoke"):
            try:
                return list(self._base_retriever.invoke(query))
            except TypeError:
                pass
        # Classic interface: get_relevant_documents()
        if hasattr(self._base_retriever, "get_relevant_documents"):
            return list(self._base_retriever.get_relevant_documents(query))
        raise TypeError(
            "base_retriever does not expose a recognized LangChain retrieval "
            "method (invoke() or get_relevant_documents())"
        )

    @staticmethod
    def _document_text(document: Any) -> str:
        """Extract the chunk text from a LangChain Document (or duck-typed equivalent)."""
        # LangChain Documents have a .page_content attribute.
        if hasattr(document, "page_content"):
            return document.page_content
        # Allow raw strings for tests / simple usage.
        if isinstance(document, str):
            return document
        raise TypeError(
            "Cannot extract text from retrieved object: expected a LangChain "
            "Document with .page_content or a string"
        )

    def get_relevant_documents_with_receipt(
        self,
        query: str,
        output_text: str = "",
        trajectory: Optional[TrajectoryContext] = None,
        step_kind: str = "retrieval",
        agent_id: Optional[str] = None,
    ) -> RetrievalResult:
        """Retrieve documents, verify them, apply policy, and produce a receipt.

        Args:
            query: The retrieval query string, passed through to the base
                retriever unchanged.
            output_text: The LLM output text, if available. Its SHA-256 hash
                is recorded on the receipt. Pass ``""`` if the receipt is
                being generated before inference (the hash field will still
                be filled — a hash of the empty string — and can be updated
                later by regenerating the receipt with the actual output).
            trajectory: Optional :class:`TrajectoryContext` linking this
                retrieval call into a multi-step agent trajectory. Use
                :func:`provenex.core.trajectory.start_trajectory` to allocate
                a fresh trajectory; chain successive calls via
                ``trajectory.next_step(parent_receipts=[prev])``. See
                RFC-0003 for the trajectory schema.
            step_kind: Trajectory ``step_kind`` recorded on the emitted
                receipt. Defaults to ``"retrieval"`` — a retriever's
                receipts are retrieval steps, by definition. Override
                per-call when the same retriever is reused for a
                different trajectory shape (e.g. ``"memory_read"``).
            agent_id: Optional agent identifier override for this call.
                When supplied, overrides whatever ``trajectory.agent_id``
                was on the cursor.

        Returns:
            A :class:`RetrievalResult` containing kept documents, blocked
            documents, and the signed receipt covering both sets.
        """
        retrieved = self._retrieve(query)
        builder = ReceiptBuilder(policy=self._policy)

        kept: List[Any] = []
        blocked: List[Any] = []

        for doc in retrieved:
            text = self._document_text(doc)
            fingerprint = self._fingerprinter.fingerprint_chunk(text)
            outcome = self._index.verify(fingerprint)
            entry = self._index.lookup(fingerprint)

            builder.add_source(
                fingerprint=fingerprint,
                outcome=outcome,
                entry=entry,
                normalization_applied=list(
                    self._fingerprinter.fingerprint(text).normalization_applied
                ),
            )

            if self._policy.should_block(outcome):
                blocked.append(doc)
            else:
                kept.append(doc)

        # When a trajectory is supplied, stamp step_kind / agent_id onto
        # it for this emission. Mirrors ``verify_chunks(step_kind=...)``.
        # Without a trajectory there is no trajectory block on the
        # receipt to label; step_kind is a per-trajectory-step concept.
        emit_trajectory: Optional[TrajectoryContext] = trajectory
        if trajectory is not None:
            emit_trajectory = TrajectoryContext(
                trajectory_id=trajectory.trajectory_id,
                step_index=trajectory.step_index,
                trajectory_started_at=trajectory.trajectory_started_at,
                parent_step_ids=trajectory.parent_step_ids,
                step_kind=step_kind,
                agent_id=agent_id if agent_id is not None else trajectory.agent_id,
            )

        receipt = builder.finalize(
            output_text=output_text,
            signer=self._signer,
            trajectory=emit_trajectory,
        )
        from ...export.streaming import _safe_publish

        _safe_publish(self._sink, receipt)
        return RetrievalResult(documents=kept, blocked=blocked, receipt=receipt)

    # Convenience alias matching the classic LangChain retriever API. Returns
    # only the kept documents; receipts are not surfaced.
    def get_relevant_documents(self, query: str) -> List[Any]:
        """Alias that returns only kept documents (LangChain-compatible signature).

        For most production use you should call
        :meth:`get_relevant_documents_with_receipt` instead, which surfaces
        the receipt.
        """
        return self.get_relevant_documents_with_receipt(query).documents
