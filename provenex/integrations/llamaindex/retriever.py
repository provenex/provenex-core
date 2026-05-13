"""LlamaIndex retriever middleware.

Wraps any existing LlamaIndex retriever, verifies every retrieved node
against a :class:`ProvenanceIndex`, applies a policy, and produces a
signed provenance receipt alongside the retrieved nodes.

LlamaIndex is an optional dependency. This module duck-types the
``BaseRetriever`` and ``NodeWithScore`` interfaces so it can be imported
and tested without LlamaIndex installed.

Drop-in usage inside an existing LlamaIndex pipeline:

    from provenex.integrations.llamaindex import ProvenexRetriever
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    index = SQLiteProvenanceIndex("provenance.db")
    retriever = ProvenexRetriever(
        base_retriever=your_vector_index.as_retriever(),
        index=index,
    )
    result = retriever.retrieve_with_receipt("your query")
    print(result.receipt.to_json())
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from ...core.fingerprinter import Fingerprinter, FingerprinterConfig
from ...core.receipt import ProvenanceReceipt, ReceiptBuilder, ReceiptSigner
from ...index.base import ProvenanceIndex
from ...policy.policy import VerificationPolicy


@dataclass
class RetrievalResult:
    """The output of a Provenex-wrapped LlamaIndex retrieval call.

    Attributes:
        nodes: The retrieved nodes (typically ``NodeWithScore`` instances),
            with any policy-blocked nodes already removed.
        blocked: The nodes that were retrieved but removed by policy.
            Surfaced so the caller can log them or display them in a UI.
        receipt: The signed provenance receipt covering ALL retrieved
            chunks (kept and blocked), so the receipt is a complete record.
    """

    nodes: List[Any]
    blocked: List[Any]
    receipt: ProvenanceReceipt


class ProvenexRetriever:
    """LlamaIndex retriever wrapper that verifies nodes and emits receipts.

    Args:
        base_retriever: Any LlamaIndex retriever (BaseRetriever subclass).
            The wrapper delegates retrieval to it untouched and then
            verifies the results.
        index: The provenance index to verify against.
        policy: Verification policy. Defaults to a sensible production
            policy (block unauthorized, flag everything).
        signer: Optional :class:`ReceiptSigner`. If ``None``, receipts are
            unsigned. Production deployments should always provide one.
        fingerprinter: Optional :class:`Fingerprinter`. Must match the
            configuration used at ingestion time, otherwise fingerprints
            will not match and every chunk will appear UNVERIFIED.

    Example:
        >>> retriever = ProvenexRetriever(
        ...     base_retriever=vector_index.as_retriever(similarity_top_k=3),
        ...     index=index,
        ...     policy=VerificationPolicy(block_stale=True),
        ...     signer=HmacSha256Signer(),
        ... )
        >>> result = retriever.retrieve_with_receipt("question")
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
    ) -> None:
        self._base_retriever = base_retriever
        self._index = index
        self._policy = policy or VerificationPolicy()
        self._signer = signer
        self._fingerprinter = fingerprinter or Fingerprinter(FingerprinterConfig())

    @property
    def base_retriever(self) -> Any:
        """The underlying LlamaIndex retriever this wraps."""
        return self._base_retriever

    def _retrieve(self, query: str) -> List[Any]:
        """Call the underlying retriever and return its nodes.

        LlamaIndex's BaseRetriever exposes ``retrieve(str_or_query_bundle)``.
        We pass through the raw string; LlamaIndex wraps it in a
        ``QueryBundle`` internally.
        """
        if hasattr(self._base_retriever, "retrieve"):
            return list(self._base_retriever.retrieve(query))
        raise TypeError(
            "base_retriever does not expose a recognized LlamaIndex "
            "retrieval method (.retrieve())"
        )

    @staticmethod
    def _node_text(item: Any) -> str:
        """Extract the chunk text from a LlamaIndex node or NodeWithScore.

        Handles three shapes:
            * ``NodeWithScore`` — unwrap ``.node`` first, then extract.
            * Bare node (TextNode etc.) with ``.get_content()`` or ``.text``.
            * Raw string (for tests and the trivial usage path).
        """
        # NodeWithScore wraps a BaseNode. Unwrap before extracting text.
        if hasattr(item, "node"):
            inner = item.node
        else:
            inner = item

        if hasattr(inner, "get_content"):
            try:
                return inner.get_content()
            except TypeError:
                pass
        if hasattr(inner, "text"):
            return inner.text
        if isinstance(inner, str):
            return inner
        raise TypeError(
            "Cannot extract text from retrieved object: expected a "
            "LlamaIndex node (with .get_content() or .text), a "
            "NodeWithScore, or a string"
        )

    def retrieve_with_receipt(
        self,
        query: str,
        output_text: str = "",
    ) -> RetrievalResult:
        """Retrieve nodes, verify them, apply policy, and produce a receipt.

        Args:
            query: The retrieval query string, passed through to the base
                retriever unchanged.
            output_text: The LLM output text, if available. Its SHA-256
                hash is recorded on the receipt. Pass ``""`` if the receipt
                is being generated before inference.

        Returns:
            A :class:`RetrievalResult` containing kept nodes, blocked
            nodes, and the signed receipt covering both sets.
        """
        retrieved = self._retrieve(query)
        builder = ReceiptBuilder(policy=self._policy)

        kept: List[Any] = []
        blocked: List[Any] = []

        for item in retrieved:
            text = self._node_text(item)
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
                blocked.append(item)
            else:
                kept.append(item)

        receipt = builder.finalize(output_text=output_text, signer=self._signer)
        return RetrievalResult(nodes=kept, blocked=blocked, receipt=receipt)

    def retrieve(self, query: str) -> List[Any]:
        """Alias that returns only kept nodes (LlamaIndex-compatible signature).

        For most production use call :meth:`retrieve_with_receipt`
        instead, which surfaces the receipt.
        """
        return self.retrieve_with_receipt(query).nodes
