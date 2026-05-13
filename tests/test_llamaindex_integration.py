"""Integration tests for the LlamaIndex wrapper.

Uses duck-typed stub classes that mimic LlamaIndex's Document, TextNode,
NodeWithScore, and BaseRetriever shapes. The middleware only requires
``.text`` (or ``.get_content()``) on nodes and ``.retrieve()`` on the
retriever, so anything fitting those shapes is accepted. These tests run
without LlamaIndex installed.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from provenex.core.receipt import HmacSha256Signer
from provenex.index.base import VerificationOutcome
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.llamaindex import ProvenexIngestor, ProvenexRetriever
from provenex.policy.policy import VerificationPolicy


SECRET = b"llamaindex-test-secret"


@dataclass
class StubDocument:
    """Minimal LlamaIndex Document — has .text only."""

    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StubTextNode:
    """Minimal LlamaIndex TextNode-like — has both .text and .get_content()."""

    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_content(self, metadata_mode: Optional[str] = None) -> str:
        # Mirrors the real signature; the optional kwarg is honoured by
        # the production LlamaIndex API but we just return the text.
        return self.text


@dataclass
class StubNodeWithScore:
    """Minimal LlamaIndex NodeWithScore — wraps a node + score."""

    node: Any
    score: float = 1.0


@dataclass
class StubRetriever:
    """Minimal LlamaIndex BaseRetriever — just .retrieve()."""

    nodes_to_return: List[Any]

    def retrieve(self, query: str) -> List[Any]:
        # Real LlamaIndex returns List[NodeWithScore]. We mirror that shape.
        return list(self.nodes_to_return)


def _make_index(workdir: Path) -> SQLiteProvenanceIndex:
    return SQLiteProvenanceIndex(str(workdir / "p.db"), signing_secret=SECRET)


# --------------------------------------------------------------------- ingestor


def test_ingestor_accepts_documents_with_text_attr():
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)
    docs = [
        StubDocument(text="The encryption policy requires AES-256."),
        StubDocument(text="Keys are rotated quarterly."),
    ]
    result = ingestor.ingest(docs, doc_id="policy_v1", authorized=True)
    assert result.document_id == "policy_v1"
    assert result.chunk_count == 2
    assert result.fingerprint_count >= 2  # whole-chunk + sliding-window fps


def test_ingestor_accepts_text_nodes_with_get_content():
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)
    nodes = [
        StubTextNode(text="Backups must be encrypted with a separate key."),
    ]
    result = ingestor.ingest(nodes, doc_id="policy_v1")
    assert result.chunk_count == 1


def test_ingestor_accepts_raw_strings():
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)
    result = ingestor.ingest(["just a plain string chunk"], doc_id="strings_v1")
    assert result.fingerprint_count >= 1


def test_ingestor_rejects_unknown_shape():
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)

    @dataclass
    class NoText:
        body: str = "not what we want"

    try:
        ingestor.ingest([NoText()], doc_id="x")
    except TypeError as exc:
        assert "Cannot extract text" in str(exc)
    else:
        raise AssertionError("expected TypeError on unknown shape")


# --------------------------------------------------------------------- retriever


def test_retriever_verifies_and_passes_through():
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)
    chunk_text = "AES-256-GCM with quarterly key rotation is mandatory."
    ingestor.ingest([StubDocument(text=chunk_text)], doc_id="policy_v1")

    # The retriever returns the same chunk we ingested, wrapped as a NodeWithScore.
    node = StubNodeWithScore(node=StubTextNode(text=chunk_text), score=0.92)
    base = StubRetriever(nodes_to_return=[node])

    retriever = ProvenexRetriever(
        base_retriever=base,
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    result = retriever.retrieve_with_receipt(
        query="encryption policy?",
        output_text="AES-256, rotated quarterly.",
    )

    assert len(result.nodes) == 1
    assert len(result.blocked) == 0
    assert result.receipt.summary["verified"] == 1
    # The receipt's first source should be VERIFIED for this known chunk.
    assert (
        result.receipt.sources[0].verification_outcome
        == VerificationOutcome.VERIFIED
    )


def test_retriever_blocks_unverified_chunks_by_policy():
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)
    ingestor.ingest([StubDocument(text="known chunk text")], doc_id="policy_v1")

    # Poisoned chunk: text never ingested through Provenex.
    poisoned = StubNodeWithScore(node=StubTextNode(text="poisoned attacker text"))
    legit = StubNodeWithScore(node=StubTextNode(text="known chunk text"))
    base = StubRetriever(nodes_to_return=[poisoned, legit])

    retriever = ProvenexRetriever(
        base_retriever=base,
        index=index,
        policy=VerificationPolicy(block_unverified=True),
        signer=HmacSha256Signer(secret=SECRET),
    )
    result = retriever.retrieve_with_receipt(query="anything")

    assert len(result.nodes) == 1
    assert result.nodes[0] is legit
    assert len(result.blocked) == 1
    assert result.blocked[0] is poisoned


def test_retriever_alias_returns_only_kept_nodes():
    """The .retrieve() convenience alias drops blocked nodes silently."""
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)
    ingestor.ingest([StubDocument(text="known chunk text")], doc_id="policy_v1")

    legit = StubNodeWithScore(node=StubTextNode(text="known chunk text"))
    poisoned = StubNodeWithScore(node=StubTextNode(text="poisoned"))
    base = StubRetriever(nodes_to_return=[legit, poisoned])

    retriever = ProvenexRetriever(
        base_retriever=base,
        index=index,
        policy=VerificationPolicy(block_unverified=True),
        signer=HmacSha256Signer(secret=SECRET),
    )
    nodes = retriever.retrieve("anything")
    assert len(nodes) == 1
    assert nodes[0] is legit


def test_retriever_handles_bare_text_nodes_not_node_with_score():
    """Some LlamaIndex retrievers return bare TextNode without the score wrapper."""
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)
    ingestor = ProvenexIngestor(index=index)
    chunk_text = "bare-node test chunk that is sufficiently long for windowing"
    ingestor.ingest([StubDocument(text=chunk_text)], doc_id="policy_v1")

    # Pass a bare TextNode (no NodeWithScore wrapper).
    base = StubRetriever(nodes_to_return=[StubTextNode(text=chunk_text)])
    retriever = ProvenexRetriever(
        base_retriever=base,
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    result = retriever.retrieve_with_receipt(query="anything")
    assert (
        result.receipt.sources[0].verification_outcome
        == VerificationOutcome.VERIFIED
    )


def test_retriever_rejects_retriever_without_retrieve_method():
    """A retriever without .retrieve() should raise a TypeError on use."""
    workdir = Path(tempfile.mkdtemp())
    index = _make_index(workdir)

    class BadRetriever:
        pass  # no .retrieve()

    retriever = ProvenexRetriever(base_retriever=BadRetriever(), index=index)
    try:
        retriever.retrieve_with_receipt("query")
    except TypeError as exc:
        assert "recognized LlamaIndex" in str(exc)
    else:
        raise AssertionError("expected TypeError")
