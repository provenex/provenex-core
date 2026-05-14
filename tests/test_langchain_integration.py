"""Integration tests for the LangChain wrapper.

We use a duck-typed stub for ``Document`` and ``BaseRetriever`` so these tests
run without LangChain installed. The middleware only requires ``page_content``
on documents and either ``invoke`` or ``get_relevant_documents`` on the
retriever — anything fitting those shapes is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from provenex.core.receipt import HmacSha256Signer
from provenex.index.base import VerificationOutcome
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor, ProvenexRetriever
from provenex.policy.policy import VerificationPolicy


SECRET = b"langchain-test-secret"


@dataclass
class StubDoc:
    """Minimal duck-typed LangChain Document."""

    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class StubRetriever:
    """Returns a fixed list of documents regardless of the query."""

    def __init__(self, docs: List[StubDoc]) -> None:
        self._docs = docs

    def get_relevant_documents(self, query: str) -> List[StubDoc]:
        return list(self._docs)


def test_ingest_then_verify_end_to_end():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunks = [
        StubDoc(page_content="The policy permits external sharing in tier 2."),
        StubDoc(page_content="Encryption is required for all PII at rest."),
    ]
    result = ingestor.ingest(chunks, doc_id="policy_v4", authorized=True)
    assert result.chunk_count == 2
    assert result.fingerprint_count > 0

    base = StubRetriever(chunks)
    retriever = ProvenexRetriever(
        base_retriever=base,
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    res = retriever.get_relevant_documents_with_receipt("what about PII?", output_text="Answer")
    assert len(res.documents) == 2
    assert len(res.blocked) == 0
    assert res.receipt.summary["overall_status"] == "PASS"
    # All sources should be VERIFIED.
    for s in res.receipt.sources:
        assert s.verification_outcome == VerificationOutcome.VERIFIED


def test_unverified_when_chunk_not_in_index():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    base = StubRetriever([StubDoc(page_content="never ingested")])
    retriever = ProvenexRetriever(base_retriever=base, index=index)
    res = retriever.get_relevant_documents_with_receipt("q")
    assert res.receipt.summary["unverified"] == 1
    assert res.receipt.summary["overall_status"] == "PARTIAL"


def test_policy_blocks_unauthorized():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunks = [StubDoc(page_content="confidential information")]
    ingestor.ingest(chunks, doc_id="confidential", authorized=False)

    base = StubRetriever(chunks)
    retriever = ProvenexRetriever(
        base_retriever=base,
        index=index,
        policy=VerificationPolicy(block_unauthorized=True),
    )
    res = retriever.get_relevant_documents_with_receipt("q", output_text="")
    assert len(res.documents) == 0
    assert len(res.blocked) == 1
    assert res.receipt.summary["unauthorized"] == 1
    assert res.receipt.summary["overall_status"] == "FAIL"


def test_supersession_makes_old_chunks_stale():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    v1 = [StubDoc(page_content="old v1 content of the document")]
    ingestor.ingest(v1, doc_id="policy", authorized=True)
    # Re-ingest with new content under same doc_id.
    v2 = [StubDoc(page_content="new v2 content of the document")]
    ingestor.ingest(v2, doc_id="policy", authorized=True)

    # Retrieving the old chunk should now be STALE.
    base = StubRetriever(v1)
    retriever = ProvenexRetriever(base_retriever=base, index=index)
    res = retriever.get_relevant_documents_with_receipt("q")
    outcomes = [s.verification_outcome for s in res.receipt.sources]
    assert VerificationOutcome.STALE in outcomes


def test_retriever_invoke_interface():
    """LangChain 0.1+ uses .invoke() — we should call that when available."""

    class InvokeOnlyRetriever:
        def __init__(self, docs):
            self._docs = docs

        def invoke(self, query):
            return list(self._docs)

    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    docs = [StubDoc(page_content="content")]
    base = InvokeOnlyRetriever(docs)
    retriever = ProvenexRetriever(base_retriever=base, index=index)
    res = retriever.get_relevant_documents_with_receipt("q")
    # No index entries → UNVERIFIED, but retrieval still works.
    assert len(res.documents) == 1
    assert res.receipt.summary["unverified"] == 1


def test_string_documents_accepted():
    """Plain strings should be accepted as duck-typed documents."""
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    ingestor.ingest(["a quick brown fox"], doc_id="d1", authorized=True)

    class StringRetriever:
        def get_relevant_documents(self, q):
            return ["a quick brown fox"]

    retriever = ProvenexRetriever(base_retriever=StringRetriever(), index=index)
    res = retriever.get_relevant_documents_with_receipt("q")
    assert len(res.documents) == 1


def test_retriever_threads_trajectory_into_receipt():
    """A trajectory passed to the retriever surfaces on the emitted receipt."""
    from provenex.core.trajectory import start_trajectory

    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunks = [StubDoc(page_content="some authorized policy text here.")]
    ingestor.ingest(chunks, doc_id="d1", authorized=True)

    retriever = ProvenexRetriever(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )

    trajectory = start_trajectory(agent_id="research_agent", step_kind="retrieval")
    res = retriever.get_relevant_documents_with_receipt(
        "q", output_text="answer", trajectory=trajectory
    )
    d = res.receipt.to_dict()
    assert "trajectory" in d
    assert d["trajectory"]["trajectory_id"] == trajectory.trajectory_id
    assert d["trajectory"]["agent_id"] == "research_agent"
    assert d["trajectory"]["step_kind"] == "retrieval"
    assert d["trajectory"]["step_index"] == 0


def test_retriever_chains_trajectory_across_calls():
    """Two sequential retrievals share trajectory_id and increment step_index."""
    from provenex.core.trajectory import start_trajectory

    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunks = [StubDoc(page_content="document A.")]
    ingestor.ingest(chunks, doc_id="d1", authorized=True)

    retriever = ProvenexRetriever(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )

    traj = start_trajectory(agent_id="agent")
    r1 = retriever.get_relevant_documents_with_receipt("q1", trajectory=traj)
    traj2 = traj.next_step(parent_receipts=[r1.receipt], step_kind="retrieval")
    r2 = retriever.get_relevant_documents_with_receipt("q2", trajectory=traj2)

    d1 = r1.receipt.to_dict()
    d2 = r2.receipt.to_dict()
    assert d1["trajectory"]["trajectory_id"] == d2["trajectory"]["trajectory_id"]
    assert d1["trajectory"]["step_index"] == 0
    assert d2["trajectory"]["step_index"] == 1
    assert d2["trajectory"]["parent_step_ids"] == [r1.receipt.receipt_id]


def test_retriever_without_trajectory_emits_no_block():
    """Backward compatibility: omitting trajectory leaves the block absent."""
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunks = [StubDoc(page_content="hello world")]
    ingestor.ingest(chunks, doc_id="d1", authorized=True)

    retriever = ProvenexRetriever(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    res = retriever.get_relevant_documents_with_receipt("q")
    assert "trajectory" not in res.receipt.to_dict()
