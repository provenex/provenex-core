"""Integration tests for the LangGraph wrapper.

LangGraph nodes are just callables ``(state) -> state_delta``. Our
integration does not import langgraph itself, so these tests don't either
— we exercise the node by calling it directly with a state dict and
asserting on the returned delta.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature
from provenex.core.trajectory import audit_trajectory_dag
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor
from provenex.integrations.langgraph import (
    provenex_retrieval_node,
    record_step_receipt,
    start_trajectory_state,
)
from provenex.policy.policy import VerificationPolicy


SECRET = b"langgraph-test-secret"


@dataclass
class StubDoc:
    """Minimal duck-typed LangChain Document — works for the LangGraph node
    too, since the helper accepts the same shape."""

    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class StubRetriever:
    """Returns a fixed list of documents regardless of the query."""

    def __init__(self, docs: List[StubDoc]) -> None:
        self._docs = docs

    def get_relevant_documents(self, query: str) -> List[StubDoc]:
        return list(self._docs)


def _seeded_index() -> tuple[SQLiteProvenanceIndex, List[StubDoc]]:
    """Create an index pre-populated with two authorized chunks."""
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunks = [
        StubDoc(page_content="Encryption policy requires AES-256 for data at rest."),
        StubDoc(page_content="Key-encryption keys must be rotated quarterly."),
    ]
    ingestor.ingest(chunks, doc_id="policy_v4", authorized=True)
    return index, chunks


# --------------------------------------------------------------------------- #
# start_trajectory_state                                                      #
# --------------------------------------------------------------------------- #


def test_start_trajectory_state_seeds_state():
    delta = start_trajectory_state(agent_id="research_agent")
    assert "trajectory" in delta
    assert "receipts" in delta
    assert delta["receipts"] == []
    assert delta["trajectory"].agent_id == "research_agent"
    assert delta["trajectory"].step_index == 0


def test_start_trajectory_state_respects_custom_keys():
    delta = start_trajectory_state(
        state_keys={"trajectory": "tcur", "receipts": "audit_log"}
    )
    assert "tcur" in delta
    assert "audit_log" in delta
    assert delta["audit_log"] == []


# --------------------------------------------------------------------------- #
# provenex_retrieval_node                                                     #
# --------------------------------------------------------------------------- #


def test_node_returns_documents_and_receipt_with_trajectory():
    index, chunks = _seeded_index()
    node = provenex_retrieval_node(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )

    state = {**start_trajectory_state(agent_id="planner"), "query": "what about keys?"}
    delta = node(state)

    assert len(delta["documents"]) == 2
    assert delta["blocked_documents"] == []
    assert len(delta["receipts"]) == 1
    receipt = delta["receipts"][0]
    d = receipt.to_dict()
    assert "trajectory" in d
    assert d["trajectory"]["agent_id"] == "planner"
    assert d["trajectory"]["step_index"] == 0
    # The trajectory cursor in state should have been advanced.
    assert delta["trajectory"].step_index == 1
    assert delta["trajectory"].parent_step_ids == (receipt.receipt_id,)


def test_node_can_run_without_pre_seeded_trajectory():
    """If state has no trajectory, the node starts a fresh one."""
    index, chunks = _seeded_index()
    node = provenex_retrieval_node(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        agent_id="auto_agent",
    )
    delta = node({"query": "tell me"})
    assert len(delta["receipts"]) == 1
    d = delta["receipts"][0].to_dict()
    assert d["trajectory"]["agent_id"] == "auto_agent"
    assert d["trajectory"]["step_index"] == 0
    assert d["trajectory"]["parent_step_ids"] == []


def test_two_nodes_in_a_row_form_a_chain():
    """Wiring two retrieval nodes back-to-back produces a linked trajectory."""
    index, chunks = _seeded_index()
    retriever = StubRetriever(chunks)
    node_a = provenex_retrieval_node(
        base_retriever=retriever,
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        agent_id="agent",
        step_kind="retrieval",
    )
    node_b = provenex_retrieval_node(
        base_retriever=retriever,
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        agent_id="agent",
        step_kind="retrieval",
    )

    state = {**start_trajectory_state(agent_id="agent"), "query": "q1"}
    after_a = {**state, **node_a(state)}
    after_a["query"] = "q2"
    after_b = {**after_a, **node_b(after_a)}

    r1, r2 = after_b["receipts"]
    d1 = r1.to_dict()["trajectory"]
    d2 = r2.to_dict()["trajectory"]
    assert d1["trajectory_id"] == d2["trajectory_id"]
    assert d1["step_index"] == 0
    assert d2["step_index"] == 1
    assert d2["parent_step_ids"] == [r1.receipt_id]


def test_chain_passes_full_trajectory_audit():
    """End-to-end: a three-node chain produces receipts that audit cleanly."""
    index, chunks = _seeded_index()
    retriever = StubRetriever(chunks)
    node = provenex_retrieval_node(
        base_retriever=retriever,
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        agent_id="agent",
    )

    state: Dict[str, Any] = {**start_trajectory_state(agent_id="agent"), "query": "q"}
    for i in range(3):
        state["query"] = f"query_{i}"
        state.update(node(state))

    receipts = state["receipts"]
    assert len(receipts) == 3

    # Each receipt's signature must verify.
    verifier = HmacSha256Signer(secret=SECRET)
    for r in receipts:
        assert verify_receipt_signature(r.to_dict(), verifier) is True

    # Trajectory DAG audit must pass.
    result = audit_trajectory_dag([r.to_dict() for r in receipts])
    assert result.ok is True
    assert result.receipt_count == 3


def test_node_respects_custom_state_keys():
    index, chunks = _seeded_index()
    node = provenex_retrieval_node(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        state_keys={
            "query": "q",
            "documents": "docs",
            "receipts": "audit",
            "trajectory": "cursor",
        },
    )
    state = {
        **start_trajectory_state(
            state_keys={"trajectory": "cursor", "receipts": "audit"}
        ),
        "q": "ask",
    }
    delta = node(state)
    assert "docs" in delta
    assert "audit" in delta
    assert "cursor" in delta
    assert len(delta["audit"]) == 1


def test_node_blocks_unauthorized_per_policy():
    """Policy threading: blocked docs go to blocked_documents, not documents."""
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunks = [StubDoc(page_content="restricted internal memo about pricing.")]
    ingestor.ingest(chunks, doc_id="memo_v1", authorized=False)

    node = provenex_retrieval_node(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        policy=VerificationPolicy(block_unauthorized=True),
    )
    delta = node({"query": "pricing?"})
    assert delta["documents"] == []
    assert len(delta["blocked_documents"]) == 1


def test_node_rejects_non_string_query():
    index, chunks = _seeded_index()
    node = provenex_retrieval_node(
        base_retriever=StubRetriever(chunks), index=index
    )
    try:
        node({"query": 42})
    except TypeError as exc:
        assert "must be a string query" in str(exc)
    else:
        raise AssertionError("expected TypeError for non-string query")


def test_unknown_state_key_override_raises():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    try:
        provenex_retrieval_node(
            base_retriever=StubRetriever([]),
            index=index,
            state_keys={"not_a_real_key": "x"},
        )
    except KeyError as exc:
        assert "unknown state_keys override" in str(exc)
    else:
        raise AssertionError("expected KeyError for unknown state_keys override")


# --------------------------------------------------------------------------- #
# record_step_receipt (custom-node helper)                                    #
# --------------------------------------------------------------------------- #


def test_record_step_receipt_advances_trajectory_and_appends():
    """Custom-node helper: append a receipt, advance the cursor."""
    index, chunks = _seeded_index()
    node = provenex_retrieval_node(
        base_retriever=StubRetriever(chunks),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    state = {**start_trajectory_state(agent_id="agent"), "query": "q"}
    state.update(node(state))

    # Now simulate a custom step adding its own receipt to state.
    from provenex.core.receipt import ReceiptBuilder
    from provenex.index.base import VerificationOutcome

    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64, VerificationOutcome.VERIFIED
    )
    custom_receipt = builder.finalize(
        output_text="", trajectory=state["trajectory"]
    )

    delta = record_step_receipt(state, custom_receipt, step_kind="tool_call")
    assert len(delta["receipts"]) == 2
    assert delta["receipts"][-1] is custom_receipt
    assert delta["trajectory"].step_index == state["trajectory"].step_index + 1
    assert custom_receipt.receipt_id in delta["trajectory"].parent_step_ids


def test_record_step_receipt_starts_trajectory_when_missing():
    """If state lacks a trajectory, record_step_receipt synthesises one
    rooted at the supplied receipt."""
    from provenex.core.receipt import ReceiptBuilder
    from provenex.index.base import VerificationOutcome

    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64, VerificationOutcome.VERIFIED
    )
    r = builder.finalize(output_text="")  # no trajectory on the receipt itself
    delta = record_step_receipt({}, r, step_kind="memory_write")
    assert delta["receipts"] == [r]
    assert delta["trajectory"].step_index == 1
    assert delta["trajectory"].parent_step_ids == (r.receipt_id,)
    assert delta["trajectory"].step_kind == "memory_write"
