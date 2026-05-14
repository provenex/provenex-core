"""Regression tests for `step_kind` propagation on retrieval emissions.

Before this fix, two Phase 1 entry points took a `step_kind` argument
but did not actually stamp it onto the receipt's trajectory block:

    * ``provenex_retrieval_node`` accepted ``step_kind="retrieval"`` as a
      factory argument but only applied it on a freshly created
      trajectory — pre-seeded trajectories carried whatever step_kind
      the cursor had (usually None).
    * ``ProvenexRetriever.get_relevant_documents_with_receipt`` had no
      ``step_kind`` parameter at all, so every receipt it emitted had
      a trajectory block with no step_kind classifier.

The fixes:

    * The LangGraph retrieval node now stamps the factory's step_kind /
      agent_id onto every emission (mirrors
      ``verify_chunks(step_kind=...)``).
    * ``ProvenexRetriever`` gained ``step_kind`` and ``agent_id``
      kwargs on ``get_relevant_documents_with_receipt``; both default
      to the natural value (``"retrieval"`` / cursor inherits) so
      existing callers see the correction without code changes.

Why this matters: ``provenex audit --trajectory`` (added in 0.6.3) emits
an aggregate ``per_step_kind`` summary block. Without the fix, the
``retrieval`` count was always zero on receipts produced via these
two entrypoints, so the auditor's headline summary was wrong on every
mixed retrieval + tool-call trajectory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from provenex.core.receipt import HmacSha256Signer
from provenex.core.trajectory import start_trajectory
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import (
    ProvenexIngestor,
    ProvenexRetriever,
)
from provenex.integrations.langgraph import (
    provenex_retrieval_node,
    start_trajectory_state,
)


SECRET = b"step-kind-test-secret"


@dataclass
class StubDoc:
    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class StubRetriever:
    def __init__(self, docs: List[StubDoc]) -> None:
        self._docs = docs

    def get_relevant_documents(self, query: str) -> List[StubDoc]:
        return list(self._docs)


def _seeded_index() -> SQLiteProvenanceIndex:
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    ingestor.ingest(
        [StubDoc(page_content="seeded chunk for step_kind tests")],
        doc_id="doc_1",
        authorized=True,
    )
    return index


# --------------------------------------------------------------------------- #
# LangGraph retrieval node                                                    #
# --------------------------------------------------------------------------- #


def test_retrieval_node_stamps_step_kind_on_pre_seeded_trajectory():
    """Bug fix: the factory's step_kind default ("retrieval") now lands
    on every emission, including when the trajectory cursor was
    pre-seeded by start_trajectory_state (where step_kind is None by
    default).
    """
    index = _seeded_index()
    retrieve = provenex_retrieval_node(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    # Pre-seed with no step_kind on the cursor — the previous bug surface.
    state = {
        **start_trajectory_state(agent_id="lg_agent"),
        "query": "what",
    }
    delta = retrieve(state)
    receipt_d = delta["receipts"][0].to_dict()
    assert receipt_d["trajectory"]["step_kind"] == "retrieval"


def test_retrieval_node_custom_step_kind_overrides_default():
    """The factory arg flows through unchanged when overridden — same
    behaviour as before for callers who explicitly set step_kind."""
    index = _seeded_index()
    retrieve = provenex_retrieval_node(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        step_kind="memory_read",
    )
    state = {
        **start_trajectory_state(agent_id="lg_agent"),
        "query": "what",
    }
    receipt_d = retrieve(state)["receipts"][0].to_dict()
    assert receipt_d["trajectory"]["step_kind"] == "memory_read"


def test_retrieval_node_agent_id_factory_arg_lands_on_emission():
    """A factory-level agent_id now also reaches the emitted receipt
    even when the pre-seeded cursor had a different (or no) agent_id.
    """
    index = _seeded_index()
    retrieve = provenex_retrieval_node(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        agent_id="from_factory",
    )
    state = {
        # No agent_id on the cursor.
        **start_trajectory_state(),
        "query": "what",
    }
    receipt_d = retrieve(state)["receipts"][0].to_dict()
    assert receipt_d["trajectory"]["agent_id"] == "from_factory"


def test_mixed_retrieval_plus_admission_yields_correct_per_step_kind():
    """End-to-end: the headline aggregate-summary use case. A mixed
    trajectory of one retrieval + one admission step now produces
    receipts with step_kind values that the aggregator can bucket
    correctly.
    """
    from provenex import Policy, RequestContext
    from provenex.integrations.langgraph import provenex_admission_node

    POLICY_YAML = """
version: 1
policy_id: step-kind-test
tool_call_control:
  rules:
    - name: web_search_domain
      when: { tool.name: web_search }
      require:
        tool.target_system: { in: [google_custom_search] }
      on_violation: deny
"""

    index = _seeded_index()
    retrieve = provenex_retrieval_node(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    admit = provenex_admission_node(
        name="web_search",
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=lambda s: RequestContext(
            caller={"role": "engineer"},
            jurisdiction="US",
            purpose="t",
            timestamp="2026-05-14T11:30:00Z",
        ),
        operation="query",
        target_system="google_custom_search",
    )
    state: Dict[str, Any] = {
        **start_trajectory_state(agent_id="lg_agent"),
        "query": "what",
    }
    state.update(retrieve(state))
    state["tool_parameters"] = {"q": "x"}
    state.update(admit(state))

    kinds = [r.to_dict()["trajectory"]["step_kind"] for r in state["receipts"]]
    assert kinds == ["retrieval", "tool_call"]


# --------------------------------------------------------------------------- #
# LangChain ProvenexRetriever                                                 #
# --------------------------------------------------------------------------- #


def test_langchain_retriever_default_step_kind_is_retrieval():
    """Bug fix: ProvenexRetriever now stamps step_kind="retrieval" on
    every receipt it emits when a trajectory is supplied. Previously
    every emission was step_kind=None.
    """
    index = _seeded_index()
    retriever = ProvenexRetriever(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    trj = start_trajectory(agent_id="lc_agent")
    result = retriever.get_relevant_documents_with_receipt(
        query="anything", trajectory=trj,
    )
    receipt_d = result.receipt.to_dict()
    assert receipt_d["trajectory"]["step_kind"] == "retrieval"


def test_langchain_retriever_step_kind_override():
    """The new kwarg accepts caller-side overrides for reuse cases
    (same retriever wrapping a memory store, say)."""
    index = _seeded_index()
    retriever = ProvenexRetriever(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    trj = start_trajectory(agent_id="lc_agent")
    result = retriever.get_relevant_documents_with_receipt(
        query="anything",
        trajectory=trj,
        step_kind="memory_read",
    )
    assert result.receipt.to_dict()["trajectory"]["step_kind"] == "memory_read"


def test_langchain_retriever_agent_id_override():
    index = _seeded_index()
    retriever = ProvenexRetriever(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    trj = start_trajectory(agent_id="original_agent")
    result = retriever.get_relevant_documents_with_receipt(
        query="anything",
        trajectory=trj,
        agent_id="per_call_override",
    )
    assert result.receipt.to_dict()["trajectory"]["agent_id"] == "per_call_override"


def test_langchain_retriever_without_trajectory_emits_no_trajectory_block():
    """When no trajectory is supplied, the receipt simply has no
    trajectory block — step_kind has no surface to live on. This
    preserves the original non-agentic single-shot behaviour.
    """
    index = _seeded_index()
    retriever = ProvenexRetriever(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for step_kind tests"),
        ]),
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    result = retriever.get_relevant_documents_with_receipt(query="anything")
    # No trajectory was passed → receipt has no "trajectory" key
    # (to_dict only emits the block when one was set on the receipt).
    assert "trajectory" not in result.receipt.to_dict()
