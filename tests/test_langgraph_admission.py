"""Tests for ``provenex_admission_node`` (LangGraph tool-call admission).

Same conventions as ``test_langgraph_integration.py``: we don't import
langgraph itself — nodes are callables ``(state) -> state_delta``, so we
exercise them by calling directly with state dicts and asserting on the
returned delta. Tests cover allow / deny paths, trajectory composition
with the retrieval node, params extraction, per-step overrides, and the
"decision-not-execution" property (the node never invokes the tool).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
)
from provenex.core.trajectory import audit_trajectory_dag
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor
from provenex.integrations.langgraph import (
    provenex_admission_node,
    provenex_retrieval_node,
    start_trajectory_state,
)


SECRET = b"langgraph-admission-test-secret"


POLICY_YAML = """
version: 1
policy_id: langgraph-admission-test-v1
tool_call_control:
  rules:
    - name: web_search_domain_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search]
      on_violation: deny
    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue] }
      require:
        request.caller.role: { in: [engineer, manager] }
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


def _policy() -> Policy:
    return Policy.from_text(POLICY_YAML)


def _signer() -> HmacSha256Signer:
    return HmacSha256Signer(secret=SECRET)


def _request_factory(state: Dict[str, Any]) -> RequestContext:
    """Pulls caller fields off state. Matches how a host app would wire it."""
    return RequestContext(
        caller=state.get("caller", {"role": "engineer"}),
        jurisdiction=state.get("jurisdiction", "US"),
        purpose=state.get("purpose", "incident_response"),
        timestamp=state.get("timestamp", "2026-05-14T11:30:00Z"),
    )


# --------------------------------------------------------------------------- #
# Basic admission node                                                        #
# --------------------------------------------------------------------------- #


def test_admission_node_allow_writes_decision_into_state():
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
    )
    state = {"tool_parameters": {"q": "weather"}}
    delta = node(state)
    assert delta["tool_admitted"] is True
    assert delta["tool_decision"] == "allow"
    assert "web_search_domain_allowlist" in delta["tool_rules_fired"]
    # Receipt list is appended (here from scratch — list of len 1).
    assert len(delta["receipts"]) == 1
    # Trajectory cursor was advanced.
    assert delta["trajectory"].step_index == 1


def test_admission_node_deny_writes_false_into_state_and_still_emits_receipt():
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="duckduckgo",  # not allowlisted
    )
    state = {"tool_parameters": {"q": "x"}}
    delta = node(state)
    assert delta["tool_admitted"] is False
    assert delta["tool_decision"] == "deny"
    assert delta["tool_rules_fired"] == ["web_search_domain_allowlist"]
    # The receipt is still emitted on deny — that's the audit anchor.
    assert len(delta["receipts"]) == 1
    receipt_d = delta["receipts"][0].to_dict()
    assert receipt_d["policy"]["tool_call_control"]["decisions"][0]["decision"] == "deny"


def test_admission_node_does_not_execute_anything():
    """The load-bearing 'decision and proof, not execution' property.

    The admission node receives nothing that resembles a callable tool
    and never produces tool output. It returns a decision, full stop.
    The state delta has no 'documents' / 'tool_output' / etc keys —
    only the decision-shaped keys plus receipts + trajectory.
    """
    node = provenex_admission_node(
        name="jira",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="create_issue",
    )
    state = {"tool_parameters": {"project": "INC", "summary": "..."}}
    delta = node(state)
    keys = set(delta.keys())
    # No execution-shaped keys.
    assert "tool_output" not in keys
    assert "documents" not in keys
    assert "result" not in keys
    # Only the decision + receipts + trajectory triplet.
    expected = {
        "tool_admitted", "tool_decision", "tool_rules_fired",
        "receipts", "trajectory",
    }
    assert keys == expected


# --------------------------------------------------------------------------- #
# Parameter extraction                                                        #
# --------------------------------------------------------------------------- #


def test_admission_node_default_reads_tool_parameters_state_key():
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
    )
    delta = node({"tool_parameters": {"q": "weather", "num": 10}})
    receipt_d = delta["receipts"][0].to_dict()
    assert receipt_d["actions"][0]["parameters"] == {"q": "weather", "num": 10}


def test_admission_node_non_dict_parameters_wrapped_under_input():
    node = provenex_admission_node(
        name="jira",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="create_issue",
    )
    delta = node({"tool_parameters": "raw user message"})
    receipt_d = delta["receipts"][0].to_dict()
    assert receipt_d["actions"][0]["parameters"] == {"input": "raw user message"}


def test_admission_node_custom_params_extractor():
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
        params_extractor=lambda s: {"q": s["planner"]["query"]},
    )
    delta = node({"planner": {"query": "extracted via custom path"}})
    receipt_d = delta["receipts"][0].to_dict()
    assert receipt_d["actions"][0]["parameters"] == {"q": "extracted via custom path"}


# --------------------------------------------------------------------------- #
# Per-step overrides                                                          #
# --------------------------------------------------------------------------- #


def test_admission_node_per_step_overrides():
    node = provenex_admission_node(
        name="jira",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="default_op",
    )
    delta = node(
        {
            "tool_parameters": {"project": "INC", "summary": "..."},
            "__operation__": "create_issue",
            "__target_system__": "acme.atlassian.net",
            "__invocation_id__": "inv_xyz",
        }
    )
    receipt_d = delta["receipts"][0].to_dict()
    assert receipt_d["actions"][0]["operation"] == "create_issue"
    assert receipt_d["actions"][0]["target_system"] == "acme.atlassian.net"
    assert receipt_d["actions"][0]["invocation_id"] == "inv_xyz"


# --------------------------------------------------------------------------- #
# Trajectory composition with retrieval node                                  #
# --------------------------------------------------------------------------- #


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
        [StubDoc(page_content="seeded chunk for trajectory tests")],
        doc_id="doc_1",
        authorized=True,
    )
    return index


def test_retrieve_then_admit_threads_trajectory_into_one_dag():
    """The headline cross-front-end demo — retrieval and admission share
    one trajectory through state. The full DAG validates end-to-end.
    """
    index = _seeded_index()

    retrieve = provenex_retrieval_node(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for trajectory tests"),
        ]),
        index=index,
        signer=_signer(),
    )
    admit = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
    )

    # Seed an empty trajectory + receipts list into state.
    state: Dict[str, Any] = {
        **start_trajectory_state(agent_id="lg_agent"),
        "query": "what is the policy",
    }
    # Step 0: retrieval.
    state.update(retrieve(state))
    assert len(state["receipts"]) == 1
    # Step 1: admission (sets tool_admitted into state).
    state["tool_parameters"] = {"q": "follow-up question"}
    state.update(admit(state))
    assert len(state["receipts"]) == 2
    assert state["tool_admitted"] is True

    # Single trajectory_id across both receipts.
    ids = {r.to_dict()["trajectory"]["trajectory_id"] for r in state["receipts"]}
    assert len(ids) == 1

    # Audit the full DAG.
    audit = audit_trajectory_dag([r.to_dict() for r in state["receipts"]])
    assert audit.ok is True


def test_admission_node_emits_step_kind_tool_call():
    """The tool-call admission node propagates step_kind="tool_call" onto
    the emitted receipt's trajectory block.
    """
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
    )
    delta = node({"tool_parameters": {"q": "x"}})
    receipt_d = delta["receipts"][0].to_dict()
    assert receipt_d["trajectory"]["step_kind"] == "tool_call"


def test_retrieve_then_admit_yields_correct_step_kinds():
    """Mixed trajectory now records distinct step_kinds for each
    emission — ``retrieval`` for the retrieval node, ``tool_call`` for
    the admission node. This drives the trajectory audit's
    ``per_step_kind`` aggregate correctly.
    """
    index = _seeded_index()
    retrieve = provenex_retrieval_node(
        base_retriever=StubRetriever([
            StubDoc(page_content="seeded chunk for trajectory tests"),
        ]),
        index=index,
        signer=_signer(),
    )
    admit = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
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
# Custom state-key remapping                                                  #
# --------------------------------------------------------------------------- #


def test_admission_node_respects_custom_state_keys():
    """A graph with its own naming convention can remap each input/output."""
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
        state_keys={
            "tool_parameters": "params",
            "tool_admitted": "allowed",
            "tool_decision": "decision",
            "tool_rules_fired": "rules",
            "receipts": "audit_log",
            "trajectory": "trj",
        },
    )
    delta = node({"params": {"q": "test"}})
    assert delta["allowed"] is True
    assert delta["decision"] == "allow"
    assert "web_search_domain_allowlist" in delta["rules"]
    assert len(delta["audit_log"]) == 1
    assert delta["trj"].step_index == 1


def test_admission_node_starts_trajectory_when_state_has_none():
    """A node that runs with no pre-seeded trajectory boots one fresh.

    Same convention as the retrieval node — no required upstream
    start_trajectory_state call.
    """
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
    )
    delta = node({"tool_parameters": {"q": "x"}})
    assert delta["trajectory"].trajectory_id.startswith("trj_")
    assert delta["trajectory"].step_index == 1


# --------------------------------------------------------------------------- #
# Conditional-edge integration pattern                                        #
# --------------------------------------------------------------------------- #


def test_conditional_routing_uses_tool_admitted():
    """Demonstrate the recommended LangGraph pattern: admission node's
    output drives a conditional edge that routes to the actual executor
    or to a denied-handler. We assert the routing function's behaviour.
    """
    node = provenex_admission_node(
        name="web_search",
        policy=_policy(),
        signer=_signer(),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
    )

    def route(state: Dict[str, Any]) -> str:
        return "execute_search" if state["tool_admitted"] else "denied_handler"

    # Allow path.
    state = node({"tool_parameters": {"q": "ok"}})
    assert route(state) == "execute_search"

    # Deny path (override the target via reserved key).
    state = node(
        {
            "tool_parameters": {"q": "x"},
            "__target_system__": "duckduckgo",
        }
    )
    assert route(state) == "denied_handler"
