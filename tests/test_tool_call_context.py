"""Tests for the tool-call data model.

Covers:

    * :class:`ToolCallContext` construction, defaults, immutability.
    * :func:`build_tool_call_inputs` — canonical inputs shape for receipts.
    * :func:`compute_parameters_hash` — stable across key order, dependent
      on values.
    * :class:`NullToolCallPolicyEvaluator` — allow-all stub.
    * :class:`ToolCallPolicyEvaluator` Protocol — runtime_checkable
      structural-typing behaviour.
"""

from __future__ import annotations

import json

import pytest

from provenex.policy.evaluator import (
    DECISION_ALLOW,
    PolicyDecision,
    RequestContext,
)
from provenex.tool_call import (
    ToolCallContext,
    ToolCallPolicyEvaluator,
)
from provenex.tool_call.evaluator import (
    NullToolCallPolicyEvaluator,
    build_tool_call_control_metadata,
    build_tool_call_inputs,
    compute_parameters_hash,
)


# --------------------------------------------------------------------------- #
# ToolCallContext                                                             #
# --------------------------------------------------------------------------- #


def test_tool_call_context_minimum_required():
    ctx = ToolCallContext(name="web_search", operation="query")
    assert ctx.name == "web_search"
    assert ctx.operation == "query"
    assert ctx.parameters == {}
    assert ctx.target_system is None
    assert ctx.invocation_id is None


def test_tool_call_context_with_all_fields():
    ctx = ToolCallContext(
        name="jira",
        operation="create_issue",
        parameters={"project": "INC", "summary": "..."},
        target_system="acme.atlassian.net",
        invocation_id="inv_8e2c",
    )
    assert ctx.parameters == {"project": "INC", "summary": "..."}
    assert ctx.target_system == "acme.atlassian.net"
    assert ctx.invocation_id == "inv_8e2c"


def test_tool_call_context_is_frozen():
    ctx = ToolCallContext(name="t", operation="op")
    with pytest.raises(Exception):
        ctx.name = "other"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# build_tool_call_inputs                                                      #
# --------------------------------------------------------------------------- #


def _request() -> RequestContext:
    return RequestContext(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )


def test_build_tool_call_inputs_shape():
    ctx = ToolCallContext(
        name="jira",
        operation="create_issue",
        parameters={"project": "INC"},
        target_system="acme.atlassian.net",
    )
    inputs = build_tool_call_inputs(ctx, _request())
    assert set(inputs.keys()) == {"tool_parameters", "request_context"}
    assert inputs["tool_parameters"]["name"] == "jira"
    assert inputs["tool_parameters"]["operation"] == "create_issue"
    assert inputs["tool_parameters"]["parameters"] == {"project": "INC"}
    assert inputs["tool_parameters"]["target_system"] == "acme.atlassian.net"
    assert inputs["request_context"]["caller"] == {"id": "u_42", "role": "engineer"}
    assert inputs["request_context"]["jurisdiction"] == "US"
    assert inputs["request_context"]["timestamp"] == "2026-05-14T11:30:00Z"


def test_build_tool_call_inputs_omits_unset_optionals():
    ctx = ToolCallContext(name="web_search", operation="query")
    inputs = build_tool_call_inputs(ctx, _request())
    # Optional fields absent rather than emitted as None — keeps the
    # canonical hash stable across constructions that don't supply them.
    assert "target_system" not in inputs["tool_parameters"]
    assert "invocation_id" not in inputs["tool_parameters"]


# --------------------------------------------------------------------------- #
# compute_parameters_hash                                                     #
# --------------------------------------------------------------------------- #


def test_parameters_hash_format():
    h = compute_parameters_hash({"q": "test"})
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_parameters_hash_stable_across_key_order():
    a = compute_parameters_hash({"q": "test", "num": 10})
    b = compute_parameters_hash({"num": 10, "q": "test"})
    assert a == b


def test_parameters_hash_changes_with_value():
    a = compute_parameters_hash({"q": "alpha"})
    b = compute_parameters_hash({"q": "beta"})
    assert a != b


def test_parameters_hash_changes_with_added_field():
    a = compute_parameters_hash({"q": "test"})
    b = compute_parameters_hash({"q": "test", "num": 10})
    assert a != b


def test_parameters_hash_empty_dict_is_stable():
    a = compute_parameters_hash({})
    b = compute_parameters_hash({})
    assert a == b


# --------------------------------------------------------------------------- #
# NullToolCallPolicyEvaluator                                                 #
# --------------------------------------------------------------------------- #


def test_null_evaluator_always_allows():
    ev = NullToolCallPolicyEvaluator()
    ctx = ToolCallContext(name="anything", operation="any")
    decision = ev.evaluate(ctx, _request())
    assert decision.decision == DECISION_ALLOW
    assert decision.rules_fired == []
    assert decision.inputs_hash.startswith("sha256:")


def test_null_evaluator_policy_id_is_sentinel():
    ev = NullToolCallPolicyEvaluator()
    assert ev.policy_id == "none"
    assert ev.evaluator_name == "none"
    assert ev.policy_version_hash.startswith("sha256:")


def test_null_evaluator_implements_protocol():
    ev = NullToolCallPolicyEvaluator()
    assert isinstance(ev, ToolCallPolicyEvaluator)


# --------------------------------------------------------------------------- #
# build_tool_call_control_metadata                                            #
# --------------------------------------------------------------------------- #


def test_build_tool_call_control_metadata_shape():
    ev = NullToolCallPolicyEvaluator()
    block = build_tool_call_control_metadata(ev, decisions=[])
    assert block["evaluator"] == "none"
    assert block["policy_id"] == "none"
    assert block["policy_version_hash"].startswith("sha256:")
    assert block["policy_in_transparency_log"] is False
    assert block["decisions"] == []


def test_build_tool_call_control_metadata_carries_decisions():
    ev = NullToolCallPolicyEvaluator()
    decisions = [
        {"action_index": 0, "decision": "allow", "rules_fired": [], "inputs_hash": "sha256:x", "inputs": None},
    ]
    block = build_tool_call_control_metadata(ev, decisions=decisions)
    assert block["decisions"] == decisions
    # The list is copied — caller-side mutations don't leak through.
    decisions.append({"action_index": 1})
    assert len(block["decisions"]) == 1
