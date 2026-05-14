"""Tests for :func:`provenex.admission_check`.

Covers, end-to-end:

    * Allow path: receipt has actions[0]=action, decision=allow,
      rules_fired matches policy.
    * Deny path: receipt records the action AND the denial; the caller
      sees ``decision=deny`` and a fully-signed receipt.
    * No-policy path: receipt records the action, omits the
      tool_call_control block; default decision is allow.
    * Trajectory composition: passing a TrajectoryContext returns a
      next_trajectory cursor whose parent_step_ids points to the new
      receipt; default step_kind on emit is "tool_call".
    * Signature covers the full 2.2.0 receipt (actions[] +
      tool_call_control + trajectory).
    * Parameter redaction: parameters_hash survives even when
      parameters: null.
    * ``enforce_admission`` raises on deny, returns on allow.
"""

from __future__ import annotations

import pytest

from provenex import (
    AdmissionResult,
    HmacSha256Signer,
    Policy,
    RequestContext,
    ToolCallContext,
    ToolCallDenied,
    admission_check,
    enforce_admission,
    start_trajectory,
)
from provenex.core.receipt import verify_receipt_signature
from provenex.tool_call.evaluator import compute_parameters_hash


SECRET = b"test-admission-secret"


# ----- shared fixtures (plain functions, no pytest fixtures needed) ----- #


POLICY_YAML = """
version: 1
policy_id: admission-test-v1
tool_call_control:
  rules:
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search]
      on_violation: deny
    - name: jira_write_role_gate
      when:
        tool.name: jira
        tool.operation: { in: [create_issue, update_issue] }
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


def _request(**overrides) -> RequestContext:
    base = dict(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )
    base.update(overrides)
    return RequestContext(**base)


# --------------------------------------------------------------------------- #
# Allow path                                                                  #
# --------------------------------------------------------------------------- #


def test_allow_web_search_records_action_and_decision():
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "weather"},
        target_system="google_custom_search",
    )
    result = admission_check(tool, _request(), policy=_policy(), signer=_signer())
    assert isinstance(result, AdmissionResult)
    assert result.decision == "allow"
    assert "web_search_provider_allowlist" in result.rules_fired
    assert result.policy_id == "admission-test-v1"
    assert result.allowed is True

    d = result.receipt.to_dict()
    assert len(d["actions"]) == 1
    assert d["actions"][0]["name"] == "web_search"
    assert d["actions"][0]["parameters"] == {"q": "weather"}
    assert "tool_call_control" in d["policy"]
    dec = d["policy"]["tool_call_control"]["decisions"][0]
    assert dec["action_index"] == 0
    assert dec["decision"] == "allow"
    assert dec["metadata_binding"]["tool_parameters"] == "at_evaluate"
    assert dec["metadata_binding"]["request_context"] == "at_evaluate"


# --------------------------------------------------------------------------- #
# Deny path                                                                   #
# --------------------------------------------------------------------------- #


def test_deny_disallowed_search_provider():
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "x"},
        target_system="duckduckgo",
    )
    result = admission_check(tool, _request(), policy=_policy(), signer=_signer())
    assert result.decision == "deny"
    assert result.allowed is False
    assert result.rules_fired == ["web_search_provider_allowlist"]

    d = result.receipt.to_dict()
    # The receipt records both the action AND the denial — denied calls
    # are auditable.
    assert d["actions"][0]["name"] == "web_search"
    assert d["policy"]["tool_call_control"]["decisions"][0]["decision"] == "deny"
    assert d["summary"]["actions_denied"] == 1
    assert d["summary"]["overall_status"] == "FAIL"


def test_deny_jira_write_for_viewer():
    tool = ToolCallContext(name="jira", operation="create_issue")
    result = admission_check(
        tool,
        _request(caller={"id": "u_99", "role": "viewer"}),
        policy=_policy(),
        signer=_signer(),
    )
    assert result.decision == "deny"
    assert result.rules_fired == ["jira_write_role_gate"]


# --------------------------------------------------------------------------- #
# No-policy path                                                              #
# --------------------------------------------------------------------------- #


def test_no_tool_call_policy_defaults_allow_and_omits_block():
    # A policy with verification + access_control but no tool_call_control.
    policy = Policy.from_text(
        """
version: 1
policy_id: chunks-only-v1

verification:
  block_unauthorized: true

access_control:
  rules:
    - name: r
      require: { chunk.metadata.classification: { in: [public] } }
      on_violation: deny
"""
    )
    tool = ToolCallContext(name="anything", operation="op")
    result = admission_check(tool, _request(), policy=policy, signer=_signer())
    assert result.decision == "allow"
    assert result.rules_fired == []
    assert result.policy_id == "none"

    d = result.receipt.to_dict()
    # Action is recorded; tool_call_control block is omitted.
    assert len(d["actions"]) == 1
    assert "tool_call_control" not in d["policy"]
    assert d["summary"]["actions_allowed"] == 1


def test_policy_none_defaults_allow():
    """Passing policy=None is the most permissive shape — useful for
    development and for callers that want a signed receipt but no
    enforcement.
    """
    tool = ToolCallContext(name="t", operation="op")
    result = admission_check(tool, _request(), policy=None, signer=_signer())
    assert result.decision == "allow"


# --------------------------------------------------------------------------- #
# Trajectory composition                                                      #
# --------------------------------------------------------------------------- #


def test_trajectory_composition_with_default_step_kind():
    trj = start_trajectory(agent_id="incident_agent")
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "x"},
        target_system="google_custom_search",
    )
    result = admission_check(
        tool,
        _request(),
        policy=_policy(),
        signer=_signer(),
        trajectory=trj,
    )
    # The emitted receipt carries step_kind="tool_call" — the default
    # for admission emissions when the cursor itself has no step_kind.
    d = result.receipt.to_dict()
    assert d["trajectory"]["step_kind"] == "tool_call"
    assert d["trajectory"]["trajectory_id"] == trj.trajectory_id
    # The advanced cursor references this receipt as parent.
    assert result.next_trajectory is not None
    assert result.next_trajectory.parent_step_ids == (result.receipt.receipt_id,)
    assert result.next_trajectory.step_index == 1


def test_trajectory_compose_with_explicit_step_kind_override():
    trj = start_trajectory()
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        target_system="google_custom_search",
    )
    result = admission_check(
        tool, _request(), policy=_policy(), signer=_signer(),
        trajectory=trj, step_kind="memory_write",
    )
    assert result.receipt.to_dict()["trajectory"]["step_kind"] == "memory_write"


# --------------------------------------------------------------------------- #
# Signature                                                                   #
# --------------------------------------------------------------------------- #


def test_full_receipt_signature_verifies():
    signer = _signer()
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "x"},
        target_system="google_custom_search",
    )
    result = admission_check(tool, _request(), policy=_policy(), signer=signer)
    d = result.receipt.to_dict()
    assert verify_receipt_signature(d, signer) is True


def test_tampering_with_decision_invalidates_signature():
    signer = _signer()
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "x"},
        target_system="duckduckgo",
    )
    result = admission_check(tool, _request(), policy=_policy(), signer=signer)
    d = result.receipt.to_dict()
    assert verify_receipt_signature(d, signer) is True
    # Flip the decision under the signature.
    d["policy"]["tool_call_control"]["decisions"][0]["decision"] = "allow"
    assert verify_receipt_signature(d, signer) is False


# --------------------------------------------------------------------------- #
# Parameter redaction                                                         #
# --------------------------------------------------------------------------- #


def test_redact_parameters_writes_null_but_preserves_hash():
    verbatim = {"q": "extremely sensitive query with PII"}
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters=verbatim,
        target_system="google_custom_search",
    )
    result = admission_check(
        tool, _request(), policy=_policy(), signer=_signer(),
        redact_parameters=True,
    )
    d = result.receipt.to_dict()
    assert d["actions"][0]["parameters"] is None
    expected = compute_parameters_hash(verbatim)
    assert d["actions"][0]["parameters_hash"] == expected


def test_redact_inputs_drops_inputs_but_keeps_inputs_hash():
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "x"},
        target_system="google_custom_search",
    )
    result = admission_check(
        tool, _request(), policy=_policy(), signer=_signer(),
        redact_inputs=True,
    )
    d = result.receipt.to_dict()
    dec = d["policy"]["tool_call_control"]["decisions"][0]
    assert dec["inputs"] is None
    assert dec["inputs_hash"].startswith("sha256:")


# --------------------------------------------------------------------------- #
# enforce_admission convenience wrapper                                       #
# --------------------------------------------------------------------------- #


def test_enforce_admission_returns_on_allow():
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "weather"},
        target_system="google_custom_search",
    )
    result = enforce_admission(tool, _request(), policy=_policy(), signer=_signer())
    assert result.allowed is True


def test_enforce_admission_raises_on_deny():
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "x"},
        target_system="duckduckgo",
    )
    with pytest.raises(ToolCallDenied) as exc_info:
        enforce_admission(tool, _request(), policy=_policy(), signer=_signer())
    # The receipt is reachable on the exception for downstream audit.
    assert exc_info.value.result.receipt.receipt_id.startswith("prx_")
    assert exc_info.value.result.decision == "deny"
    assert "web_search_provider_allowlist" in str(exc_info.value)
