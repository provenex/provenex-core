"""Phase 2 tests for ``ProvenexCrewSession``.

Covers the new tool-call admission surface added in 0.6.2:

    * ``ProvenexCrewSession`` accepts a unified :class:`Policy`
      carrying ``tool_call_control`` alongside the legacy
      :class:`VerificationPolicy` path.
    * ``session.admission_check(...)`` threads trajectory state and
      appends receipts.
    * ``session.wrap_tool_admission(...)`` runs admission **before**
      invoking the underlying tool; denials raise
      :class:`ToolCallDenied` (or trigger ``on_deny``).
    * The wrapper's parameter shape mirrors the LangChain wrapper —
      sole positional → ``{"input": arg}``, kwargs become parameters,
      reserved ``__operation__`` / ``__target_system__`` /
      ``__invocation_id__`` overrides.
    * Mixed retrieval + admission in one session links into one
      trajectory; the full DAG audits end-to-end.
"""

from __future__ import annotations

from typing import Any, List

import pytest

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    ToolCallContext,
    ToolCallDenied,
)
from provenex.core.trajectory import audit_trajectory_dag
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.crewai import ProvenexCrewSession


SECRET = b"crewai-admission-test-secret"


POLICY_YAML = """
version: 1
policy_id: crewai-admission-test-v1
tool_call_control:
  rules:
    - name: web_search_domain_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search]
      on_violation: deny
    - name: jira_write_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue] }
      require:
        request.caller.role: { in: [engineer, manager] }
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


def _session(**overrides) -> ProvenexCrewSession:
    """Construct a session with the test policy + signer."""
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    defaults = dict(
        index=index,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        agent_id="crew_agent",
    )
    defaults.update(overrides)
    return ProvenexCrewSession(**defaults)


def _request(role: str = "engineer", **overrides) -> RequestContext:
    base = dict(
        caller={"id": "u_42", "role": role},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )
    base.update(overrides)
    return RequestContext(**base)


# --------------------------------------------------------------------------- #
# Policy backward-compatibility on session construction                       #
# --------------------------------------------------------------------------- #


def test_session_accepts_unified_policy():
    """A unified Policy with tool_call_control lights up admission."""
    session = _session()
    assert session.policy.tool_call_control is not None
    assert session.policy.tool_call_control.policy_id == "crewai-admission-test-v1"


def test_session_still_accepts_bare_verification_policy():
    """Phase 1 callers passing a VerificationPolicy continue to work."""
    from provenex.policy.policy import VerificationPolicy

    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    session = ProvenexCrewSession(
        index=index, policy=VerificationPolicy(block_unauthorized=True)
    )
    assert session.policy.verification.block_unauthorized is True
    assert session.policy.tool_call_control is None


# --------------------------------------------------------------------------- #
# session.admission_check                                                     #
# --------------------------------------------------------------------------- #


def test_admission_check_allow_threads_trajectory_and_appends_receipt():
    session = _session()
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "auth-gateway runbook"},
        target_system="google_custom_search",
    )
    result = session.admission_check(tool, _request())
    assert result.allowed is True
    assert result.rules_fired == ["web_search_domain_allowlist"]
    # Session trajectory advanced and receipt is on the session.
    assert session.trajectory.step_index == 1
    assert session.trajectory.parent_step_ids == (result.receipt.receipt_id,)
    assert len(session.receipts) == 1


def test_admission_check_deny_still_emits_receipt():
    session = _session()
    tool = ToolCallContext(
        name="web_search",
        operation="query",
        parameters={"q": "x"},
        target_system="duckduckgo",
    )
    result = session.admission_check(tool, _request())
    assert result.allowed is False
    # Denials are auditable — the receipt is appended to the session.
    assert len(session.receipts) == 1
    d = session.receipts[0].to_dict()
    assert d["policy"]["tool_call_control"]["decisions"][0]["decision"] == "deny"


def test_admission_check_step_kind_defaults_to_tool_call():
    session = _session()
    tool = ToolCallContext(
        name="web_search", operation="query",
        parameters={"q": "x"}, target_system="google_custom_search",
    )
    result = session.admission_check(tool, _request())
    assert result.receipt.to_dict()["trajectory"]["step_kind"] == "tool_call"


# --------------------------------------------------------------------------- #
# session.wrap_tool_admission                                                 #
# --------------------------------------------------------------------------- #


def _request_factory(*args: Any, **kwargs: Any) -> RequestContext:
    """Pulls caller role from kwargs; ergonomic for tests."""
    return _request(role=kwargs.get("__caller_role__", "engineer"))


def test_wrap_tool_admission_allow_invokes_underlying_tool():
    session = _session()
    calls: List[Any] = []

    def search_tool(q: str) -> str:
        calls.append(q)
        return f"results for {q}"

    wrapped = session.wrap_tool_admission(
        search_tool,
        name="web_search",
        operation="query",
        target_system="google_custom_search",
        request_factory=_request_factory,
    )
    result = wrapped("weather today")
    assert result == "results for weather today"
    assert calls == ["weather today"]
    # One receipt was emitted, marked allow.
    assert len(session.receipts) == 1
    d = session.receipts[0].to_dict()
    assert d["actions"][0]["parameters"] == {"input": "weather today"}
    assert d["policy"]["tool_call_control"]["decisions"][0]["decision"] == "allow"


def test_wrap_tool_admission_deny_raises_and_does_not_invoke():
    session = _session()
    calls: List[Any] = []

    def search_tool(q: str) -> str:
        calls.append(q)
        return "should not run"

    wrapped = session.wrap_tool_admission(
        search_tool,
        name="web_search",
        operation="query",
        target_system="duckduckgo",   # not allowlisted
        request_factory=_request_factory,
    )
    with pytest.raises(ToolCallDenied) as exc_info:
        wrapped("anything")
    assert calls == []
    # Receipt still recorded.
    assert len(session.receipts) == 1
    assert exc_info.value.result.decision == "deny"


def test_wrap_tool_admission_on_deny_callback_replaces_exception():
    session = _session()
    seen: List[str] = []

    def on_deny(result):
        seen.append(result.policy_id)
        return {"error": "denied", "receipt_id": result.receipt.receipt_id}

    def search_tool(q: str) -> str:
        return "n/a"

    wrapped = session.wrap_tool_admission(
        search_tool,
        name="web_search",
        operation="query",
        target_system="duckduckgo",
        request_factory=_request_factory,
        on_deny=on_deny,
    )
    out = wrapped("x")
    assert seen == ["crewai-admission-test-v1"]
    assert out["error"] == "denied"
    assert out["receipt_id"].startswith("prx_")


def test_wrap_tool_admission_per_call_overrides():
    session = _session()
    forwarded: List[Any] = []

    def jira_tool(**kwargs: Any) -> str:
        forwarded.append(kwargs)
        return "ok"

    wrapped = session.wrap_tool_admission(
        jira_tool,
        name="jira",
        operation="default_op",
        request_factory=_request_factory,
    )
    wrapped(
        project="INC",
        summary="...",
        __operation__="create_issue",
        __target_system__="acme.atlassian.net",
        __invocation_id__="inv_xyz",
    )
    d = session.receipts[0].to_dict()
    assert d["actions"][0]["operation"] == "create_issue"
    assert d["actions"][0]["target_system"] == "acme.atlassian.net"
    assert d["actions"][0]["invocation_id"] == "inv_xyz"
    # The double-underscore keys are stripped before being forwarded
    # to the underlying tool.
    assert "__operation__" not in forwarded[0]
    assert "__target_system__" not in forwarded[0]


def test_wrap_tool_admission_custom_params_extractor():
    session = _session()

    def web_search(*args: Any, **kwargs: Any) -> str:
        return "ok"

    # Caller wants `query` extracted explicitly as `q` in the policy
    # decision inputs.
    wrapped = session.wrap_tool_admission(
        web_search,
        name="web_search",
        operation="query",
        target_system="google_custom_search",
        request_factory=_request_factory,
        params_extractor=lambda *a, **kw: {"q": kw.get("query", "")},
    )
    wrapped(query="latest CVE")
    d = session.receipts[0].to_dict()
    assert d["actions"][0]["parameters"] == {"q": "latest CVE"}


# --------------------------------------------------------------------------- #
# Mixed retrieval + admission in one session                                  #
# --------------------------------------------------------------------------- #


def test_mixed_retrieve_and_admit_compose_one_trajectory():
    """Phase 1 verify_chunks + Phase 2 admission_check on the same
    session must produce one DAG that audits end-to-end."""
    session = _session()
    # Step 0: verify some content (will be UNVERIFIED since the index
    # is empty in this fixture; the session's verification policy
    # doesn't block unverified by default so the receipt emits cleanly).
    session.verify_chunks("some chunk that wasn't ingested")
    # Step 1: tool-call admission.
    tool = ToolCallContext(
        name="web_search", operation="query",
        parameters={"q": "x"}, target_system="google_custom_search",
    )
    session.admission_check(tool, _request())
    # Step 2: another retrieve.
    session.verify_chunks("another chunk")

    assert len(session.receipts) == 3
    # All three receipts share a trajectory_id.
    ids = {r.to_dict()["trajectory"]["trajectory_id"] for r in session.receipts}
    assert len(ids) == 1
    # And the full DAG validates.
    audit = audit_trajectory_dag([r.to_dict() for r in session.receipts])
    assert audit.ok is True


def test_step_kinds_are_correct_for_each_emission():
    session = _session()
    session.verify_chunks("chunk")
    session.admission_check(
        ToolCallContext(
            name="web_search", operation="query",
            parameters={"q": "x"}, target_system="google_custom_search",
        ),
        _request(),
    )
    kinds = [
        r.to_dict()["trajectory"]["step_kind"] for r in session.receipts
    ]
    assert kinds == ["retrieval", "tool_call"]
