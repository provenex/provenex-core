"""Tests for the native YAML tool-call DSL.

Covers, end-to-end:

    * ``tool.*`` path resolution against :class:`ToolCallContext`.
    * The three new operators: ``matches_pattern``, ``not_matches_pattern``,
      ``length_at_most``.
    * Parse-time domain validation — ``access_control`` rejects
      ``tool.*`` paths; ``tool_call_control`` rejects ``chunk.*``
      paths. Cross-domain references are a load-time error, not a
      silent miss.
    * Unified policy file parsing — ``Policy.from_yaml`` lights up the
      ``tool_call_control`` half when present and leaves it ``None``
      when absent.
    * ``policy_version_hash`` covers only the tool-call subset and is
      stable across whitespace / key-order / verification-half changes.
"""

from __future__ import annotations

import pytest

from provenex import (
    NativeYamlToolCallEvaluator,
    Policy,
    RequestContext,
    ToolCallContext,
)
from provenex.policy.evaluator import (
    DECISION_ALLOW,
    DECISION_DENY,
    PolicyParseError,
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _request(**overrides):
    base = dict(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )
    base.update(overrides)
    return RequestContext(**base)


# A minimal admission policy: a `web_search` tool gated to specific
# search-providers, with PII patterns and length caps on the query
# string. A `jira` tool gated to writes-require-role.
TOOL_POLICY = """
version: 1
policy_id: agent-policy-v1
tool_call_control:
  rules:
    - name: web_search_domain_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny

    - name: no_pii_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*api*"
      on_violation: deny

    - name: query_length_cap
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          length_at_most: 64
      on_violation: deny

    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue, update_issue, delete_issue] }
      require:
        request.caller.role: { in: [engineer, manager, admin] }
      on_violation: deny

  defaults:
    unknown_metadata: deny
"""


def _eval(text=TOOL_POLICY) -> NativeYamlToolCallEvaluator:
    return NativeYamlToolCallEvaluator.from_text(text, source="<test>")


# --------------------------------------------------------------------------- #
# Path resolution + happy-path evaluations                                    #
# --------------------------------------------------------------------------- #


def test_web_search_allowed_provider_passes():
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "weather today"},
            target_system="google_custom_search",
        ),
        _request(),
    )
    assert decision.decision == DECISION_ALLOW
    assert "web_search_domain_allowlist" in decision.rules_fired
    assert "no_pii_in_query" in decision.rules_fired
    assert "query_length_cap" in decision.rules_fired


def test_web_search_disallowed_provider_denied():
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "test"},
            target_system="duckduckgo",
        ),
        _request(),
    )
    assert decision.decision == DECISION_DENY
    assert "web_search_domain_allowlist" in decision.rules_fired


def test_jira_write_role_gate_allows_engineer():
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(
            name="jira",
            operation="create_issue",
            parameters={"project": "INC", "summary": "..."},
        ),
        _request(caller={"id": "u_42", "role": "engineer"}),
    )
    assert decision.decision == DECISION_ALLOW
    assert decision.rules_fired == ["jira_writes_require_role"]


def test_jira_write_role_gate_denies_viewer():
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(name="jira", operation="create_issue"),
        _request(caller={"id": "u_99", "role": "viewer"}),
    )
    assert decision.decision == DECISION_DENY
    assert decision.rules_fired == ["jira_writes_require_role"]


def test_jira_read_not_gated_by_role():
    """The role gate fires on create/update/delete only — `get_issue` passes."""
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(name="jira", operation="get_issue"),
        _request(caller={"id": "u_99", "role": "viewer"}),
    )
    assert decision.decision == DECISION_ALLOW
    # No rules fired at all — neither tool.name=web_search nor the role gate's
    # when clause matched.
    assert decision.rules_fired == []


# --------------------------------------------------------------------------- #
# Operators                                                                   #
# --------------------------------------------------------------------------- #


def test_matches_pattern_glob_basic():
    ev = NativeYamlToolCallEvaluator.from_text(
        """
version: 1
policy_id: t1
rules:
  - name: url_allowlist
    when: { tool.name: fetch }
    require:
      tool.parameters.url:
        matches_pattern: "https://*.example.com/*"
    on_violation: deny
""",
        source="<inline>",
    )
    ok = ev.evaluate(
        ToolCallContext(
            name="fetch",
            operation="get",
            parameters={"url": "https://api.example.com/v1/users"},
        ),
        _request(),
    )
    assert ok.decision == DECISION_ALLOW

    deny = ev.evaluate(
        ToolCallContext(
            name="fetch",
            operation="get",
            parameters={"url": "https://evil.attacker.com/exfil"},
        ),
        _request(),
    )
    assert deny.decision == DECISION_DENY


def test_not_matches_pattern_blocks_match():
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "my api key is leaking"},
            target_system="google_custom_search",
        ),
        _request(),
    )
    assert decision.decision == DECISION_DENY
    assert "no_pii_in_query" in decision.rules_fired


def test_length_at_most_caps_string():
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "x" * 65},
            target_system="google_custom_search",
        ),
        _request(),
    )
    assert decision.decision == DECISION_DENY
    assert "query_length_cap" in decision.rules_fired


def test_length_at_most_passes_at_boundary():
    ev = _eval()
    decision = ev.evaluate(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "x" * 64},
            target_system="google_custom_search",
        ),
        _request(),
    )
    assert decision.decision == DECISION_ALLOW


# --------------------------------------------------------------------------- #
# Domain validation: cross-domain references fail at parse time               #
# --------------------------------------------------------------------------- #


def test_tool_rule_referencing_chunk_path_rejected_at_parse():
    with pytest.raises(PolicyParseError, match=r"chunk.*not allowed"):
        NativeYamlToolCallEvaluator.from_text(
            """
version: 1
policy_id: bad
rules:
  - name: cross_domain
    when: { chunk.metadata.classification: secret }
    require:
      tool.parameters.q: { in: [allowed] }
    on_violation: deny
""",
            source="<inline>",
        )


def test_chunk_rule_referencing_tool_path_rejected_at_parse():
    """the retrieval evaluator rejects ``tool.*`` paths in access_control rules.

    Same strict-load discipline applied to the other direction.
    """
    from provenex import NativeYamlEvaluator

    with pytest.raises(PolicyParseError, match=r"tool.*not allowed"):
        NativeYamlEvaluator.from_text(
            """
version: 1
policy_id: bad
rules:
  - name: cross_domain
    when: { tool.name: web_search }
    require:
      chunk.metadata.classification: { in: [public] }
    on_violation: deny
""",
            source="<inline>",
        )


# --------------------------------------------------------------------------- #
# Bad operator inputs fail at parse                                           #
# --------------------------------------------------------------------------- #


def test_matches_pattern_non_string_rejected():
    with pytest.raises(PolicyParseError, match="matches_pattern.*string"):
        NativeYamlToolCallEvaluator.from_text(
            """
version: 1
policy_id: t
rules:
  - name: r
    require:
      tool.parameters.q: { matches_pattern: 42 }
    on_violation: deny
""",
            source="<inline>",
        )


def test_length_at_most_non_int_rejected():
    with pytest.raises(PolicyParseError, match="non-negative integer"):
        NativeYamlToolCallEvaluator.from_text(
            """
version: 1
policy_id: t
rules:
  - name: r
    require:
      tool.parameters.q: { length_at_most: "lots" }
    on_violation: deny
""",
            source="<inline>",
        )


def test_length_at_most_negative_rejected():
    with pytest.raises(PolicyParseError, match="non-negative integer"):
        NativeYamlToolCallEvaluator.from_text(
            """
version: 1
policy_id: t
rules:
  - name: r
    require:
      tool.parameters.q: { length_at_most: -1 }
    on_violation: deny
""",
            source="<inline>",
        )


# --------------------------------------------------------------------------- #
# Unified Policy.from_yaml                                                    #
# --------------------------------------------------------------------------- #


UNIFIED_WITH_TOOL_CALLS = """
version: 1
policy_id: agent-policy-v2

verification:
  block_unauthorized: true
  block_tampered: true

access_control:
  rules:
    - name: eu_residency
      when: { request.jurisdiction: EU }
      require:
        chunk.metadata.residency: { in: [EU, EEA] }
      on_violation: deny

tool_call_control:
  rules:
    - name: web_search_domain
      when: { tool.name: web_search }
      require:
        tool.target_system: { in: [google_custom_search] }
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


def test_unified_yaml_lights_up_all_three_halves():
    policy = Policy.from_text(UNIFIED_WITH_TOOL_CALLS)
    assert policy.verification.block_unauthorized is True
    assert policy.access_control is not None
    assert policy.access_control.policy_id == "agent-policy-v2"
    assert policy.tool_call_control is not None
    assert policy.tool_call_control.policy_id == "agent-policy-v2"
    assert policy.tool_call_control.evaluator_name == "native_yaml"


def test_unified_yaml_without_tool_call_control_leaves_field_none():
    policy = Policy.from_text(
        """
version: 1
policy_id: chunks-only

access_control:
  rules:
    - name: r
      require: { chunk.metadata.x: { in: [a] } }
      on_violation: deny
"""
    )
    assert policy.access_control is not None
    assert policy.tool_call_control is None


def test_unified_yaml_tool_call_only():
    """A unified file with only tool_call_control: still produces a Policy."""
    policy = Policy.from_text(
        """
version: 1
policy_id: tools-only

tool_call_control:
  rules:
    - name: r
      when: { tool.name: web_search }
      require: { tool.target_system: { in: [google_custom_search] } }
      on_violation: deny
"""
    )
    assert policy.access_control is None
    assert policy.tool_call_control is not None


# --------------------------------------------------------------------------- #
# policy_version_hash stability                                               #
# --------------------------------------------------------------------------- #


def test_tool_call_hash_stable_across_whitespace():
    a = _eval(TOOL_POLICY).policy_version_hash
    b = _eval(TOOL_POLICY + "\n\n\n").policy_version_hash
    assert a == b


def test_tool_call_hash_changes_when_rules_change():
    a = _eval(TOOL_POLICY).policy_version_hash
    altered = TOOL_POLICY.replace("length_at_most: 64", "length_at_most: 32")
    b = _eval(altered).policy_version_hash
    assert a != b


def test_tool_call_hash_independent_of_verification_half():
    """Two halves version independently — same retrieval invariant.

    Adding or modifying the ``verification:`` section of a unified file
    must not change the ``tool_call_control`` hash. Auditors reading
    receipts under an older tool-call policy version shouldn't see the
    hash flip just because the operator tuned a verification threshold.
    """
    base = """
version: 1
policy_id: agent-policy
{verification}
tool_call_control:
  rules:
    - name: r
      when: { tool.name: web_search }
      require: { tool.target_system: { in: [google_custom_search] } }
      on_violation: deny
"""
    # NOTE: literal `{ ... }` inside a YAML flow-mapping conflicts with
    # str.format placeholders; we hand-build instead.
    p1 = Policy.from_text(base.replace("{verification}", ""))
    p2 = Policy.from_text(
        base.replace(
            "{verification}",
            "verification:\n  block_stale: true\n  block_unauthorized: true\n",
        )
    )
    assert p1.tool_call_control is not None
    assert p2.tool_call_control is not None
    assert (
        p1.tool_call_control.policy_version_hash
        == p2.tool_call_control.policy_version_hash
    )
