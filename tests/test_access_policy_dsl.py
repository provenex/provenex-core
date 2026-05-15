"""Tests for the native YAML data-access policy DSL (schema 1.5.0)."""

from __future__ import annotations

import pytest

from provenex.policy.evaluator import (
    DECISION_ALLOW,
    DECISION_DENY,
    EVALUATOR_NATIVE_YAML,
    EVALUATOR_NONE,
    NO_POLICY_ID,
    ChunkContext,
    NullPolicyEvaluator,
    PolicyParseError,
    RequestContext,
    UnsupportedPolicyFeature,
)
from provenex.policy.yaml_evaluator import NativeYamlEvaluator, validate_policy_file


# --------------------------------------------------------------------------- #
# Fixtures and helpers                                                        #
# --------------------------------------------------------------------------- #


def _chunk(**overrides):
    base = dict(
        fingerprint="sha256:abc",
        document_id="doc-1",
        document_version="v1",
        ingested_at="2026-05-01T00:00:00Z",
        metadata={},
        content_source=None,
    )
    base.update(overrides)
    return ChunkContext(**base)


def _request(**overrides):
    base = dict(
        caller={"role": "user"},
        jurisdiction=None,
        purpose=None,
        timestamp="2026-05-13T00:00:00Z",
    )
    base.update(overrides)
    return RequestContext(**base)


HR_POLICY = """
version: 1
policy_id: hr-corpus-v3
rules:
  - name: jurisdiction_eu_only
    when:
      request.jurisdiction: EU
    require:
      chunk.metadata.residency:
        in: [EU, EEA]
    on_violation: deny

  - name: pii_classification_gate
    when:
      chunk.metadata.contains_pii: true
    require:
      request.caller.role:
        in: [hr_admin, payroll]
    on_violation: deny

  - name: freshness_for_policy_corpus
    when:
      chunk.metadata.corpus: policy_documents
    require:
      chunk.ingested_at:
        not_older_than: 90d
    on_violation: deny

defaults:
  unknown_metadata: deny
  policy_version_mismatch: deny
"""


# --------------------------------------------------------------------------- #
# Evaluator metadata                                                          #
# --------------------------------------------------------------------------- #


def test_native_yaml_evaluator_reports_id_and_name():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    assert ev.policy_id == "hr-corpus-v3"
    assert ev.evaluator_name == EVALUATOR_NATIVE_YAML
    assert ev.policy_version_hash.startswith("sha256:")


def test_null_evaluator_allows_everything_and_records_none_id():
    ev = NullPolicyEvaluator()
    assert ev.policy_id == NO_POLICY_ID
    assert ev.evaluator_name == EVALUATOR_NONE
    d = ev.evaluate(_chunk(), _request())
    assert d.decision == DECISION_ALLOW
    assert d.rules_fired == []


# --------------------------------------------------------------------------- #
# `when` clause semantics                                                     #
# --------------------------------------------------------------------------- #


def test_when_clause_scopes_rule_to_matching_chunks():
    # The EU-only rule should not fire for US requests.
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={"residency": "US"})
    req = _request(jurisdiction="US")
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_ALLOW
    assert "jurisdiction_eu_only" not in d.rules_fired


def test_when_clause_fires_rule_when_condition_matches():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={"residency": "EU"})
    req = _request(jurisdiction="EU")
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_ALLOW
    assert "jurisdiction_eu_only" in d.rules_fired


def test_when_clause_with_missing_path_does_not_fire():
    # No `request.jurisdiction` (None) does not match `EU`, so the rule
    # is out of scope.
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={"residency": "EU"})
    req = _request(jurisdiction=None)
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_ALLOW
    assert d.rules_fired == []


# --------------------------------------------------------------------------- #
# `require` operators                                                         #
# --------------------------------------------------------------------------- #


def test_in_operator_allow_when_value_in_list():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={"residency": "EEA"})
    req = _request(jurisdiction="EU")
    assert ev.evaluate(chunk, req).decision == DECISION_ALLOW


def test_in_operator_deny_when_value_not_in_list():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={"residency": "US"})
    req = _request(jurisdiction="EU")
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_DENY
    assert d.rules_fired == ["jurisdiction_eu_only"]


def test_in_operator_with_missing_metadata_defaults_to_deny():
    # No residency metadata at all + EU jurisdiction + default deny.
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={})
    req = _request(jurisdiction="EU")
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_DENY


def test_in_operator_with_missing_metadata_when_default_allow():
    policy = """
version: 1
policy_id: test
rules:
  - name: r
    when:
      request.jurisdiction: EU
    require:
      chunk.metadata.residency:
        in: [EU]
    on_violation: deny
defaults:
  unknown_metadata: allow
  policy_version_mismatch: deny
"""
    ev = NativeYamlEvaluator.from_text(policy)
    chunk = _chunk(metadata={})
    req = _request(jurisdiction="EU")
    assert ev.evaluate(chunk, req).decision == DECISION_ALLOW


def test_not_in_operator():
    policy = """
version: 1
policy_id: test
rules:
  - name: r
    when:
      chunk.metadata.tier: prod
    require:
      chunk.metadata.classification:
        not_in: [confidential, secret]
    on_violation: deny
"""
    ev = NativeYamlEvaluator.from_text(policy)
    # not in denylist → allow
    allow_chunk = _chunk(
        metadata={"tier": "prod", "classification": "public"}
    )
    assert ev.evaluate(allow_chunk, _request()).decision == DECISION_ALLOW
    # in denylist → deny
    deny_chunk = _chunk(
        metadata={"tier": "prod", "classification": "secret"}
    )
    assert ev.evaluate(deny_chunk, _request()).decision == DECISION_DENY


def test_direct_equality_operator():
    policy = """
version: 1
policy_id: eq-test
rules:
  - name: must_be_eu
    when:
      chunk.metadata.tier: prod
    require:
      chunk.metadata.residency: EU
    on_violation: deny
"""
    ev = NativeYamlEvaluator.from_text(policy)
    eu = _chunk(metadata={"tier": "prod", "residency": "EU"})
    us = _chunk(metadata={"tier": "prod", "residency": "US"})
    assert ev.evaluate(eu, _request()).decision == DECISION_ALLOW
    assert ev.evaluate(us, _request()).decision == DECISION_DENY


def test_not_older_than_with_fresh_chunk_allows():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    # Ingested 30d before request — within 90d window.
    chunk = _chunk(
        metadata={"corpus": "policy_documents"},
        ingested_at="2026-04-13T00:00:00Z",
    )
    req = _request(timestamp="2026-05-13T00:00:00Z")
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_ALLOW
    assert "freshness_for_policy_corpus" in d.rules_fired


def test_not_older_than_with_stale_chunk_denies():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    # Ingested ~120d before request — outside 90d window.
    chunk = _chunk(
        metadata={"corpus": "policy_documents"},
        ingested_at="2026-01-13T00:00:00Z",
    )
    req = _request(timestamp="2026-05-13T00:00:00Z")
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_DENY
    assert d.rules_fired == ["freshness_for_policy_corpus"]


# --------------------------------------------------------------------------- #
# Multiple rules, rules_fired trace                                           #
# --------------------------------------------------------------------------- #


def test_multiple_rules_fire_and_all_pass():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(
        metadata={
            "residency": "EU",
            "contains_pii": True,
            "corpus": "policy_documents",
        },
        ingested_at="2026-04-13T00:00:00Z",
    )
    req = _request(
        caller={"role": "hr_admin"},
        jurisdiction="EU",
        timestamp="2026-05-13T00:00:00Z",
    )
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_ALLOW
    assert set(d.rules_fired) == {
        "jurisdiction_eu_only",
        "pii_classification_gate",
        "freshness_for_policy_corpus",
    }


def test_first_violating_rule_denies_and_records_partial_trace():
    # PII gate fires first in policy order — but the EU rule comes earlier
    # and passes. The PII gate then denies.
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={"residency": "EU", "contains_pii": True})
    req = _request(caller={"role": "intern"}, jurisdiction="EU")
    d = ev.evaluate(chunk, req)
    assert d.decision == DECISION_DENY
    # jurisdiction_eu_only fired and passed; pii_classification_gate fired
    # and denied — both are in the trace.
    assert "jurisdiction_eu_only" in d.rules_fired
    assert "pii_classification_gate" in d.rules_fired


# --------------------------------------------------------------------------- #
# Caller-side path resolution                                                 #
# --------------------------------------------------------------------------- #


def test_request_caller_role_path_resolves():
    ev = NativeYamlEvaluator.from_text(HR_POLICY)
    chunk = _chunk(metadata={"contains_pii": True})
    req_admin = _request(caller={"role": "hr_admin"})
    req_user = _request(caller={"role": "intern"})
    assert ev.evaluate(chunk, req_admin).decision == DECISION_ALLOW
    assert ev.evaluate(chunk, req_user).decision == DECISION_DENY


# --------------------------------------------------------------------------- #
# Parse errors                                                                #
# --------------------------------------------------------------------------- #


def test_malformed_yaml_raises_parse_error_with_location():
    with pytest.raises(PolicyParseError) as info:
        NativeYamlEvaluator.from_text(": bad yaml [")
    assert "line" in str(info.value).lower() or "yaml" in str(info.value).lower()


def test_missing_policy_id_raises():
    with pytest.raises(PolicyParseError, match="policy_id"):
        NativeYamlEvaluator.from_text("version: 1\nrules: []\n")


def test_wrong_version_raises():
    with pytest.raises(PolicyParseError, match="version"):
        NativeYamlEvaluator.from_text("version: 2\npolicy_id: p\nrules: []\n")


def test_rule_missing_name_raises():
    bad = """
version: 1
policy_id: p
rules:
  - require:
      chunk.metadata.x: y
    on_violation: deny
"""
    with pytest.raises(PolicyParseError, match="name"):
        NativeYamlEvaluator.from_text(bad)


def test_unknown_rule_key_raises():
    bad = """
version: 1
policy_id: p
rules:
  - name: r
    typo_here: oops
    on_violation: deny
"""
    with pytest.raises(PolicyParseError, match="unknown keys"):
        NativeYamlEvaluator.from_text(bad)


def test_unknown_require_operator_raises():
    bad = """
version: 1
policy_id: p
rules:
  - name: r
    require:
      chunk.metadata.x:
        contains: foo
    on_violation: deny
"""
    with pytest.raises(PolicyParseError, match="unknown operator"):
        NativeYamlEvaluator.from_text(bad)


def test_invalid_duration_raises():
    bad = """
version: 1
policy_id: p
rules:
  - name: r
    require:
      chunk.ingested_at:
        not_older_than: 90 days
    on_violation: deny
"""
    with pytest.raises(PolicyParseError, match="duration"):
        NativeYamlEvaluator.from_text(bad)


def test_unknown_defaults_key_raises():
    bad = """
version: 1
policy_id: p
rules: []
defaults:
  unknown_metadata: deny
  oops_typo: deny
"""
    with pytest.raises(PolicyParseError, match="unknown keys"):
        NativeYamlEvaluator.from_text(bad)


# --------------------------------------------------------------------------- #
# Unsupported features                                                        #
# --------------------------------------------------------------------------- #


def test_any_of_raises_unsupported_feature():
    bad = """
version: 1
policy_id: p
rules:
  - name: r
    any_of:
      - chunk.metadata.x: y
    on_violation: deny
"""
    with pytest.raises(UnsupportedPolicyFeature, match="any_of"):
        NativeYamlEvaluator.from_text(bad)


def test_all_of_raises_unsupported_feature():
    bad = """
version: 1
policy_id: p
rules:
  - name: r
    all_of:
      - chunk.metadata.x: y
    on_violation: deny
"""
    with pytest.raises(UnsupportedPolicyFeature, match="all_of"):
        NativeYamlEvaluator.from_text(bad)


# --------------------------------------------------------------------------- #
# validate_policy_file CLI helper                                             #
# --------------------------------------------------------------------------- #


def test_validate_policy_file_on_valid_file(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(HR_POLICY, encoding="utf-8")
    ok, err = validate_policy_file(str(p))
    assert ok is True
    assert err is None


def test_validate_policy_file_on_missing_file(tmp_path):
    ok, err = validate_policy_file(str(tmp_path / "does-not-exist.yaml"))
    assert ok is False
    assert err is not None


def test_validate_policy_file_on_invalid(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("version: 2\npolicy_id: p\nrules: []\n", encoding="utf-8")
    ok, err = validate_policy_file(str(p))
    assert ok is False
    assert "version" in err
