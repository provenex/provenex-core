"""Tests for :class:`Policy` — the unified verification + access-control wrapper.

The Policy object is the v0.4 entry point. Tests here exercise:

* ``Policy.from_yaml`` / ``Policy.from_text`` with both sections present.
* Either section omitted (defaults applied).
* ``coerce_policy`` normalisation (Policy / VerificationPolicy / None).
* Parse errors on unknown top-level keys (typos fail loud).
"""

from __future__ import annotations

import pytest

from provenex import Policy, VerificationPolicy
from provenex.policy.evaluator import PolicyParseError
from provenex.policy.unified import coerce_policy


# --------------------------------------------------------------------------- #
# Policy.from_text — both sections present                                    #
# --------------------------------------------------------------------------- #


UNIFIED_FULL = """
version: 1
policy_id: hr-corpus-v3
description: A complete unified config for the test suite.

verification:
  block_unauthorized: true
  block_tampered: true
  block_stale: false

access_control:
  rules:
    - name: jurisdiction_eu_only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency:
          in: [EU, EEA]
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


def test_unified_yaml_loads_both_sections():
    policy = Policy.from_text(UNIFIED_FULL)
    # Verification half is honoured.
    assert policy.verification.block_unauthorized is True
    assert policy.verification.block_tampered is True
    assert policy.verification.block_stale is False
    # Access-control half is a working evaluator.
    assert policy.access_control is not None
    assert policy.access_control.policy_id == "hr-corpus-v3"
    assert policy.access_control.evaluator_name == "native_yaml"
    assert policy.access_control.policy_version_hash.startswith("sha256:")


# --------------------------------------------------------------------------- #
# Section omission — verification only / access_control only / neither        #
# --------------------------------------------------------------------------- #


def test_unified_yaml_without_access_control_uses_default():
    text = """
version: 1
policy_id: verification-only-v1
verification:
  block_unauthorized: true
  block_unverified: true
"""
    policy = Policy.from_text(text)
    assert policy.verification.block_unverified is True
    assert policy.access_control is None


def test_unified_yaml_without_verification_uses_defaults():
    text = """
version: 1
policy_id: access-only-v1
access_control:
  rules:
    - name: r
      require:
        chunk.metadata.x: y
      on_violation: deny
"""
    policy = Policy.from_text(text)
    # Verification defaults: block_unauthorized + block_tampered True;
    # everything else False/flag.
    assert policy.verification.block_unauthorized is True
    assert policy.verification.block_tampered is True
    assert policy.verification.block_stale is False
    assert policy.access_control is not None
    assert policy.access_control.policy_id == "access-only-v1"


def test_unified_yaml_empty_yields_pure_defaults():
    """A file with only ``version: 1`` produces a Policy with default
    verification and no access control. This is identical to ``Policy()``."""
    policy = Policy.from_text("version: 1")
    assert policy.access_control is None
    assert policy.verification == VerificationPolicy()


# --------------------------------------------------------------------------- #
# Loading from a file on disk                                                  #
# --------------------------------------------------------------------------- #


def test_policy_from_yaml_loads_from_disk(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text(UNIFIED_FULL, encoding="utf-8")
    policy = Policy.from_yaml(str(p))
    assert policy.access_control is not None
    assert policy.access_control.policy_id == "hr-corpus-v3"


# --------------------------------------------------------------------------- #
# Parse errors                                                                 #
# --------------------------------------------------------------------------- #


def test_unknown_top_level_key_raises():
    """A top-level typo fails loud, not silently. The cost of a silent
    accept here would be a policy whose typoed section is ignored — a
    correctness bug worse than any parse error."""
    bad = """
version: 1
policy_id: p
verificaton:                 # typo: should be 'verification'
  block_unauthorized: true
"""
    with pytest.raises(PolicyParseError, match="unknown top-level keys"):
        Policy.from_text(bad)


def test_non_boolean_verification_value_raises():
    bad = """
version: 1
policy_id: p
verification:
  block_unauthorized: "true"   # string, not bool
"""
    with pytest.raises(PolicyParseError, match="must be a boolean"):
        Policy.from_text(bad)


def test_unknown_verification_key_raises():
    bad = """
version: 1
policy_id: p
verification:
  block_unauthroized: true     # typo: missing 'i'
"""
    with pytest.raises(PolicyParseError, match="unknown keys"):
        Policy.from_text(bad)


def test_wrong_version_raises():
    with pytest.raises(PolicyParseError, match="version"):
        Policy.from_text("version: 2\npolicy_id: p\n")


# --------------------------------------------------------------------------- #
# coerce_policy normalisation                                                  #
# --------------------------------------------------------------------------- #


def test_coerce_policy_passes_policy_through():
    p = Policy(verification=VerificationPolicy(block_stale=True))
    assert coerce_policy(p) is p


def test_coerce_policy_wraps_bare_verification_policy():
    vp = VerificationPolicy(block_stale=True, block_unauthorized=False)
    coerced = coerce_policy(vp)
    assert isinstance(coerced, Policy)
    assert coerced.verification is vp
    assert coerced.access_control is None


def test_coerce_policy_handles_none():
    coerced = coerce_policy(None)
    assert isinstance(coerced, Policy)
    assert coerced.verification == VerificationPolicy()
    assert coerced.access_control is None


def test_coerce_policy_rejects_unrelated_types():
    with pytest.raises(TypeError, match="Policy, VerificationPolicy, or None"):
        coerce_policy("not a policy")


def test_coerce_policy_rejects_dict():
    """A common mistake — passing a raw config dict. Fail loud."""
    with pytest.raises(TypeError):
        coerce_policy({"verification": {"block_stale": True}})
