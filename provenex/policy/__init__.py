"""Policy engines.

This package houses two distinct policy concerns:

* :mod:`provenex.policy.policy` — :class:`VerificationPolicy`. Gates
  chunks on the five verification outcomes (VERIFIED / STALE /
  UNAUTHORIZED / UNVERIFIED / TAMPERED). Shipped since v0.1.

* :mod:`provenex.policy.evaluator` and
  :mod:`provenex.policy.yaml_evaluator` — the schema-1.5.0 data-access
  policy framework. Pluggable evaluator backends (native YAML in v0.4;
  Rego and OPA-service reserved for commercial) decide allow / deny on
  each (chunk, request) pair using the operator's own rules — origin,
  freshness, access, jurisdiction, PII tags, classification.

A chunk reaches the LLM only if it clears BOTH gates. The receipt
records both verdicts so an auditor can reason about them independently.
"""

from .evaluator import (
    DECISION_ALLOW,
    DECISION_ALLOW_WITH_CONDITIONS,
    DECISION_DENY,
    EVALUATOR_CUSTOM,
    EVALUATOR_NATIVE_YAML,
    EVALUATOR_NONE,
    EVALUATOR_OPA_SERVICE,
    EVALUATOR_REGO,
    NO_POLICY_ID,
    ChunkContext,
    NullPolicyEvaluator,
    PolicyDecision,
    PolicyError,
    PolicyEvaluator,
    PolicyParseError,
    RequestContext,
    UnsupportedPolicyFeature,
    compute_inputs_hash,
    compute_policy_version_hash,
)
from .policy import VerificationPolicy, overall_status
from .unified import Policy, build_access_control_metadata, coerce_policy
from .yaml_evaluator import NativeYamlEvaluator, validate_policy_file

__all__ = [
    # Unified policy (schema 2.0.0)
    "Policy",
    "coerce_policy",
    "build_access_control_metadata",
    # Verification gate (the five-outcome half)
    "VerificationPolicy",
    "overall_status",
    # Data-access policy framework (schema 1.5.0)
    "ChunkContext",
    "RequestContext",
    "PolicyDecision",
    "PolicyEvaluator",
    "PolicyError",
    "PolicyParseError",
    "UnsupportedPolicyFeature",
    "NullPolicyEvaluator",
    "NativeYamlEvaluator",
    "validate_policy_file",
    "compute_policy_version_hash",
    "compute_inputs_hash",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "DECISION_ALLOW_WITH_CONDITIONS",
    "EVALUATOR_NATIVE_YAML",
    "EVALUATOR_REGO",
    "EVALUATOR_OPA_SERVICE",
    "EVALUATOR_CUSTOM",
    "EVALUATOR_NONE",
    "NO_POLICY_ID",
]
