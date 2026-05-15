"""Tool-call admission — Phase 2 of Provenex.

This is the second enforcement front-end on the same policy-and-proof spine
that Phase 1 built for retrieval. Where Phase 1 fingerprints content and
verifies a retrieved chunk against a signed index (the five outcomes),
Phase 2 intercepts an action attempt — agent wants to call tool X with
parameters Y on behalf of caller Z — evaluates it against declarative
policy, and emits a signed receipt with the decision.

Scope discipline (load-bearing):

    Decision and proof, not execution.

The admission API never holds OAuth tokens, never proxies the call, and
never sits on the response data path. The caller still executes the call
with its own credentials after we return ``allow``. We are a Kubernetes-
admission-controller-shaped layer, not a service mesh.

What's reused verbatim from Phase 1:

    * :class:`provenex.core.receipt.ReceiptBuilder` and the signers
      (HMAC + Ed25519)
    * :class:`provenex.core.trajectory.TrajectoryContext` —
      ``step_kind="tool_call"`` was reserved in schema 1.3.0 for exactly
      this case
    * :class:`provenex.policy.evaluator.PolicyDecision`,
      :class:`RequestContext`, and the ``metadata_binding`` discipline
    * The native YAML DSL grammar (``when`` / ``require`` /
      ``on_violation``) and the existing operators

What's new in this subpackage:

    * :class:`ToolCallContext` — the per-call view the evaluator sees,
      analogous to :class:`provenex.policy.evaluator.ChunkContext`
    * :class:`ToolCallPolicyEvaluator` — sibling :class:`Protocol` to
      :class:`PolicyEvaluator`, same shape, different ``evaluate``
      first-arg
    * :func:`admission_check` — the one-shot framework-agnostic API
      (built in a later module)
"""

from .admission import (
    AdmissionResult,
    ToolCallDenied,
    admission_check,
    admit_memory_write,
    admit_model_inference,
    enforce_admission,
)
from .context import ToolCallContext
from .evaluator import (
    DECISION_ALLOW,
    DECISION_DENY,
    NullToolCallPolicyEvaluator,
    ToolCallPolicyEvaluator,
    build_tool_call_control_metadata,
    build_tool_call_inputs,
    compute_parameters_hash,
)
from .yaml_evaluator import (
    NativeYamlToolCallEvaluator,
    validate_tool_call_policy_file,
)

__all__ = [
    "ToolCallContext",
    "ToolCallPolicyEvaluator",
    "NullToolCallPolicyEvaluator",
    "NativeYamlToolCallEvaluator",
    "AdmissionResult",
    "ToolCallDenied",
    "admission_check",
    "admit_memory_write",
    "admit_model_inference",
    "enforce_admission",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "build_tool_call_control_metadata",
    "build_tool_call_inputs",
    "compute_parameters_hash",
    "validate_tool_call_policy_file",
]
