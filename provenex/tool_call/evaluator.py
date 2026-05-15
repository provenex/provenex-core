"""Tool-call policy evaluator interface (schema 2.2.0).

Mirrors :mod:`provenex.policy.evaluator`. The tool-call admission Protocol
takes a :class:`ToolCallContext` instead of a :class:`ChunkContext`.

Why a sibling Protocol rather than a subclass:

    The discriminator between retrieval and tool-call admission is the type of
    ``evaluate()``'s first argument. Subtyping would force either a
    union type (loses static checking benefits) or a single ``evaluate``
    method that branches at runtime on context type (ugly, error-prone).
    Two parallel Protocols cost a handful of lines and make every call
    site explicit about which decision domain it's in.

The :class:`PolicyDecision` shape is reused verbatim from the retrieval flow —
``decision``, ``rules_fired``, ``inputs_hash``, ``inputs``,
``metadata_binding`` are all content-agnostic. The :class:`RequestContext`
is also reused verbatim (caller / jurisdiction / purpose / timestamp
have the same semantics for chunk decisions and tool-call decisions).
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from ..policy.evaluator import (
    BINDING_AT_EVALUATE,
    DECISION_ALLOW,
    DECISION_DENY,
    EVALUATOR_NATIVE_YAML,
    EVALUATOR_NONE,
    NO_POLICY_ID,
    PolicyDecision,
    RequestContext,
    _canonical_bytes,
    compute_inputs_hash,
    compute_policy_version_hash,
)
from .context import ToolCallContext


# --------------------------------------------------------------------------- #
# Protocol                                                                    #
# --------------------------------------------------------------------------- #


@runtime_checkable
class ToolCallPolicyEvaluator(Protocol):
    """The interface every tool-call policy backend implements.

    Identical contract to :class:`provenex.policy.evaluator.PolicyEvaluator`:
    deterministic, side-effect-free per evaluation, stable
    ``policy_version_hash``. The only difference is that ``evaluate()``
    takes a :class:`ToolCallContext` instead of a chunk context.

    Backends MUST be deterministic: the same ``(tool, request)`` and same
    bundle MUST produce the same decision. Logging, metrics, and audit
    emission are the caller's responsibility, not the evaluator's.
    """

    @property
    def evaluator_name(self) -> str:
        """Backend identifier recorded on the receipt (``"native_yaml"`` etc).

        Both retrieval and tool-call admission share evaluator-name constants — the
        backend identity is what matters, not the domain. The receipt's
        section (``policy.access_control`` vs ``policy.tool_call_control``)
        tells an auditor which domain the decision governed.
        """
        ...

    @property
    def policy_id(self) -> str:
        """The ``policy_id`` from the loaded bundle, or ``"none"``."""
        ...

    @property
    def policy_version_hash(self) -> str:
        """``"sha256:<hex>"`` over the canonicalized tool-call bundle.

        Covers only the tool-call rules subset, not the entire unified
        bundle. Two unified files that differ only in ``access_control``
        or ``verification`` content produce the same
        ``policy_version_hash`` here, the same way the retrieval-side
        ``NativeYamlEvaluator`` only hashes the access-control subset.
        The two halves version independently.
        """
        ...

    def evaluate(
        self,
        tool: ToolCallContext,
        request: RequestContext,
    ) -> PolicyDecision:
        """Return the decision for one ``(tool, request)`` pair."""
        ...


# --------------------------------------------------------------------------- #
# Null evaluator (allow-all stub, parallel to NullPolicyEvaluator)            #
# --------------------------------------------------------------------------- #


class NullToolCallPolicyEvaluator:
    """Allow-all evaluator used when no tool-call policy is configured.

    Mirrors :class:`provenex.policy.evaluator.NullPolicyEvaluator`. When
    no ``tool_call_control:`` subsection is configured the wiring layer
    SHOULD omit the ``policy.tool_call_control`` block from the receipt
    entirely rather than emit an explicit "no policy" record — but this
    class is here for callers who want a decisions[] trace during a
    migration window.
    """

    @property
    def evaluator_name(self) -> str:
        return EVALUATOR_NONE

    @property
    def policy_id(self) -> str:
        return NO_POLICY_ID

    @property
    def policy_version_hash(self) -> str:
        return compute_policy_version_hash({})

    def evaluate(
        self,
        tool: ToolCallContext,
        request: RequestContext,
    ) -> PolicyDecision:
        inputs = build_tool_call_inputs(tool, request)
        return PolicyDecision(
            decision=DECISION_ALLOW,
            rules_fired=[],
            inputs_hash=compute_inputs_hash(inputs),
            inputs=inputs,
        )


# --------------------------------------------------------------------------- #
# Inputs canonicalisation                                                     #
# --------------------------------------------------------------------------- #


def build_tool_call_inputs(
    tool: ToolCallContext,
    request: RequestContext,
) -> Dict[str, Any]:
    """Build the canonical ``inputs`` dict for a tool-call decision record.

    Shape mirrors what retrieval emits under
    ``policy.access_control.decisions[i].inputs``: a top-level
    ``request_context`` plus a domain-specific block — ``chunk_metadata``
    in the retrieval flow, ``tool_parameters`` here.

    The full parameter values appear in ``tool_parameters.parameters``.
    Receipt-level redaction (``parameters: null`` plus the surviving
    ``parameters_hash`` on the actions[] entry) is handled at the
    receipt-emission layer, not here — the hash this function feeds into
    must always cover the verbatim parameters so an auditor with the
    original values can re-derive it.
    """
    tool_block: Dict[str, Any] = {
        "name": tool.name,
        "operation": tool.operation,
        "parameters": dict(tool.parameters),
    }
    if tool.target_system is not None:
        tool_block["target_system"] = tool.target_system
    if tool.invocation_id is not None:
        tool_block["invocation_id"] = tool.invocation_id
    request_ctx: Dict[str, Any] = {
        "caller": dict(request.caller),
        "jurisdiction": request.jurisdiction,
        "purpose": request.purpose,
        "timestamp": request.timestamp,
    }
    return {
        "tool_parameters": tool_block,
        "request_context": request_ctx,
    }


def compute_parameters_hash(parameters: Dict[str, Any]) -> str:
    """SHA-256 over the canonicalized parameter dict.

    Recorded on every ``actions[i].parameters_hash`` regardless of whether
    the operator opts in to redacting ``parameters`` itself on the
    receipt. Same canonicalisation as
    :func:`provenex.policy.evaluator.compute_policy_version_hash` so the
    hash is reproducible across language implementations.
    """
    return "sha256:" + hashlib.sha256(_canonical_bytes(parameters)).hexdigest()


# --------------------------------------------------------------------------- #
# Receipt assembly helper                                                     #
# --------------------------------------------------------------------------- #


def build_tool_call_control_metadata(
    evaluator: ToolCallPolicyEvaluator,
    decisions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble the ``policy.tool_call_control`` payload for a receipt.

    Parallel to :func:`provenex.policy.unified.build_access_control_metadata`.
    Centralised here so every wiring path (the framework-agnostic
    admission API, the MCP middleware, the LangChain wrapper, future
    sidecar bindings) emits the same shape.
    """
    return {
        "evaluator": evaluator.evaluator_name,
        "policy_id": evaluator.policy_id,
        "policy_version_hash": evaluator.policy_version_hash,
        # Lit up by the commercial transparency-log integration. Always
        # False in the open-source core, mirroring access_control.
        "policy_in_transparency_log": False,
        "decisions": list(decisions),
    }


# Re-export decision constants so callers can do ``from provenex.tool_call
# import DECISION_ALLOW`` without dipping into the retrieval namespace.
__all__ = [
    "ToolCallPolicyEvaluator",
    "NullToolCallPolicyEvaluator",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "BINDING_AT_EVALUATE",
    "EVALUATOR_NATIVE_YAML",
    "EVALUATOR_NONE",
    "build_tool_call_inputs",
    "build_tool_call_control_metadata",
    "compute_parameters_hash",
]
