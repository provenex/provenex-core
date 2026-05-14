"""The one-shot admission API: :func:`admission_check`.

Phase 2 analog of :func:`provenex.verify_chunks`. Where ``verify_chunks``
takes retrieved chunks and returns kept/blocked plus a signed receipt,
``admission_check`` takes a single tool-call attempt and returns
allow/deny plus a signed receipt. Both halves share the same trajectory
plumbing so a mixed retrieval + tool-call agent flow produces one signed
end-to-end record.

Scope reminder:

    Decision and proof, not execution.

This function returns a decision. It does NOT execute the tool call. It
does NOT proxy. It does NOT hold credentials. The caller (the MCP
middleware, the LangChain wrapper, the agent framework) is responsible
for executing the actual call with its own credentials after we return
``allow``. If we return ``deny``, the caller is responsible for not
executing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..core.receipt import ProvenanceReceipt, ReceiptBuilder, ReceiptSigner
from ..core.trajectory import TrajectoryContext
from ..policy.evaluator import (
    BINDING_AT_EVALUATE,
    DECISION_ALLOW,
    DECISION_DENY,
    PolicyDecision,
    RequestContext,
)
from ..policy.unified import Policy, coerce_policy
from .context import ToolCallContext
from .evaluator import (
    build_tool_call_control_metadata,
    build_tool_call_inputs,
    compute_parameters_hash,
)


@dataclass
class AdmissionResult:
    """Result of an :func:`admission_check` call.

    Attributes:
        decision: ``"allow"`` or ``"deny"`` (``"allow_with_conditions"``
            reserved for v1). Mirror of the same field on the underlying
            :class:`PolicyDecision`.
        rules_fired: Names of the policy rules whose ``when`` clauses
            matched. Empty when no tool-call policy was configured.
        receipt: The signed (if a signer was supplied) receipt covering
            the admission decision. Always present, even on ``deny``.
        next_trajectory: When the caller passed a ``trajectory`` to
            :func:`admission_check`, this is the advanced cursor ready to
            be passed to the next step (chains receipts into a DAG).
            ``None`` when no trajectory was supplied.
        policy_id: The ``policy_id`` of the tool-call bundle, or
            ``"none"`` when no tool-call policy was configured.
    """

    decision: str
    rules_fired: List[str]
    receipt: ProvenanceReceipt
    next_trajectory: Optional[TrajectoryContext] = None
    policy_id: str = "none"

    @property
    def allowed(self) -> bool:
        """Convenience for ``decision == "allow"``.

        ``allow_with_conditions`` (reserved) also returns True here; the
        caller is expected to inspect ``rules_fired`` if it cares about
        the conditional case.
        """
        return self.decision != DECISION_DENY


class ToolCallDenied(Exception):
    """Raised by :func:`enforce_admission` when admission denies a call.

    Carries the receipt for downstream audit logging. The MCP middleware
    surfaces this as a JSON-RPC error with the receipt ID; the
    LangChain wrapper raises it directly so the agent framework's tool
    error handler kicks in.
    """

    def __init__(self, result: AdmissionResult) -> None:
        rules = ", ".join(result.rules_fired) or "no specific rule"
        super().__init__(
            f"tool call denied by policy {result.policy_id} ({rules}); "
            f"receipt_id={result.receipt.receipt_id}"
        )
        self.result = result


def admission_check(
    tool: ToolCallContext,
    request: RequestContext,
    *,
    policy: Any = None,  # Policy | None
    signer: Optional[ReceiptSigner] = None,
    trajectory: Optional[TrajectoryContext] = None,
    step_kind: Optional[str] = None,
    agent_id: Optional[str] = None,
    output_text: str = "",
    redact_parameters: bool = False,
    redact_inputs: bool = False,
) -> AdmissionResult:
    """Evaluate one tool-call attempt against policy and emit a signed receipt.

    Framework-agnostic. The MCP middleware, the LangChain
    :class:`ProvenexToolWrapper`, and the CrewAI / LangGraph wrappers
    all ultimately delegate to this function. It's also the right
    callable for custom frameworks that don't have a first-class
    wrapper — install it directly at the admission point.

    Args:
        tool: The :class:`ToolCallContext` describing the attempt.
        request: The :class:`RequestContext` carrying caller identity,
            jurisdiction, purpose, and timestamp. Required (unlike
            :func:`verify_chunks`, where ``request_context`` is only
            required when access_control is configured) — tool-call
            admission is meaningless without caller context.
        policy: Optional unified :class:`Policy`. When ``None``, or when
            ``policy.tool_call_control is None``, admission allows by
            default and the receipt omits the ``tool_call_control``
            block. The verification half of ``policy`` does not apply
            to tool calls and is recorded on the receipt unchanged.
        signer: Optional :class:`ReceiptSigner`. Production should always
            sign.
        trajectory: Optional :class:`TrajectoryContext`. When supplied,
            the emitted receipt carries the trajectory block and the
            returned :class:`AdmissionResult` includes ``next_trajectory``
            so the caller can chain calls into a DAG that mixes
            retrieval and tool-call receipts.
        step_kind: Optional override for ``trajectory.step_kind`` on the
            emitted receipt. Defaults to ``"tool_call"`` when a
            trajectory is supplied and the cursor doesn't already
            specify one. Per-emission only — the cursor itself is not
            mutated.
        agent_id: Optional override for ``trajectory.agent_id``. Same
            per-emission semantics as ``step_kind``.
        output_text: Optional text whose hash should appear on the
            receipt. Tool-call receipts usually leave this empty;
            populate it only on the final receipt in a multi-step flow
            where the agent's output is bound to this admission step.
        redact_parameters: If True, the receipt records
            ``actions[i].parameters = null`` while keeping
            ``parameters_hash`` covering the verbatim values. Use when
            parameters carry PII or confidential data. The hash remains
            independently verifiable by anyone with the verbatim input.
        redact_inputs: If True, the receipt's
            ``policy.tool_call_control.decisions[i].inputs`` is set to
            ``None`` (the ``inputs_hash`` survives). Same discipline
            as Phase 1's access-control receipt redaction.

    Returns:
        An :class:`AdmissionResult` with the decision, rules fired, the
        signed receipt, and (when a trajectory was passed) the advanced
        cursor.
    """
    eff_policy: Policy = coerce_policy(policy)

    decision: PolicyDecision
    if eff_policy.tool_call_control is None:
        # No tool-call policy configured. Admission defaults to allow;
        # the receipt records an action but omits the tool_call_control
        # decisions block (parallel to the no-access-control receipt
        # shape from Phase 1).
        inputs = build_tool_call_inputs(tool, request)
        from ..policy.evaluator import compute_inputs_hash

        decision = PolicyDecision(
            decision=DECISION_ALLOW,
            rules_fired=[],
            inputs_hash=compute_inputs_hash(inputs),
            inputs=inputs,
            metadata_binding={
                "tool_parameters": BINDING_AT_EVALUATE,
                "request_context": BINDING_AT_EVALUATE,
            },
        )
    else:
        raw = eff_policy.tool_call_control.evaluate(tool, request)
        # Attach metadata_binding the same way Phase 1's verify_chunks
        # does — operator-declared on chunks; always at_evaluate for
        # tool calls because parameters are caller-supplied per-request
        # (there is no "at_ingest" analog for an ephemeral action).
        decision = PolicyDecision(
            decision=raw.decision,
            rules_fired=raw.rules_fired,
            inputs_hash=raw.inputs_hash,
            inputs=raw.inputs if not redact_inputs else None,
            metadata_binding={
                "tool_parameters": BINDING_AT_EVALUATE,
                "request_context": BINDING_AT_EVALUATE,
            },
        )

    # Compute parameters_hash over verbatim params regardless of receipt
    # redaction. The hash is the audit anchor; redaction only affects
    # whether the receipt itself stores the verbatim values.
    params_hash = compute_parameters_hash(tool.parameters)

    builder = ReceiptBuilder(policy=eff_policy.verification)
    action_index = builder.add_action(
        name=tool.name,
        operation=tool.operation,
        parameters_hash=params_hash,
        parameters=None if redact_parameters else dict(tool.parameters),
        target_system=tool.target_system,
        invocation_id=tool.invocation_id,
    )

    tool_call_control_block: Optional[Dict[str, Any]] = None
    if eff_policy.tool_call_control is not None:
        decision_dict = {
            "action_index": action_index,
            "decision": decision.decision,
            "rules_fired": list(decision.rules_fired),
            "inputs_hash": decision.inputs_hash,
            "inputs": (
                dict(decision.inputs) if decision.inputs is not None else None
            ),
            "metadata_binding": (
                dict(decision.metadata_binding)
                if decision.metadata_binding is not None
                else None
            ),
        }
        tool_call_control_block = build_tool_call_control_metadata(
            eff_policy.tool_call_control,
            decisions=[decision_dict],
        )

    # Per-emission step_kind override. Default to "tool_call" when no
    # explicit step_kind is on the cursor — this is the canonical
    # value reserved in trajectory schema 1.3.0 for exactly this case.
    emit_trajectory: Optional[TrajectoryContext] = trajectory
    if trajectory is not None:
        emit_step_kind = (
            step_kind
            if step_kind is not None
            else (trajectory.step_kind or "tool_call")
        )
        emit_agent_id = agent_id if agent_id is not None else trajectory.agent_id
        if (
            emit_step_kind != trajectory.step_kind
            or emit_agent_id != trajectory.agent_id
        ):
            emit_trajectory = TrajectoryContext(
                trajectory_id=trajectory.trajectory_id,
                step_index=trajectory.step_index,
                trajectory_started_at=trajectory.trajectory_started_at,
                parent_step_ids=trajectory.parent_step_ids,
                step_kind=emit_step_kind,
                agent_id=emit_agent_id,
            )

    receipt = builder.finalize(
        output_text=output_text,
        signer=signer,
        trajectory=emit_trajectory,
        tool_call_control=tool_call_control_block,
    )

    next_trajectory: Optional[TrajectoryContext] = None
    if trajectory is not None:
        next_trajectory = trajectory.next_step(
            parent_receipts=[receipt],
            agent_id=agent_id if agent_id is not None else trajectory.agent_id,
        )

    return AdmissionResult(
        decision=decision.decision,
        rules_fired=list(decision.rules_fired),
        receipt=receipt,
        next_trajectory=next_trajectory,
        policy_id=(
            eff_policy.tool_call_control.policy_id
            if eff_policy.tool_call_control is not None
            else "none"
        ),
    )


def enforce_admission(*args: Any, **kwargs: Any) -> AdmissionResult:
    """Call :func:`admission_check`; raise :class:`ToolCallDenied` on deny.

    Convenience for callers (notably framework wrappers) that want a
    "raise on deny, return on allow" semantic. The receipt is reachable
    on both branches: via the returned :class:`AdmissionResult` on allow,
    via :attr:`ToolCallDenied.result` on deny.
    """
    result = admission_check(*args, **kwargs)
    if not result.allowed:
        raise ToolCallDenied(result)
    return result
