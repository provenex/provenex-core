"""The one-shot admission API: :func:`admission_check`.

Tool-call admission analog of :func:`provenex.verify_chunks`. Where ``verify_chunks``
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

from ..core.receipt import (
    ProvenanceReceipt,
    ReceiptBuilder,
    ReceiptSigner,
    compute_caller_hash,
    compute_value_hash,
)
from ..export.streaming import _safe_publish
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
        decision: ``"allow"`` or ``"deny"``. Mirror of the same field on
            the underlying :class:`PolicyDecision`.
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
        """Convenience for ``decision == "allow"``."""
        return self.decision == DECISION_ALLOW


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
    caller_hash_salt: Optional[bytes] = None,
    sink: Any = None,
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
            as the retrieval-side access-control receipt redaction.

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
        # shape from the retrieval flow).
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
        # Attach metadata_binding the same way verify_chunks
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

    # Per-emission step_kind / agent_id / session_id overrides. Default
    # step_kind to "tool_call" when no explicit one is on the cursor —
    # this is the canonical value reserved in trajectory schema 1.3.0
    # for exactly this case. session_id (schema 2.3.0) is pulled from
    # the request: the request is the source-of-truth per emission, and
    # the per-step value propagates forward via next_step.
    emit_trajectory: Optional[TrajectoryContext] = trajectory
    if trajectory is not None:
        emit_step_kind = (
            step_kind
            if step_kind is not None
            else (trajectory.step_kind or "tool_call")
        )
        emit_agent_id = agent_id if agent_id is not None else trajectory.agent_id
        emit_session_id = (
            request.session_id
            if request.session_id is not None
            else trajectory.session_id
        )
        if (
            emit_step_kind != trajectory.step_kind
            or emit_agent_id != trajectory.agent_id
            or emit_session_id != trajectory.session_id
        ):
            emit_trajectory = TrajectoryContext(
                trajectory_id=trajectory.trajectory_id,
                step_index=trajectory.step_index,
                trajectory_started_at=trajectory.trajectory_started_at,
                parent_step_ids=trajectory.parent_step_ids,
                step_kind=emit_step_kind,
                agent_id=emit_agent_id,
                session_id=emit_session_id,
            )

    # Schema 2.3.0: compute caller_hash from the request's caller dict.
    # admission_check always requires a request, so this is always
    # emitted on tool-call receipts. When ``caller_hash_salt`` is
    # supplied (0.6.5+), the hash becomes HMAC-SHA256 — same payload,
    # different deployment-keyed digest for per-deployment
    # unlinkability.
    emit_caller_hash = compute_caller_hash(
        request.caller, salt=caller_hash_salt
    )

    receipt = builder.finalize(
        output_text=output_text,
        signer=signer,
        trajectory=emit_trajectory,
        tool_call_control=tool_call_control_block,
        caller_hash=emit_caller_hash,
    )

    # Schema 2.3.0 / 0.6.6+: ship to downstream sink if supplied.
    # Failures swallowed (warnings.warn); agent hot path never broken.
    _safe_publish(sink, receipt)

    next_trajectory: Optional[TrajectoryContext] = None
    if trajectory is not None:
        next_trajectory = trajectory.next_step(
            parent_receipts=[receipt],
            agent_id=agent_id if agent_id is not None else trajectory.agent_id,
            session_id=(
                request.session_id
                if request.session_id is not None
                else trajectory.session_id
            ),
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


def admit_memory_write(
    memory_key: str,
    value: Any,
    request: RequestContext,
    *,
    store_id: Optional[str] = None,
    ttl: Optional[int] = None,
    extra_parameters: Optional[Dict[str, Any]] = None,
    policy: Any = None,
    signer: Optional[ReceiptSigner] = None,
    trajectory: Optional[TrajectoryContext] = None,
    redact_value: bool = True,
    caller_hash_salt: Optional[bytes] = None,
    **admission_kwargs: Any,
) -> AdmissionResult:
    """Convenience: :func:`admission_check` shaped for a memory write (schema 2.3.0).

    Builds a :class:`ToolCallContext` with:

        * ``name="memory.write"`` — the rule axis a tool-call policy
          author writes against (``when: { tool.name: "memory.write" }``).
        * ``operation=<memory_key>`` — the policy-rule axis for per-key
          gating. A rule like ``when: { tool.operation: user_profile }``
          fires for writes to the ``user_profile`` key only.
        * ``parameters={value_hash, store_id?, ttl?, **extra_parameters}``
          — the verbatim value's hash is always present;
          ``store_id`` and ``ttl`` are included only when supplied;
          ``extra_parameters`` is merged in for callers who want
          additional auditable parameters on the receipt.
        * ``target_system=store_id`` — same as ``parameters.store_id``;
          duplicated so rules that read ``tool.target_system`` work
          uniformly across all admission entrypoints.

    Then runs :func:`admission_check(..., step_kind="memory_write")`.

    By default the **verbatim value is NOT recorded** — only its hash
    via :func:`compute_value_hash`. Memory values commonly contain PII
    (chat history, user state, intermediate reasoning), so the safer
    default is to record the hash anchor and let the operator opt in
    to recording the verbatim value via ``redact_value=False``. The
    hash is independently verifiable by anyone holding the original
    value either way.

    Args:
        memory_key: The key being written. Lands as
            ``actions[0].operation`` so it's the natural policy-rule
            axis. Detectors group by
            ``caller_hash + tool.name="memory.write" + tool.operation=<key>``.
        value: The value being written. Hashed via
            :func:`compute_value_hash`; verbatim recorded only if
            ``redact_value=False``.
        request: The :class:`RequestContext` carrying caller identity.
        store_id: Optional logical store identifier (e.g.
            ``"crewai_memory"``, ``"redis_sessions"``). Recorded as
            ``target_system`` and as ``parameters.store_id``.
        ttl: Optional TTL in seconds. Recorded under ``parameters.ttl``
            when supplied.
        extra_parameters: Additional caller-supplied parameters to
            merge onto the action record's ``parameters`` dict.
        policy: Optional unified :class:`Policy`. The
            ``tool_call_control`` half of the policy gates the write.
        signer: Optional :class:`ReceiptSigner`.
        trajectory: Optional :class:`TrajectoryContext`.
        redact_value: When True (default), the verbatim value is not
            recorded on the receipt. ``value_hash`` is always
            recorded. Set False to record the verbatim value when
            the value is non-sensitive and you want full audit detail.
        caller_hash_salt: Optional bytes; passed through to
            :func:`admission_check` for per-deployment unlinkability.
        **admission_kwargs: Passed verbatim to :func:`admission_check`.

    Returns:
        :class:`AdmissionResult`. The receipt carries an ``actions[]``
        entry with ``name="memory.write"`` and the trajectory step
        kind ``"memory_write"`` (when a trajectory is in scope).
    """
    parameters: Dict[str, Any] = {"value_hash": compute_value_hash(value)}
    if store_id is not None:
        parameters["store_id"] = store_id
    if ttl is not None:
        parameters["ttl"] = ttl
    if not redact_value:
        parameters["value"] = value
    if extra_parameters:
        parameters.update(extra_parameters)

    return admission_check(
        tool=ToolCallContext(
            name="memory.write",
            operation=memory_key,
            parameters=parameters,
            target_system=store_id,
        ),
        request=request,
        policy=policy,
        signer=signer,
        trajectory=trajectory,
        step_kind=admission_kwargs.pop("step_kind", "memory_write"),
        caller_hash_salt=caller_hash_salt,
        **admission_kwargs,
    )


def admit_model_inference(
    model_name: str,
    prompt: Any,
    request: RequestContext,
    *,
    target_provider: Optional[str] = None,
    operation: str = "complete",
    extra_parameters: Optional[Dict[str, Any]] = None,
    policy: Any = None,
    signer: Optional[ReceiptSigner] = None,
    trajectory: Optional[TrajectoryContext] = None,
    redact_prompt: bool = True,
    caller_hash_salt: Optional[bytes] = None,
    **admission_kwargs: Any,
) -> AdmissionResult:
    """Convenience: :func:`admission_check` shaped for a model-inference call (schema 2.3.0).

    Builds a :class:`ToolCallContext` with:

        * ``name=<model_name>`` — e.g. ``"claude-opus-4-7"``,
          ``"gpt-4o"``. The rule axis a tool-call policy author writes
          against (``when: { tool.name: claude-opus-4-7 }``).
        * ``operation=<operation>`` — ``"complete"`` by default; pass
          ``"stream"``, ``"embed"``, ``"chat"`` etc. Free-form string,
          no enum.
        * ``parameters={prompt_hash, **extra_parameters}`` — the
          prompt's hash via :func:`compute_value_hash`;
          ``extra_parameters`` is merged in for things like
          ``{"max_tokens": 4000, "temperature": 0.2}``.
        * ``target_system=<target_provider>`` — e.g. ``"anthropic"``,
          ``"openai"``. The natural axis for a "calls to provider X
          allowed only for role Y" rule.

    Then runs :func:`admission_check(..., step_kind="model_inference")`.

    Enables anomaly-detector patterns like "this caller is calling
    claude-opus 100x baseline", "this agent's prompt_hash distribution
    shifted", "this caller is calling a model from a non-allowlisted
    provider" — `model_inference` becomes a first-class step kind
    alongside `retrieval` / `tool_call` / `memory_read` /
    `memory_write`.

    By default the **verbatim prompt is NOT recorded** — only its hash.
    Prompts often contain PII / customer data; recording them by
    default would put Provenex on the data path (against the
    decision-and-proof discipline). Set ``redact_prompt=False`` to
    record the verbatim prompt.

    Args:
        model_name: Model identifier (e.g. ``"claude-opus-4-7"``).
            Lands as ``actions[0].name``. Detectors group by
            ``caller_hash + tool.name=<model_name>``.
        prompt: The prompt. String, bytes, or any JSON-serializable
            structure (e.g. list of ``{role, content}`` chat messages).
            Hashed via :func:`compute_value_hash`; verbatim recorded
            only if ``redact_prompt=False``.
        request: The :class:`RequestContext` carrying caller identity.
        target_provider: Optional provider identifier (e.g.
            ``"anthropic"``, ``"openai"``). Recorded as
            ``target_system``.
        operation: Operation classifier on the model
            (``"complete"`` default, ``"stream"``, ``"embed"``,
            ``"chat"``).
        extra_parameters: Additional caller-supplied parameters to
            merge onto the action record (e.g. ``max_tokens``,
            ``temperature``).
        policy: Optional unified :class:`Policy`.
        signer: Optional :class:`ReceiptSigner`.
        trajectory: Optional :class:`TrajectoryContext`.
        redact_prompt: When True (default), the verbatim prompt is
            not recorded on the receipt. ``prompt_hash`` is always
            recorded. Set False to record the verbatim prompt.
        caller_hash_salt: Optional bytes; passed through for
            per-deployment unlinkability.
        **admission_kwargs: Passed verbatim to :func:`admission_check`.

    Returns:
        :class:`AdmissionResult`. The receipt carries an ``actions[]``
        entry with ``name=<model_name>`` and trajectory step kind
        ``"model_inference"``.
    """
    parameters: Dict[str, Any] = {"prompt_hash": compute_value_hash(prompt)}
    if not redact_prompt:
        parameters["prompt"] = prompt
    if extra_parameters:
        parameters.update(extra_parameters)

    return admission_check(
        tool=ToolCallContext(
            name=model_name,
            operation=operation,
            parameters=parameters,
            target_system=target_provider,
        ),
        request=request,
        policy=policy,
        signer=signer,
        trajectory=trajectory,
        step_kind=admission_kwargs.pop("step_kind", "model_inference"),
        caller_hash_salt=caller_hash_salt,
        **admission_kwargs,
    )
