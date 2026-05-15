"""Session-scoped trajectory and tool wrapping for CrewAI flows.

A :class:`ProvenexCrewSession` is the per-crew-run container for:

    * **Trajectory cursor** — advances as wrapped tools fire.
    * **Receipts list** — accumulates the signed receipts those tools emit.

The session is mutable (its trajectory cursor is the one piece of mutable
state in the integration) so that tools sharing the session share a single
trajectory. This matches the way CrewAI tools are invoked: they don't
receive shared state as a parameter, so the session has to be visible to
the wrapping closure, not threaded through arguments.

Thread safety
-------------

The session is **not** thread-safe. CrewAI's default execution model is
sequential within a crew, so concurrent tool invocations across a single
session are not a normal pattern. If you do run parallel agents that
share a session, wrap the advance/append operations in a lock at your
call site.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Iterable, List, Optional

from ...core.fingerprinter import Fingerprinter, FingerprinterConfig
from ...core.receipt import ProvenanceReceipt, ReceiptSigner
from ...core.trajectory import TrajectoryContext, start_trajectory
from ...core.verify import VerifiedChunks, verify_chunks as _core_verify_chunks
from ...index.base import ProvenanceIndex
from ...policy.evaluator import RequestContext
from ...policy.policy import VerificationPolicy
from ...policy.unified import Policy, coerce_policy
from ...tool_call.admission import (
    AdmissionResult,
    ToolCallDenied,
    admission_check as _core_admission_check,
)
from ...tool_call.context import ToolCallContext


class ProvenexCrewSession:
    """Per-crew-run trajectory + receipt aggregator with tool wrapping.

    Args:
        index: The :class:`ProvenanceIndex` to verify chunks against.
        signer: Optional :class:`ReceiptSigner` for signing each emitted
            receipt. Production should always sign.
        policy: Verification policy. Defaults to a sensible production
            policy.
        fingerprinter: Optional custom fingerprinter; must match the one
            used at ingest time.
        agent_id: Optional default agent identifier carried on every
            emitted receipt's trajectory block. Can be overridden per-call.

    Example:
        >>> session = ProvenexCrewSession(index=index, signer=signer)
        >>> retrieve_tool = session.wrap_tool(my_retrieval_fn, step_kind="retrieval")
        >>> # ... pass retrieve_tool to a CrewAI Agent ...
        >>> # After the crew runs:
        >>> for r in session.receipts:
        ...     audit_log.write(r.to_json())
    """

    def __init__(
        self,
        index: ProvenanceIndex,
        signer: Optional[ReceiptSigner] = None,
        policy: Any = None,  # Policy | VerificationPolicy | None
        fingerprinter: Optional[Fingerprinter] = None,
        agent_id: Optional[str] = None,
        sink: Any = None,
    ) -> None:
        self._index = index
        self._signer = signer
        # Accept a unified Policy (Phase 2) or a bare VerificationPolicy
        # (Phase 1 callers continue to work). coerce_policy wraps the
        # legacy form. The Policy object carries verification +
        # access_control + tool_call_control; verify_chunks and
        # admission_check pick the half they need.
        self._policy: Policy = coerce_policy(policy)
        self._fingerprinter = fingerprinter or Fingerprinter(FingerprinterConfig())
        self._agent_id = agent_id
        self._trajectory: TrajectoryContext = start_trajectory(agent_id=agent_id)
        self._receipts: List[ProvenanceReceipt] = []
        # 0.6.6+: per-session sinks. Sinks are accumulated so callers
        # can ``session.add_sink(...)`` after construction. A None or
        # empty list means no streaming export.
        self._sinks: List[Any] = []
        if sink is not None:
            if isinstance(sink, list):
                self._sinks.extend(sink)
            else:
                self._sinks.append(sink)

    def add_sink(self, sink: Any) -> None:
        """Add a downstream sink to this session.

        Every receipt emitted by ``verify_chunks`` / ``admission_check``
        / ``wrap_tool*`` after this call is also published to ``sink``.
        Sinks already on the session continue to receive receipts —
        :meth:`add_sink` is additive.

        Failures in any sink are swallowed and logged via
        :mod:`warnings`; the agent's hot path is never broken by
        export degradation.
        """
        self._sinks.append(sink)

    def _session_sink(self) -> Any:
        """Return the effective sink for this emission (None / single / list)."""
        if not self._sinks:
            return None
        if len(self._sinks) == 1:
            return self._sinks[0]
        return list(self._sinks)

    # ----------------------------------------------------------------- state

    @property
    def trajectory(self) -> TrajectoryContext:
        """Current trajectory cursor. Advances as receipts are emitted."""
        return self._trajectory

    @property
    def receipts(self) -> List[ProvenanceReceipt]:
        """Snapshot copy of receipts emitted so far in this session."""
        return list(self._receipts)

    @property
    def trajectory_id(self) -> str:
        """The trajectory id shared by every receipt in this session."""
        return self._trajectory.trajectory_id

    # ----------------------------------------------------------------- core verify

    @property
    def policy(self) -> Policy:
        """The unified policy in effect for this session."""
        return self._policy

    def verify_chunks(
        self,
        chunks: Any,
        step_kind: str = "retrieval",
        agent_id: Optional[str] = None,
        output_text: str = "",
    ) -> VerifiedChunks:
        """Verify a tool's chunk output and emit a trajectory-linked receipt.

        Delegates to the framework-agnostic :func:`provenex.verify_chunks`
        and threads the result back into session state (advances the
        trajectory cursor; appends the receipt).

        Args:
            chunks: A string, list of strings, list of Documents, or list
                of dicts containing chunk text.
            step_kind: Trajectory ``step_kind`` recorded on the emitted
                receipt. Defaults to ``"retrieval"``.
            agent_id: Optional per-call agent override (otherwise the
                session's default is used).
            output_text: Optional LLM-output text whose hash should be
                recorded on the receipt. Usually only the final receipt
                in a session carries non-empty output.

        Returns:
            A :class:`VerifiedChunks` with kept text, blocked text, and
            the signed receipt. The session's trajectory advances by one
            step; the receipt is appended to :attr:`receipts`.
        """
        result = _core_verify_chunks(
            chunks=chunks,
            index=self._index,
            signer=self._signer,
            policy=self._policy,
            fingerprinter=self._fingerprinter,
            trajectory=self._trajectory,
            step_kind=step_kind,
            agent_id=agent_id if agent_id is not None else self._agent_id,
            output_text=output_text,
            sink=self._session_sink(),
        )

        # Thread the new cursor back into session state.
        assert result.next_trajectory is not None  # trajectory was supplied
        self._trajectory = result.next_trajectory
        self._receipts.append(result.receipt)
        return result

    # ----------------------------------------------------------------- tool wrapping

    def wrap_tool(
        self,
        tool: Callable[..., Any],
        step_kind: str = "tool_call",
        agent_id: Optional[str] = None,
        return_blocked: bool = False,
    ) -> Callable[..., Any]:
        """Wrap a CrewAI-style tool so its output is verified and a receipt emitted.

        The returned callable:

            1. Invokes ``tool(*args, **kwargs)`` to get its raw output.
            2. Coerces the output to a chunk list.
            3. Verifies each chunk and applies policy.
            4. Emits a signed, trajectory-linked receipt into the session.
            5. Returns the kept chunks in the same shape the original
               tool returned (string in → string out, list in → list out).

        Args:
            tool: Any callable. Most CrewAI tools return strings; lists
                of strings or Document-like objects are also accepted.
            step_kind: Trajectory step kind recorded on the receipt.
                Defaults to ``"tool_call"``. Use ``"retrieval"`` for
                tools that fetch chunks from a vector store, or
                ``"memory_read"`` for memory lookups.
            agent_id: Optional agent override for receipts emitted by
                this wrapped tool.
            return_blocked: If True, blocked chunks are included in the
                returned output anyway (the receipt still records them as
                blocked). Useful when downstream wants the model to see
                "[REDACTED]" content or otherwise be aware of removed
                material. Default False — blocked chunks are dropped.

        Returns:
            A new callable with the same signature as ``tool``. ``functools.wraps``
            preserves the original function's name and docstring so CrewAI
            tool introspection still works.
        """

        @functools.wraps(tool)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            raw = tool(*args, **kwargs)
            result = self.verify_chunks(
                raw, step_kind=step_kind, agent_id=agent_id
            )
            output_chunks = result.kept + (result.blocked if return_blocked else [])
            # Preserve the original output shape: string-in → string-out,
            # list-in → list-out.
            if isinstance(raw, str):
                return "\n".join(output_chunks)
            return output_chunks

        return wrapped

    # ----------------------------------------------------------------- tool-call admission

    def admission_check(
        self,
        tool: ToolCallContext,
        request: RequestContext,
        step_kind: str = "tool_call",
        agent_id: Optional[str] = None,
        output_text: str = "",
        redact_parameters: bool = False,
        redact_inputs: bool = False,
    ) -> AdmissionResult:
        """Run Phase 2 admission on a tool-call attempt and thread state.

        Session-aware sibling of :func:`provenex.admission_check`. Pulls
        the policy and signer off the session, supplies the current
        trajectory cursor, advances the cursor on the result, and
        appends the receipt to :attr:`receipts`.

        Args:
            tool: The :class:`ToolCallContext` describing the attempt.
            request: The :class:`RequestContext` carrying caller identity
                and timestamp. CrewAI does not surface identity to tool
                callables; the host application must supply it.
            step_kind: Trajectory ``step_kind`` recorded on the emitted
                receipt. Defaults to ``"tool_call"``.
            agent_id: Optional per-call agent override.
            output_text: Optional text whose hash should appear on the
                receipt. Usually empty for admission steps.
            redact_parameters: If True, the receipt records
                ``actions[i].parameters = null`` (the
                ``parameters_hash`` survives). Same semantics as
                :func:`provenex.admission_check`.
            redact_inputs: If True, the receipt's
                ``policy.tool_call_control.decisions[i].inputs`` is set
                to ``None``.

        Returns:
            An :class:`AdmissionResult`. The session's trajectory cursor
            advances by one step; the receipt is appended to
            :attr:`receipts`.
        """
        result = _core_admission_check(
            tool=tool,
            request=request,
            policy=self._policy,
            signer=self._signer,
            trajectory=self._trajectory,
            step_kind=step_kind,
            agent_id=agent_id if agent_id is not None else self._agent_id,
            output_text=output_text,
            redact_parameters=redact_parameters,
            redact_inputs=redact_inputs,
            sink=self._session_sink(),
        )
        # Thread the new cursor back into session state. ``next_trajectory``
        # is non-None because we passed a trajectory in.
        assert result.next_trajectory is not None
        self._trajectory = result.next_trajectory
        self._receipts.append(result.receipt)
        return result

    def wrap_tool_admission(
        self,
        tool: Callable[..., Any],
        *,
        name: str,
        request_factory: Callable[..., RequestContext],
        operation: str = "invoke",
        target_system: Optional[str] = None,
        params_extractor: Optional[Callable[..., Dict[str, Any]]] = None,
        step_kind: str = "tool_call",
        agent_id: Optional[str] = None,
        redact_parameters: bool = False,
        on_deny: Optional[Callable[[AdmissionResult], Any]] = None,
    ) -> Callable[..., Any]:
        """Wrap a CrewAI tool with **Phase 2 admission** semantics.

        Parallel to :meth:`wrap_tool`, but instead of verifying the
        tool's *output* (Phase 1), this runs admission *before* the
        tool is invoked (Phase 2). The decision is "should this tool
        be called at all," not "should this chunk reach the LLM."

        The returned callable:

            1. Builds a :class:`ToolCallContext` from the call arguments
               (via ``params_extractor`` if supplied, else
               ``dict(kwargs)`` or ``{"input": args[0]}`` for a single
               positional).
            2. Resolves a :class:`RequestContext` via ``request_factory``.
            3. Calls :meth:`admission_check`. On deny:
               - if ``on_deny`` is set, returns ``on_deny(result)``;
               - else raises :class:`provenex.ToolCallDenied`.
            4. On allow, invokes the underlying tool with the original
               args/kwargs and returns its result.

        The receipt is appended to the session whether the call was
        admitted or denied — denials are auditable.

        Args:
            tool: Any CrewAI-style callable.
            name: Tool identifier evaluated against ``tool.name`` in the
                policy. For MCP servers, the server-and-tool path.
            request_factory: Callable that takes the same ``*args, **kwargs``
                the tool receives and returns a :class:`RequestContext`.
                Provenex does not own identity; this factory is where the
                host application injects caller / jurisdiction / purpose
                / timestamp.
            operation: Optional default operation string. Many CrewAI
                tools have one operation per tool, so a constant like
                ``"invoke"`` is the right default. Per-call overrides
                via the ``__operation__`` kwarg are also accepted.
            target_system: Optional default target system. Per-call
                overrides via the ``__target_system__`` kwarg are also
                accepted.
            params_extractor: Optional callable mapping
                ``(*args, **kwargs) → parameters dict``. Default: any
                ``__operation__`` / ``__target_system__`` /
                ``__invocation_id__`` keys are stripped from kwargs,
                and the rest become the parameters dict. A single
                positional arg becomes ``{"input": arg}``.
            step_kind: Trajectory step kind. Default ``"tool_call"``.
            agent_id: Optional per-tool agent override.
            redact_parameters: If True, receipts have
                ``parameters: null`` (hash survives).
            on_deny: Optional callback invoked on deny instead of
                raising; its return value becomes the wrapped tool's
                return value. Useful when an agent framework expects
                a structured error rather than an exception.

        Returns:
            A new callable with the same signature as ``tool``.
            ``functools.wraps`` preserves the original name/docstring
            so CrewAI tool introspection still works.
        """

        @functools.wraps(tool)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            # Extract Provenex-reserved per-call overrides before
            # touching the user-visible parameter set.
            op = kwargs.pop("__operation__", operation)
            tgt = kwargs.pop("__target_system__", target_system)
            inv_id = kwargs.pop("__invocation_id__", None)

            if params_extractor is not None:
                parameters = params_extractor(*args, **kwargs)
            elif kwargs:
                parameters = dict(kwargs)
            elif len(args) == 1:
                # Common CrewAI pattern: tool(query: str).
                parameters = {"input": args[0]}
            else:
                parameters = {f"arg{i}": v for i, v in enumerate(args)}

            tool_ctx = ToolCallContext(
                name=name,
                operation=op,
                parameters=parameters,
                target_system=tgt,
                invocation_id=inv_id,
            )
            request = request_factory(*args, **kwargs)
            result = self.admission_check(
                tool=tool_ctx,
                request=request,
                step_kind=step_kind,
                agent_id=agent_id,
                redact_parameters=redact_parameters,
            )
            if not result.allowed:
                if on_deny is not None:
                    return on_deny(result)
                raise ToolCallDenied(result)
            return tool(*args, **kwargs)

        return wrapped

    # ----------------------------------------------------------------- manual advance

    def advance(
        self,
        parent_receipts: Optional[Iterable[ProvenanceReceipt]] = None,
        step_kind: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> TrajectoryContext:
        """Increment the trajectory cursor without emitting a receipt.

        Use this for trajectory steps that don't touch chunks (e.g. a
        pure-reasoning step). By default, ``parent_step_ids`` is
        **preserved** on the new cursor — the next emitted receipt will
        still point at whatever the previous emission was, with the
        skipped step showing up only as a gap in ``step_index`` values.

        Pass ``parent_receipts`` to override and branch the cursor onto
        explicit parents instead (the normal "next step has these
        parents" semantics from :meth:`TrajectoryContext.next_step`).

        Args:
            parent_receipts: Optional explicit parents. If provided, the
                new cursor's ``parent_step_ids`` is set to these. If
                omitted, the existing cursor's ``parent_step_ids`` is
                carried forward unchanged.
            step_kind: Optional step kind to set on the new cursor.
            agent_id: Optional agent override.

        Returns:
            The new :class:`TrajectoryContext`. Also stored on the session.
        """
        if parent_receipts is None:
            # Preserve the chain — skip a step number, keep the parent ref.
            self._trajectory = self._trajectory.next_step(
                parent_step_ids=list(self._trajectory.parent_step_ids),
                step_kind=step_kind,
                agent_id=agent_id,
            )
        else:
            self._trajectory = self._trajectory.next_step(
                parent_receipts=parent_receipts,
                step_kind=step_kind,
                agent_id=agent_id,
            )
        return self._trajectory
