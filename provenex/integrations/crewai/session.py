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
from typing import Any, Callable, Iterable, List, Optional

from ...core.fingerprinter import Fingerprinter, FingerprinterConfig
from ...core.receipt import ProvenanceReceipt, ReceiptSigner
from ...core.trajectory import TrajectoryContext, start_trajectory
from ...core.verify import VerifiedChunks, verify_chunks as _core_verify_chunks
from ...index.base import ProvenanceIndex
from ...policy.policy import VerificationPolicy


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
        policy: Optional[VerificationPolicy] = None,
        fingerprinter: Optional[Fingerprinter] = None,
        agent_id: Optional[str] = None,
    ) -> None:
        self._index = index
        self._signer = signer
        self._policy = policy or VerificationPolicy()
        self._fingerprinter = fingerprinter or Fingerprinter(FingerprinterConfig())
        self._agent_id = agent_id
        self._trajectory: TrajectoryContext = start_trajectory(agent_id=agent_id)
        self._receipts: List[ProvenanceReceipt] = []

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
