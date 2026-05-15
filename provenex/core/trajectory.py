"""Trajectory context for iterative agentic retrieval (RFC-0003, schema 1.3.0).

A trajectory is a DAG of retrieval steps. In iterative agentic patterns —
Agentic RAG, Self-RAG, RAT, multi-hop retrieval, LangGraph DAGs, CrewAI
multi-agent flows — a single answer is the product of many retrieval calls.
Today those produce N independent receipts with no cross-linking, which makes
it impossible for an auditor to reconstruct the full retrieval trail from
the receipts alone.

This module supplies the per-step metadata that the receipt schema 1.3.0
adds to link those receipts into a verifiable DAG. The actual DAG validation
lives in ``provenex audit --trajectory`` (separate change).

Design properties:

    - **Per-step receipts, not aggregate.** Each step emits its own receipt;
      receipts reference parents by ``receipt_id``. Partial trajectories
      (when an agent aborts mid-flow) still verify.
    - **DAG-shaped.** ``parent_step_ids`` is a list, so branching flows
      (LangGraph parallel branches, CrewAI parallel agents) round-trip.
    - **Signature-covered.** The trajectory block sits in the receipt and is
      part of the canonical signature payload. Tampering with trajectory
      metadata invalidates the receipt.
    - **Immutable per step.** ``TrajectoryContext`` is a frozen dataclass.
      ``next_step()`` returns a fresh instance, so it is safe to fork a
      trajectory for parallel branches.
    - **No new verification outcome.** The five outcomes are unchanged.
      Trajectory metadata sits alongside the existing verification result.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


def _now_utc_iso() -> str:
    """ISO-8601 UTC with millisecond precision and trailing Z."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _new_trajectory_id() -> str:
    """Generate a fresh trajectory ID. ``trj_`` prefix + 32 hex chars.

    The ``trj_`` prefix mirrors the ``prx_`` prefix used for receipt IDs so
    the two namespaces stay visually distinct in logs and audit output.
    """
    return "trj_" + secrets.token_hex(16)


@dataclass(frozen=True)
class TrajectoryContext:
    """Per-step metadata that links a receipt into a trajectory DAG.

    Construct the root step via :func:`start_trajectory`. Derive subsequent
    steps via :meth:`next_step`. The object is immutable; ``next_step``
    returns a new instance rather than mutating in place.

    Attributes:
        trajectory_id: Globally unique trajectory identifier (``trj_`` +
            32 hex chars). Shared by every step in the trajectory.
        step_index: 0-based ordinal within the trajectory. In DAG shapes,
            sibling branches may share an index; uniqueness is along the
            parent chain.
        parent_step_ids: Tuple of parent receipt IDs (``receipt_id`` values
            of receipts that came before this step). Empty for the root.
        step_kind: Optional free-form classifier (``"retrieval"``,
            ``"tool_call"``, ``"memory_read"``, ``"memory_write"``,
            ``"compilation"`` are the Provenex-defined values; unknown
            values are valid for forward compatibility).
        agent_id: Optional opaque identifier for the agent that emitted
            this step. Useful in multi-agent flows.
        trajectory_started_at: ISO-8601 UTC timestamp at which the
            trajectory began. Same value across every step in the
            trajectory.
        session_id: Optional caller-chosen multi-trajectory correlation
            key (schema 2.3.0+). A user's chat session, an
            incident-response engagement, a multi-day investigation —
            anything that spans more than one trajectory in the same
            logical session. Propagates across :meth:`next_step` by
            default; per-emission overrides are flowed in by
            :func:`provenex.core.verify.verify_chunks` and
            :func:`provenex.tool_call.admission_check` from
            ``RequestContext.session_id`` so the request is the
            source-of-truth per step.
    """

    trajectory_id: str
    step_index: int
    trajectory_started_at: str
    parent_step_ids: Tuple[str, ...] = field(default_factory=tuple)
    step_kind: Optional[str] = None
    agent_id: Optional[str] = None
    session_id: Optional[str] = None

    def next_step(
        self,
        parent_receipts: Optional[Iterable[Any]] = None,
        parent_step_ids: Optional[Iterable[str]] = None,
        step_kind: Optional[str] = None,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> "TrajectoryContext":
        """Build a successor step.

        Args:
            parent_receipts: Iterable of receipts (e.g.
                :class:`provenex.core.receipt.ProvenanceReceipt`) whose
                ``receipt_id`` should be recorded as parents of the new
                step. Accepted via duck typing — anything with a
                ``receipt_id`` attribute works.
            parent_step_ids: Iterable of raw receipt-ID strings to record
                as parents. Combined with ``parent_receipts``.
            step_kind: Optional classifier for the new step. Not inherited
                from the previous step — per-step value.
            agent_id: Optional agent identifier. Inherits from the current
                step's ``agent_id`` if not specified. Override for
                multi-agent handoffs.
            session_id: Optional multi-trajectory correlation key. Inherits
                from the current step's ``session_id`` if not specified.
                Override to start a new session within the same trajectory
                (unusual — sessions usually span trajectories rather than
                the reverse).

        Returns:
            A new :class:`TrajectoryContext` with ``step_index`` incremented
            and the supplied parents recorded. The current instance is
            unchanged.
        """
        parents: list[str] = []
        if parent_receipts is not None:
            for r in parent_receipts:
                rid = getattr(r, "receipt_id", None)
                if not isinstance(rid, str):
                    raise TypeError(
                        "parent_receipts entries must expose a receipt_id "
                        "string attribute"
                    )
                parents.append(rid)
        if parent_step_ids is not None:
            parents.extend(parent_step_ids)
        return TrajectoryContext(
            trajectory_id=self.trajectory_id,
            step_index=self.step_index + 1,
            trajectory_started_at=self.trajectory_started_at,
            parent_step_ids=tuple(parents),
            step_kind=step_kind,
            agent_id=agent_id if agent_id is not None else self.agent_id,
            session_id=(
                session_id if session_id is not None else self.session_id
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the trajectory block in canonical schema order.

        Optional fields (``step_kind``, ``agent_id``, ``session_id``) are
        omitted when ``None`` rather than emitted as JSON ``null``. This
        matches the receipt's existing convention for ``transparency_log``.
        """
        d: Dict[str, Any] = {
            "trajectory_id": self.trajectory_id,
            "step_index": self.step_index,
            "parent_step_ids": list(self.parent_step_ids),
            "trajectory_started_at": self.trajectory_started_at,
        }
        if self.step_kind is not None:
            d["step_kind"] = self.step_kind
        if self.agent_id is not None:
            d["agent_id"] = self.agent_id
        if self.session_id is not None:
            d["session_id"] = self.session_id
        return d


def start_trajectory(
    agent_id: Optional[str] = None,
    step_kind: Optional[str] = None,
    session_id: Optional[str] = None,
) -> TrajectoryContext:
    """Begin a new trajectory at step 0.

    Args:
        agent_id: Optional identifier for the agent starting the trajectory.
            Inherited by subsequent steps unless overridden.
        step_kind: Optional classifier for the first step.
        session_id: Optional multi-trajectory correlation key (schema
            2.3.0+). Set once at trajectory start to tag every receipt
            in the trajectory with a stable session identifier. A
            downstream anomaly detector GROUP BYs ``session_id`` to
            correlate trajectories that share a logical session
            boundary (a chat session, an incident-response engagement).
            Propagates via :meth:`TrajectoryContext.next_step` unless
            overridden per-emission by a
            :class:`provenex.policy.evaluator.RequestContext` that
            carries its own ``session_id``.

    Returns:
        A root :class:`TrajectoryContext` with a fresh ``trajectory_id``,
        ``step_index=0``, and no parents.

    Example:
        >>> traj = start_trajectory(agent_id="research_agent")
        >>> traj.step_index
        0
        >>> traj.parent_step_ids
        ()
    """
    return TrajectoryContext(
        trajectory_id=_new_trajectory_id(),
        step_index=0,
        trajectory_started_at=_now_utc_iso(),
        parent_step_ids=(),
        step_kind=step_kind,
        agent_id=agent_id,
        session_id=session_id,
    )


# --------------------------------------------------------------------------- #
# Trajectory audit (DAG validation)                                           #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TrajectoryCheck:
    """One named check in a trajectory audit, with its result."""

    name: str
    ok: bool
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "message": self.message}


@dataclass(frozen=True)
class TrajectoryAuditResult:
    """Aggregate result of a trajectory-level audit.

    Per-receipt checks (signature, inclusion proofs) live elsewhere; this
    result covers only the *trajectory-level* invariants: shared
    trajectory_id, DAG acyclicity, no dangling parents, at least one root.
    """

    ok: bool
    trajectory_id: Optional[str]
    receipt_count: int
    checks: Tuple[TrajectoryCheck, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trajectory_id": self.trajectory_id,
            "receipt_count": self.receipt_count,
            "checks": [c.to_dict() for c in self.checks],
            "overall": "PASS" if self.ok else "FAIL",
        }


def audit_trajectory_dag(
    receipts: Iterable[Mapping[str, Any]],
) -> TrajectoryAuditResult:
    """Validate that a set of receipts forms a consistent trajectory DAG.

    The checks performed are:

        1. **Every receipt has a trajectory block.** Missing blocks mean the
           receipt isn't part of any trajectory and shouldn't be in a
           trajectory-audit set.
        2. **Shared trajectory_id.** All receipts must reference the same
           trajectory_id; otherwise they belong to different trajectories.
        3. **No dangling parents.** Every ``parent_step_id`` must resolve to
           a receipt in the supplied set. A dangling parent is either an
           operator who failed to persist a step or an attacker who dropped
           one — either way the audit fails.
        4. **DAG is acyclic.** A cycle is structurally impossible in a
           causal trajectory; its presence is evidence of either corruption
           or tampering.
        5. **At least one root step.** A trajectory must begin somewhere.
           A receipt set with no ``parent_step_ids == []`` step has no entry
           point.

    Per-receipt checks (signature validity, inclusion-proof validity) are
    NOT performed here — they remain the responsibility of the per-receipt
    audit path. This function is purely structural.

    Args:
        receipts: Iterable of parsed receipt dicts (typically the result
            of ``json.loads`` on each receipt file).

    Returns:
        A :class:`TrajectoryAuditResult` with one :class:`TrajectoryCheck`
        per invariant. ``ok`` is True iff every check passed.
    """
    receipts_list: List[Mapping[str, Any]] = list(receipts)
    checks: List[TrajectoryCheck] = []

    # Check 1: every receipt has a trajectory block.
    missing = [
        r.get("receipt_id", "(no id)")
        for r in receipts_list
        if not r.get("trajectory")
    ]
    if missing:
        checks.append(
            TrajectoryCheck(
                name="has_trajectory_block",
                ok=False,
                message=(
                    f"{len(missing)} receipt(s) lack a trajectory block: "
                    f"{missing[:3]}{'...' if len(missing) > 3 else ''}"
                ),
            )
        )
        return TrajectoryAuditResult(
            ok=False,
            trajectory_id=None,
            receipt_count=len(receipts_list),
            checks=tuple(checks),
        )
    checks.append(
        TrajectoryCheck(
            name="has_trajectory_block",
            ok=True,
            message=f"all {len(receipts_list)} receipts carry a trajectory block",
        )
    )

    # Check 2: shared trajectory_id.
    ids = {r["trajectory"]["trajectory_id"] for r in receipts_list}
    if len(ids) != 1:
        checks.append(
            TrajectoryCheck(
                name="shared_trajectory_id",
                ok=False,
                message=(
                    f"receipts span {len(ids)} distinct trajectory_ids: "
                    f"{sorted(ids)[:3]}{'...' if len(ids) > 3 else ''}"
                ),
            )
        )
        return TrajectoryAuditResult(
            ok=False,
            trajectory_id=None,
            receipt_count=len(receipts_list),
            checks=tuple(checks),
        )
    trajectory_id = next(iter(ids))
    checks.append(
        TrajectoryCheck(
            name="shared_trajectory_id",
            ok=True,
            message=f"all receipts share trajectory_id {trajectory_id}",
        )
    )

    # Index by receipt_id for the remaining structural checks.
    by_id: Dict[str, Mapping[str, Any]] = {r["receipt_id"]: r for r in receipts_list}

    # Check 3: no dangling parents.
    dangling: List[Tuple[str, str]] = []
    for r in receipts_list:
        for parent_id in r["trajectory"]["parent_step_ids"]:
            if parent_id not in by_id:
                dangling.append((r["receipt_id"], parent_id))
    if dangling:
        checks.append(
            TrajectoryCheck(
                name="no_dangling_parents",
                ok=False,
                message=(
                    f"{len(dangling)} dangling parent reference(s); first: "
                    f"receipt {dangling[0][0]} → missing parent {dangling[0][1]}"
                ),
            )
        )
    else:
        checks.append(
            TrajectoryCheck(
                name="no_dangling_parents",
                ok=True,
                message="every parent_step_id resolves",
            )
        )

    # Check 4: DAG acyclicity (three-colour iterative DFS).
    WHITE, GRAY, BLACK = 0, 1, 2
    color: Dict[str, int] = {rid: WHITE for rid in by_id}
    cycle_through: Optional[str] = None
    for start in by_id:
        if color[start] != WHITE or cycle_through is not None:
            continue
        stack: List[Tuple[str, "object"]] = [
            (start, iter(by_id[start]["trajectory"]["parent_step_ids"]))
        ]
        color[start] = GRAY
        while stack:
            node, parents_iter = stack[-1]
            try:
                p = next(parents_iter)  # type: ignore[arg-type]
            except StopIteration:
                color[node] = BLACK
                stack.pop()
                continue
            if p not in by_id:
                # Dangling — separate check above reports it.
                continue
            if color[p] == GRAY:
                cycle_through = p
                break
            if color[p] == WHITE:
                color[p] = GRAY
                stack.append((p, iter(by_id[p]["trajectory"]["parent_step_ids"])))
        if cycle_through is not None:
            break
    if cycle_through is not None:
        checks.append(
            TrajectoryCheck(
                name="dag_acyclic",
                ok=False,
                message=f"cycle detected through receipt {cycle_through}",
            )
        )
    else:
        checks.append(
            TrajectoryCheck(
                name="dag_acyclic",
                ok=True,
                message="no cycles",
            )
        )

    # Check 5: at least one root step.
    roots = [r for r in receipts_list if not r["trajectory"]["parent_step_ids"]]
    if not roots:
        checks.append(
            TrajectoryCheck(
                name="has_root_step",
                ok=False,
                message="no root step (every receipt references at least one parent)",
            )
        )
    else:
        checks.append(
            TrajectoryCheck(
                name="has_root_step",
                ok=True,
                message=f"{len(roots)} root step(s)",
            )
        )

    overall_ok = all(c.ok for c in checks)
    return TrajectoryAuditResult(
        ok=overall_ok,
        trajectory_id=trajectory_id,
        receipt_count=len(receipts_list),
        checks=tuple(checks),
    )
