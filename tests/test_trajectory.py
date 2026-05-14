"""Tests for trajectory context and trajectory-aware receipts (schema 1.3.0).

Covers RFC-0003: trajectory receipts for iterative agentic retrieval.

The schema design property under test is: trajectory metadata is an OPTIONAL
block on the receipt that links per-step receipts into a DAG. Receipts without
trajectory metadata behave identically to schema 1.1.0 receipts. The trajectory
block is covered by the existing receipt signature.
"""

from __future__ import annotations

import json
import re

from provenex.core.receipt import (
    HmacSha256Signer,
    ReceiptBuilder,
    verify_receipt_signature,
)
from provenex.core.trajectory import (
    TrajectoryContext,
    audit_trajectory_dag,
    start_trajectory,
)
from provenex.index.base import VerificationOutcome


SECRET = b"test-trajectory-secret"


# --------------------------------------------------------------------------- #
# TrajectoryContext basics                                                    #
# --------------------------------------------------------------------------- #


def test_start_trajectory_allocates_id_and_zeroes_step_index():
    t = start_trajectory()
    assert t.step_index == 0
    assert t.parent_step_ids == ()
    assert re.fullmatch(r"trj_[0-9a-f]{32}", t.trajectory_id)


def test_start_trajectory_records_started_at_as_iso_utc():
    t = start_trajectory()
    # ISO-8601 UTC with millisecond precision and trailing Z, e.g.
    # "2026-05-13T10:00:00.000Z"
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z",
        t.trajectory_started_at,
    )


def test_start_trajectory_accepts_agent_id_and_step_kind():
    t = start_trajectory(agent_id="research_agent", step_kind="retrieval")
    assert t.agent_id == "research_agent"
    assert t.step_kind == "retrieval"


def test_start_trajectory_ids_are_unique():
    a = start_trajectory()
    b = start_trajectory()
    assert a.trajectory_id != b.trajectory_id


def test_trajectory_id_uses_trj_prefix_not_prx():
    """trajectory_id is its own namespace (trj_), distinct from receipt_id (prx_)."""
    t = start_trajectory()
    assert t.trajectory_id.startswith("trj_")
    assert not t.trajectory_id.startswith("prx_")


# --------------------------------------------------------------------------- #
# next_step semantics                                                         #
# --------------------------------------------------------------------------- #


def test_next_step_increments_step_index_and_preserves_trajectory_id():
    t0 = start_trajectory()
    t1 = t0.next_step(parent_step_ids=["prx_" + "a" * 32])
    assert t1.trajectory_id == t0.trajectory_id
    assert t1.step_index == t0.step_index + 1
    assert t1.parent_step_ids == ("prx_" + "a" * 32,)


def test_next_step_preserves_trajectory_started_at():
    t0 = start_trajectory()
    t1 = t0.next_step(parent_step_ids=["prx_" + "a" * 32])
    assert t1.trajectory_started_at == t0.trajectory_started_at


def test_next_step_inherits_agent_id_when_not_overridden():
    t0 = start_trajectory(agent_id="planner")
    t1 = t0.next_step(parent_step_ids=["prx_" + "a" * 32])
    assert t1.agent_id == "planner"


def test_next_step_can_override_agent_id_for_multi_agent_handoff():
    """CrewAI-style: one agent's step is the parent of another agent's step."""
    t0 = start_trajectory(agent_id="planner")
    t1 = t0.next_step(
        parent_step_ids=["prx_" + "a" * 32], agent_id="researcher"
    )
    assert t1.agent_id == "researcher"
    assert t0.agent_id == "planner"  # original unchanged (immutable)


def test_next_step_does_not_inherit_step_kind():
    """step_kind is per-step, not per-trajectory."""
    t0 = start_trajectory(step_kind="retrieval")
    t1 = t0.next_step(parent_step_ids=["prx_" + "a" * 32])
    assert t1.step_kind is None


def test_next_step_accepts_dag_shape_multiple_parents():
    """LangGraph / CrewAI parallel agents: one step has multiple parents."""
    t0 = start_trajectory()
    parents = ["prx_" + "a" * 32, "prx_" + "b" * 32, "prx_" + "c" * 32]
    t1 = t0.next_step(parent_step_ids=parents)
    assert t1.parent_step_ids == tuple(parents)


def test_next_step_accepts_parent_receipts_objects():
    """For ergonomics, next_step accepts receipt objects directly."""
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="step 1 output")

    t0 = start_trajectory()
    t1 = t0.next_step(parent_receipts=[receipt])
    assert t1.parent_step_ids == (receipt.receipt_id,)


def test_next_step_combines_parent_receipts_and_parent_step_ids():
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    r1 = builder.finalize(output_text="")

    t0 = start_trajectory()
    t1 = t0.next_step(
        parent_receipts=[r1],
        parent_step_ids=["prx_" + "z" * 32],
    )
    assert r1.receipt_id in t1.parent_step_ids
    assert "prx_" + "z" * 32 in t1.parent_step_ids
    assert len(t1.parent_step_ids) == 2


def test_trajectory_context_is_immutable():
    """A frozen dataclass; next_step returns a new instance, doesn't mutate."""
    t0 = start_trajectory()
    t1 = t0.next_step(parent_step_ids=["prx_" + "a" * 32])
    assert t0.step_index == 0  # unchanged
    assert t1.step_index == 1


# --------------------------------------------------------------------------- #
# Receipt emission with trajectory block                                      #
# --------------------------------------------------------------------------- #


def test_receipt_without_trajectory_does_not_emit_block():
    """Backward compatibility: receipts without trajectory have no block."""
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="hello")
    d = receipt.to_dict()
    assert "trajectory" not in d


def test_receipt_with_trajectory_emits_block():
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    trajectory = start_trajectory(agent_id="planner", step_kind="retrieval")
    receipt = builder.finalize(output_text="hello", trajectory=trajectory)
    d = receipt.to_dict()
    assert "trajectory" in d
    block = d["trajectory"]
    assert block["trajectory_id"] == trajectory.trajectory_id
    assert block["step_index"] == 0
    assert block["parent_step_ids"] == []
    assert block["step_kind"] == "retrieval"
    assert block["agent_id"] == "planner"
    assert block["trajectory_started_at"] == trajectory.trajectory_started_at


def test_receipt_with_trajectory_emits_dag_parents_as_list():
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    parents = ["prx_" + "a" * 32, "prx_" + "b" * 32]
    trajectory = start_trajectory().next_step(parent_step_ids=parents)
    receipt = builder.finalize(output_text="", trajectory=trajectory)
    d = receipt.to_dict()
    assert d["trajectory"]["parent_step_ids"] == parents


def test_optional_trajectory_fields_omitted_when_none():
    """step_kind and agent_id are optional — omit when not set."""
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    trajectory = start_trajectory()  # no agent_id, no step_kind
    receipt = builder.finalize(output_text="", trajectory=trajectory)
    d = receipt.to_dict()["trajectory"]
    assert "step_kind" not in d
    assert "agent_id" not in d
    # Required fields still present.
    assert "trajectory_id" in d
    assert "step_index" in d
    assert "parent_step_ids" in d
    assert "trajectory_started_at" in d


# --------------------------------------------------------------------------- #
# Schema version                                                              #
# --------------------------------------------------------------------------- #


def test_schema_version_is_current():
    """Current schema version is 1.4.0 (after the 1.3.0 trajectory bump,
    1.4.0 adds per-source claims[] and content_source).

    1.2.0 remains reserved for RFC-0001's coverage block.
    """
    receipt = ReceiptBuilder().finalize(output_text="x")
    assert receipt.schema_version == "2.2.0"
    assert receipt.to_dict()["schema_version"] == "2.2.0"


# --------------------------------------------------------------------------- #
# Signature coverage                                                          #
# --------------------------------------------------------------------------- #


def test_trajectory_block_is_covered_by_signature():
    """Tampering with any trajectory field must invalidate the signature."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    trajectory = start_trajectory(agent_id="planner")
    receipt = builder.finalize(
        output_text="hello", signer=signer, trajectory=trajectory
    )
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, signer) is True

    # Tamper with the trajectory_id.
    parsed["trajectory"]["trajectory_id"] = "trj_" + "0" * 32
    assert verify_receipt_signature(parsed, signer) is False


def test_signature_invalidates_when_parents_are_rewritten():
    """Trajectory-rewrite attack: change parent_step_ids to hide a step."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    trajectory = start_trajectory().next_step(parent_step_ids=["prx_" + "a" * 32])
    receipt = builder.finalize(output_text="", signer=signer, trajectory=trajectory)
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, signer) is True

    parsed["trajectory"]["parent_step_ids"] = []  # drop the parent
    assert verify_receipt_signature(parsed, signer) is False


def test_signature_invalidates_when_step_index_changes():
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    trajectory = start_trajectory()
    receipt = builder.finalize(output_text="", signer=signer, trajectory=trajectory)
    parsed = json.loads(receipt.to_json())
    parsed["trajectory"]["step_index"] = 99
    assert verify_receipt_signature(parsed, signer) is False


def test_signature_succeeds_round_trip_with_trajectory():
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    trajectory = start_trajectory(agent_id="research_agent", step_kind="retrieval")
    receipt = builder.finalize(
        output_text="the answer", signer=signer, trajectory=trajectory
    )
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, signer) is True


# --------------------------------------------------------------------------- #
# Determinism                                                                 #
# --------------------------------------------------------------------------- #


def test_trajectory_block_is_deterministic_given_inputs():
    """Two receipts built from the same TrajectoryContext emit identical
    trajectory blocks. (Only receipt_id and issued_at differ between
    receipts; the trajectory block is a function of the context alone.)
    """
    trajectory = start_trajectory(agent_id="a")
    b1 = ReceiptBuilder()
    b1.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    r1 = b1.finalize(output_text="", trajectory=trajectory)

    b2 = ReceiptBuilder()
    b2.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    r2 = b2.finalize(output_text="", trajectory=trajectory)

    assert r1.to_dict()["trajectory"] == r2.to_dict()["trajectory"]


# --------------------------------------------------------------------------- #
# Multi-step trajectory composition                                           #
# --------------------------------------------------------------------------- #


def test_multi_step_trajectory_forms_linear_chain():
    """Three retrieval steps in a row; each receipt references the previous."""
    trajectory = start_trajectory(agent_id="agent")
    receipts = []
    for i in range(3):
        builder = ReceiptBuilder()
        builder.add_source("sha256:" + str(i) * 64, VerificationOutcome.VERIFIED)
        if receipts:
            trajectory = trajectory.next_step(parent_receipts=[receipts[-1]])
        receipt = builder.finalize(output_text=f"step {i}", trajectory=trajectory)
        receipts.append(receipt)

    assert receipts[0].to_dict()["trajectory"]["step_index"] == 0
    assert receipts[0].to_dict()["trajectory"]["parent_step_ids"] == []
    assert receipts[1].to_dict()["trajectory"]["step_index"] == 1
    assert receipts[1].to_dict()["trajectory"]["parent_step_ids"] == [
        receipts[0].receipt_id
    ]
    assert receipts[2].to_dict()["trajectory"]["step_index"] == 2
    assert receipts[2].to_dict()["trajectory"]["parent_step_ids"] == [
        receipts[1].receipt_id
    ]
    # All share the same trajectory_id.
    tid = receipts[0].to_dict()["trajectory"]["trajectory_id"]
    for r in receipts[1:]:
        assert r.to_dict()["trajectory"]["trajectory_id"] == tid


def test_dag_shape_two_parents_one_child():
    """A merge step (LangGraph join) has two parents."""
    trajectory = start_trajectory()

    b_a = ReceiptBuilder()
    b_a.add_source("sha256:" + "a" * 64, VerificationOutcome.VERIFIED)
    branch_a = b_a.finalize(output_text="", trajectory=trajectory)

    branch_b_ctx = trajectory.next_step(parent_step_ids=[])  # parallel root branch
    b_b = ReceiptBuilder()
    b_b.add_source("sha256:" + "b" * 64, VerificationOutcome.VERIFIED)
    branch_b = b_b.finalize(output_text="", trajectory=branch_b_ctx)

    merge_ctx = trajectory.next_step(parent_receipts=[branch_a, branch_b])
    b_m = ReceiptBuilder()
    b_m.add_source("sha256:" + "c" * 64, VerificationOutcome.VERIFIED)
    merge = b_m.finalize(output_text="", trajectory=merge_ctx)

    parents = merge.to_dict()["trajectory"]["parent_step_ids"]
    assert branch_a.receipt_id in parents
    assert branch_b.receipt_id in parents
    assert len(parents) == 2


# --------------------------------------------------------------------------- #
# audit_trajectory_dag (DAG validation as a pure function)                    #
# --------------------------------------------------------------------------- #


def _build_chain(n: int) -> list[dict]:
    """Build a linear chain of n receipts as a list of dicts."""
    traj = start_trajectory(agent_id="test_agent")
    receipts: list[dict] = []
    last = None
    for _ in range(n):
        if last is not None:
            traj = traj.next_step(parent_receipts=[_DictLike(last)])
        b = ReceiptBuilder()
        b.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
        r = b.finalize(output_text="", trajectory=traj)
        last = r.to_dict()
        receipts.append(last)
    return receipts


class _DictLike:
    """Trivial wrapper that exposes ``receipt_id`` from a dict — for the
    test helper that builds chains directly from dicts."""

    def __init__(self, d: dict):
        self.receipt_id = d["receipt_id"]


def test_audit_passes_on_single_root_receipt():
    receipts = _build_chain(1)
    result = audit_trajectory_dag(receipts)
    assert result.ok is True
    assert result.receipt_count == 1
    assert result.trajectory_id == receipts[0]["trajectory"]["trajectory_id"]


def test_audit_passes_on_linear_chain():
    receipts = _build_chain(5)
    result = audit_trajectory_dag(receipts)
    assert result.ok is True
    assert result.receipt_count == 5
    # All expected checks should have run and passed.
    check_names = {c.name for c in result.checks}
    assert check_names == {
        "has_trajectory_block",
        "shared_trajectory_id",
        "no_dangling_parents",
        "dag_acyclic",
        "has_root_step",
    }


def test_audit_fails_on_missing_trajectory_block():
    b = ReceiptBuilder()
    b.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    no_trajectory = b.finalize(output_text="").to_dict()
    with_trajectory = _build_chain(1)[0]
    result = audit_trajectory_dag([no_trajectory, with_trajectory])
    assert result.ok is False
    failed = [c for c in result.checks if not c.ok]
    assert any(c.name == "has_trajectory_block" for c in failed)


def test_audit_fails_on_mixed_trajectory_ids():
    chain_a = _build_chain(2)
    chain_b = _build_chain(2)
    # Different trajectory_ids; combining them should fail.
    result = audit_trajectory_dag(chain_a + chain_b)
    assert result.ok is False
    failed_names = {c.name for c in result.checks if not c.ok}
    assert "shared_trajectory_id" in failed_names


def test_audit_fails_on_dangling_parent():
    receipts = _build_chain(3)
    # Rewrite step 1's parent to point at a non-existent receipt.
    receipts[1]["trajectory"]["parent_step_ids"] = ["prx_" + "f" * 32]
    result = audit_trajectory_dag(receipts)
    assert result.ok is False
    failed_names = {c.name for c in result.checks if not c.ok}
    assert "no_dangling_parents" in failed_names


def test_audit_fails_on_cycle():
    """Synthesize a 2-cycle: A → B → A."""
    receipts = _build_chain(2)
    # receipts[1] already references receipts[0] as parent.
    # Force receipts[0] to also reference receipts[1], creating a cycle.
    receipts[0]["trajectory"]["parent_step_ids"] = [receipts[1]["receipt_id"]]
    result = audit_trajectory_dag(receipts)
    assert result.ok is False
    failed_names = {c.name for c in result.checks if not c.ok}
    assert "dag_acyclic" in failed_names


def test_audit_fails_when_no_root_step():
    """Every receipt references a parent — no entry point."""
    receipts = _build_chain(2)
    # Make the root step also reference something (the other receipt).
    receipts[0]["trajectory"]["parent_step_ids"] = [receipts[1]["receipt_id"]]
    # Now both have parents → no root. (Also creates a cycle, which is fine
    # — both checks will fail and we just need has_root_step to be one of
    # them.)
    result = audit_trajectory_dag(receipts)
    assert result.ok is False
    failed_names = {c.name for c in result.checks if not c.ok}
    assert "has_root_step" in failed_names


def test_audit_passes_on_diamond_dag():
    """A diamond shape: root → {branch_a, branch_b} → merge."""
    traj = start_trajectory(agent_id="orchestrator")

    b_root = ReceiptBuilder()
    b_root.add_source("sha256:" + "0" * 64, VerificationOutcome.VERIFIED)
    root = b_root.finalize(output_text="", trajectory=traj).to_dict()

    # Two parallel children of root, then a merge step.
    branch_a_ctx = traj.next_step(parent_step_ids=[root["receipt_id"]])
    b_a = ReceiptBuilder()
    b_a.add_source("sha256:" + "a" * 64, VerificationOutcome.VERIFIED)
    a = b_a.finalize(output_text="", trajectory=branch_a_ctx).to_dict()

    branch_b_ctx = traj.next_step(parent_step_ids=[root["receipt_id"]])
    b_b = ReceiptBuilder()
    b_b.add_source("sha256:" + "b" * 64, VerificationOutcome.VERIFIED)
    b = b_b.finalize(output_text="", trajectory=branch_b_ctx).to_dict()

    merge_ctx = traj.next_step(
        parent_step_ids=[a["receipt_id"], b["receipt_id"]]
    )
    b_m = ReceiptBuilder()
    b_m.add_source("sha256:" + "c" * 64, VerificationOutcome.VERIFIED)
    m = b_m.finalize(output_text="final answer", trajectory=merge_ctx).to_dict()

    result = audit_trajectory_dag([root, a, b, m])
    assert result.ok is True
    assert result.receipt_count == 4


def test_audit_result_to_dict_has_expected_shape():
    receipts = _build_chain(2)
    result = audit_trajectory_dag(receipts)
    d = result.to_dict()
    assert d["overall"] == "PASS"
    assert d["receipt_count"] == 2
    assert d["trajectory_id"].startswith("trj_")
    assert isinstance(d["checks"], list)
    for c in d["checks"]:
        assert "name" in c
        assert "ok" in c
        assert "message" in c


def test_audit_empty_set_is_a_meaningful_failure():
    """Auditing an empty set: no trajectory_id present, no DAG to validate.

    Implementation detail: this short-circuits at the shared_trajectory_id
    check (zero distinct trajectory_ids is not one), so later checks like
    has_root_step do not run. The point of this test is that empty input
    is a clear failure with a meaningful message — not a silent pass.
    """
    result = audit_trajectory_dag([])
    assert result.ok is False
    assert result.receipt_count == 0
    assert result.trajectory_id is None
    failed_names = {c.name for c in result.checks if not c.ok}
    assert "shared_trajectory_id" in failed_names
