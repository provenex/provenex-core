"""Tests for the schema-2.3.0 ``trajectory.session_id`` field.

Covers:

    * Caller-side API: RequestContext.session_id, start_trajectory(session_id=),
      TrajectoryContext.session_id.
    * Flow: session_id supplied on RequestContext appears on the emitted
      trajectory block under both verify_chunks and admission_check.
    * Omission: no session_id → the field is absent (not emitted as
      ``null``) from the trajectory block.
    * Determinism preserved: differing only by session_id, two requests
      produce the same ``inputs_hash`` and the same ``caller_hash``.
      ``session_id`` is a correlation tag, NOT a policy input.
    * Propagation: cursor.session_id flows through next_step.
    * Request wins: when both cursor and request carry a session_id, the
      request's value is what appears on the emitted receipt.
    * Silent drop: session_id on a request without a trajectory is
      silently ignored (single-shot calls aren't sessions).
    * Signature: signature still validates after session_id addition;
      tampering with session_id breaks the signature.
"""

from __future__ import annotations

import json

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    ToolCallContext,
    admission_check,
    start_trajectory,
    verify_chunks,
)
from provenex.core.receipt import verify_receipt_signature
from provenex.core.trajectory import TrajectoryContext


SECRET = b"test-session-id-secret"


def _make_index(tmp_path) -> SQLiteProvenanceIndex:
    return SQLiteProvenanceIndex(str(tmp_path / "p.db"), signing_secret=SECRET)


# ---------- TrajectoryContext + start_trajectory ---------- #


def test_start_trajectory_carries_session_id():
    trj = start_trajectory(agent_id="a", session_id="sess-1")
    assert trj.session_id == "sess-1"
    assert trj.to_dict()["session_id"] == "sess-1"


def test_start_trajectory_without_session_id_omits_field():
    trj = start_trajectory(agent_id="a")
    assert trj.session_id is None
    assert "session_id" not in trj.to_dict()


def test_next_step_propagates_session_id():
    parent = start_trajectory(agent_id="a", session_id="sess-1")

    class _R:
        receipt_id = "prx_" + "f" * 32

    child = parent.next_step(parent_receipts=[_R()])
    assert child.session_id == "sess-1"
    assert child.to_dict()["session_id"] == "sess-1"


def test_next_step_session_id_override():
    parent = start_trajectory(agent_id="a", session_id="sess-1")

    class _R:
        receipt_id = "prx_" + "f" * 32

    child = parent.next_step(parent_receipts=[_R()], session_id="sess-2")
    assert child.session_id == "sess-2"
    # Parent unchanged.
    assert parent.session_id == "sess-1"


# ---------- emission on admission_check ---------- #


def test_admission_check_emits_session_id_from_request():
    trj = start_trajectory(agent_id="agent")
    req = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
        session_id="sess-from-request",
    )
    r = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=req,
        signer=HmacSha256Signer(secret=SECRET),
        trajectory=trj,
    )
    d = r.receipt.to_dict()
    assert d["trajectory"]["session_id"] == "sess-from-request"
    # Cursor advances with the session attached.
    assert r.next_trajectory is not None
    assert r.next_trajectory.session_id == "sess-from-request"


def test_admission_check_request_session_id_overrides_cursor():
    trj = start_trajectory(agent_id="agent", session_id="cursor-session")
    req = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
        session_id="request-session",
    )
    r = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=req,
        signer=HmacSha256Signer(secret=SECRET),
        trajectory=trj,
    )
    assert r.receipt.to_dict()["trajectory"]["session_id"] == "request-session"


def test_admission_check_cursor_session_used_when_request_omits():
    trj = start_trajectory(agent_id="agent", session_id="cursor-session")
    req = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
        # session_id intentionally omitted
    )
    r = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=req,
        signer=HmacSha256Signer(secret=SECRET),
        trajectory=trj,
    )
    assert r.receipt.to_dict()["trajectory"]["session_id"] == "cursor-session"


def test_admission_check_session_id_silently_dropped_without_trajectory():
    req = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
        session_id="will-be-dropped",
    )
    r = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=req,
        signer=HmacSha256Signer(secret=SECRET),
    )
    d = r.receipt.to_dict()
    assert "trajectory" not in d


# ---------- emission on verify_chunks ---------- #


def test_verify_chunks_emits_session_id_from_request(tmp_path):
    index = _make_index(tmp_path)
    trj = start_trajectory(agent_id="agent")
    req = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
        session_id="sess-vfy",
    )
    result = verify_chunks(
        chunks=["hello"],
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        request_context=req,
        trajectory=trj,
    )
    d = result.receipt.to_dict()
    assert d["trajectory"]["session_id"] == "sess-vfy"


# ---------- determinism: session_id must NOT influence inputs_hash ---------- #


def test_session_id_does_not_affect_inputs_hash(tmp_path):
    index = _make_index(tmp_path)
    policy = Policy.from_text(
        """
version: 1
policy_id: session-id-determinism-v1
access_control:
  rules:
    - name: allow_all
      require:
        request.caller.role: { in: [engineer] }
      on_violation: deny
"""
    )
    base_kwargs = dict(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    req_a = RequestContext(**base_kwargs, session_id="session-A")
    req_b = RequestContext(**base_kwargs, session_id="session-B")
    signer = HmacSha256Signer(secret=SECRET)

    ra = verify_chunks(
        chunks=["payload"],
        index=index,
        signer=signer,
        policy=policy,
        request_context=req_a,
    )
    rb = verify_chunks(
        chunks=["payload"],
        index=index,
        signer=signer,
        policy=policy,
        request_context=req_b,
    )
    da = ra.receipt.to_dict()
    db = rb.receipt.to_dict()
    # The decision MUST be identical — same caller, same chunk, same
    # rules. Differing only in session_id.
    assert (
        da["policy"]["access_control"]["decisions"][0]["inputs_hash"]
        == db["policy"]["access_control"]["decisions"][0]["inputs_hash"]
    )


def test_session_id_does_not_affect_caller_hash():
    common = dict(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    req_a = RequestContext(**common, session_id="A")
    req_b = RequestContext(**common, session_id="B")
    signer = HmacSha256Signer(secret=SECRET)
    ra = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=req_a,
        signer=signer,
    )
    rb = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=req_b,
        signer=signer,
    )
    assert ra.receipt.to_dict()["caller_hash"] == rb.receipt.to_dict()["caller_hash"]


# ---------- signature covers session_id ---------- #


def test_signature_covers_session_id():
    trj = start_trajectory(agent_id="agent")
    req = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
        session_id="sess-sig",
    )
    r = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=req,
        signer=HmacSha256Signer(secret=SECRET),
        trajectory=trj,
    )
    receipt_json = json.loads(r.receipt.to_json())
    assert verify_receipt_signature(receipt_json, HmacSha256Signer(secret=SECRET))

    # Tamper with trajectory.session_id → signature MUST fail.
    receipt_json["trajectory"]["session_id"] = "tampered"
    assert not verify_receipt_signature(
        receipt_json, HmacSha256Signer(secret=SECRET)
    )


# ---------- TrajectoryContext directly (frozen dataclass back-compat) ---------- #


def test_trajectory_context_session_id_optional_default_none():
    """Direct construction without session_id still works (back-compat)."""
    t = TrajectoryContext(
        trajectory_id="trj_" + "f" * 32,
        step_index=0,
        trajectory_started_at="2026-05-14T11:00:00.000Z",
    )
    assert t.session_id is None
    assert "session_id" not in t.to_dict()
