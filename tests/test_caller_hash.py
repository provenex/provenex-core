"""Tests for the schema-2.3.0 top-level ``caller_hash`` field.

Covers:

    * Canonicalisation stability: same caller dict in different key
      orders → same hash. Same caller dict with non-ASCII (smart quotes,
      é) → stable hash.
    * Sensitivity: any change to the caller dict changes the hash.
    * Emission: caller_hash is on every receipt produced from a
      RequestContext, via either ``verify_chunks(request_context=...)``
      or ``admission_check(...)``. Receipts produced without a request
      context (the pure ReceiptBuilder path) omit it.
    * Independent re-derivation: a downstream consumer can read
      ``policy.access_control.decisions[0].inputs.request_context.caller``
      off a receipt, hash it via the public helper, and match the
      top-level field. This is the "verify-don't-trust" property.
    * Signature: signature still validates after caller_hash addition.
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
    compute_caller_hash,
    verify_chunks,
)
from provenex.core.receipt import verify_receipt_signature


SECRET = b"test-caller-hash-secret"


# ---------- canonicalisation ---------- #


def test_caller_hash_stable_across_key_order():
    a = {"id": "u_42", "role": "engineer", "team": "platform"}
    b = {"team": "platform", "role": "engineer", "id": "u_42"}
    c = {"role": "engineer", "team": "platform", "id": "u_42"}
    assert compute_caller_hash(a) == compute_caller_hash(b) == compute_caller_hash(c)


def test_caller_hash_has_sha256_prefix():
    h = compute_caller_hash({"id": "u_1"})
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64  # hex digest length


def test_caller_hash_changes_when_caller_changes():
    base = compute_caller_hash({"id": "u_42", "role": "engineer"})
    role_changed = compute_caller_hash({"id": "u_42", "role": "manager"})
    id_changed = compute_caller_hash({"id": "u_43", "role": "engineer"})
    key_added = compute_caller_hash(
        {"id": "u_42", "role": "engineer", "tenant": "acme"}
    )
    assert base != role_changed
    assert base != id_changed
    assert base != key_added


def test_caller_hash_unicode_survives():
    # Smart quotes and non-ASCII must produce a stable hash. The
    # repository convention (see CLAUDE.md) is that smart quotes
    # survive — the canonicalisation rule ``ensure_ascii=False`` is
    # what enforces it here.
    caller = {"display_name": "Renée “R” Dupont", "id": "u_99"}
    h1 = compute_caller_hash(caller)
    h2 = compute_caller_hash(dict(caller))  # reconstructed equally
    assert h1 == h2
    assert h1.startswith("sha256:")


# ---------- emission on Phase 1 (verify_chunks) ---------- #


def _make_index(tmp_path) -> SQLiteProvenanceIndex:
    return SQLiteProvenanceIndex(str(tmp_path / "p.db"), signing_secret=SECRET)


def test_verify_chunks_emits_caller_hash_when_request_context_supplied(tmp_path):
    index = _make_index(tmp_path)
    policy = Policy.from_text(
        """
version: 1
policy_id: caller-hash-test-v1
access_control:
  rules:
    - name: allow_all
      require:
        request.caller.role: { in: [engineer, admin] }
      on_violation: deny
"""
    )
    request = RequestContext(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    result = verify_chunks(
        chunks=["hello world"],
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        policy=policy,
        request_context=request,
    )
    d = result.receipt.to_dict()
    assert d["schema_version"] == "2.3.0"
    assert d["caller_hash"] == compute_caller_hash(request.caller)


def test_verify_chunks_omits_caller_hash_when_no_request_context(tmp_path):
    index = _make_index(tmp_path)
    result = verify_chunks(
        chunks=["hello world"],
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
    )
    d = result.receipt.to_dict()
    assert "caller_hash" not in d


# ---------- emission on Phase 2 (admission_check) ---------- #


def test_admission_check_always_emits_caller_hash():
    request = RequestContext(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    result = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=request,
        signer=HmacSha256Signer(secret=SECRET),
    )
    d = result.receipt.to_dict()
    assert d["caller_hash"] == compute_caller_hash(request.caller)


# ---------- independent re-derivation by a downstream consumer ---------- #


def test_caller_hash_independently_recomputable_from_decision_inputs(tmp_path):
    """A detector reads request_context.caller off the per-decision inputs
    block and recomputes the top-level caller_hash. Match means the
    receipt is self-consistent.
    """
    index = _make_index(tmp_path)
    policy = Policy.from_text(
        """
version: 1
policy_id: caller-hash-rederive-v1
access_control:
  rules:
    - name: allow_all
      require:
        request.caller.role: { in: [engineer] }
      on_violation: deny
"""
    )
    request = RequestContext(
        caller={"id": "u_42", "role": "engineer", "tenant": "acme"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    result = verify_chunks(
        chunks=["payload"],
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        policy=policy,
        request_context=request,
    )
    d = result.receipt.to_dict()

    # Pull caller off the decisions inputs (what a downstream tool
    # without access to the live RequestContext would do).
    decisions = d["policy"]["access_control"]["decisions"]
    embedded_caller = decisions[0]["inputs"]["request_context"]["caller"]

    rederived = compute_caller_hash(embedded_caller)
    assert rederived == d["caller_hash"]


# ---------- signature still verifies ---------- #


def test_signature_covers_caller_hash():
    request = RequestContext(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    result = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=request,
        signer=HmacSha256Signer(secret=SECRET),
    )
    receipt_json = json.loads(result.receipt.to_json())
    assert verify_receipt_signature(receipt_json, HmacSha256Signer(secret=SECRET))

    # Tamper with caller_hash → signature MUST fail.
    receipt_json["caller_hash"] = "sha256:" + "0" * 64
    assert not verify_receipt_signature(
        receipt_json, HmacSha256Signer(secret=SECRET)
    )
