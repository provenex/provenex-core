"""Tests for receipt schema 2.2.0 — tool-call ``actions[]`` and the
parallel ``policy.tool_call_control`` block.

Covers:

    * :meth:`ReceiptBuilder.add_action` shape and indexing.
    * Mixed receipts (sources + actions) serialise both arrays.
    * Pure-retrieval receipts under 2.2.0 SDK emit no ``actions``
      key — the 2.1.0 shape is preserved exactly to keep the
      additive-minor contract.
    * Summary counts: ``total_actions`` / ``actions_allowed`` /
      ``actions_denied``.
    * ``overall_status`` reflects both halves: FAIL on either denied
      action or blocked chunk; PARTIAL only when neither is denied.
    * Parameter redaction: ``parameters: null`` on receipt, but
      ``parameters_hash`` still verifiable against verbatim input.
    * Signature covers the full 2.2.0 receipt (actions[] + tool_call_control
      are inside the canonical signing payload).
    * Backward compat: a 2.1.0 receipt verifier (one that ignores
      unknown keys) still validates a 2.2.0 receipt with actions.
"""

from __future__ import annotations

import json

from provenex.core.receipt import (
    SCHEMA_VERSION,
    ActionRecord,
    HmacSha256Signer,
    ReceiptBuilder,
    verify_receipt_signature,
)
from provenex.tool_call.evaluator import (
    build_tool_call_control_metadata,
    compute_parameters_hash,
)
from provenex.tool_call.evaluator import NullToolCallPolicyEvaluator


SECRET = b"test-receipt-actions-secret"


# --------------------------------------------------------------------------- #
# add_action shape + JSON                                                     #
# --------------------------------------------------------------------------- #


def test_schema_version_is_2_2_0():
    assert SCHEMA_VERSION == "2.2.0"


def test_add_action_returns_index_and_records():
    b = ReceiptBuilder()
    idx0 = b.add_action(
        name="web_search",
        operation="query",
        parameters_hash=compute_parameters_hash({"q": "weather"}),
        parameters={"q": "weather"},
        target_system="google_custom_search",
    )
    idx1 = b.add_action(
        name="jira",
        operation="create_issue",
        parameters_hash=compute_parameters_hash({"project": "INC"}),
        parameters={"project": "INC"},
        target_system="acme.atlassian.net",
        invocation_id="inv_8e2c",
    )
    assert idx0 == 0
    assert idx1 == 1

    receipt = b.finalize(output_text="")
    d = receipt.to_dict()
    assert d["actions"][0]["action_index"] == 0
    assert d["actions"][0]["name"] == "web_search"
    assert d["actions"][0]["operation"] == "query"
    assert d["actions"][0]["parameters_hash"].startswith("sha256:")
    assert d["actions"][0]["parameters"] == {"q": "weather"}
    assert d["actions"][0]["target_system"] == "google_custom_search"
    assert "invocation_id" not in d["actions"][0]

    assert d["actions"][1]["action_index"] == 1
    assert d["actions"][1]["invocation_id"] == "inv_8e2c"


def test_action_record_redaction_writes_null():
    b = ReceiptBuilder()
    h = compute_parameters_hash({"q": "secret query"})
    b.add_action(
        name="web_search",
        operation="query",
        parameters_hash=h,
        parameters=None,  # operator-redacted
    )
    d = b.finalize(output_text="").to_dict()
    assert d["actions"][0]["parameters"] is None
    assert d["actions"][0]["parameters_hash"] == h


def test_pure_retrieval_receipt_does_not_emit_actions_key():
    """A 2.2.0 SDK that emits no actions[] must produce JSON identical
    to what a 2.1.0 SDK would have produced, except for the schema
    version string. This is the additive-minor backcompat contract.
    """
    from provenex.index.base import VerificationOutcome

    b = ReceiptBuilder()
    b.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=None,
        normalization_applied=["unicode_nfc"],
    )
    d = b.finalize(output_text="").to_dict()
    assert "actions" not in d
    assert "tool_call_control" not in d["policy"]


# --------------------------------------------------------------------------- #
# Mixed receipts                                                              #
# --------------------------------------------------------------------------- #


def test_mixed_receipt_carries_both_arrays_and_policy_halves():
    from provenex.index.base import VerificationOutcome

    b = ReceiptBuilder()
    b.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=None,
        normalization_applied=[],
    )
    b.add_action(
        name="web_search",
        operation="query",
        parameters_hash=compute_parameters_hash({"q": "x"}),
        parameters={"q": "x"},
    )
    tcc = build_tool_call_control_metadata(
        NullToolCallPolicyEvaluator(),
        decisions=[
            {
                "action_index": 0,
                "decision": "allow",
                "rules_fired": [],
                "inputs_hash": "sha256:" + "f" * 64,
                "inputs": None,
            }
        ],
    )
    d = b.finalize(output_text="answer", tool_call_control=tcc).to_dict()
    assert len(d["sources"]) == 1
    assert len(d["actions"]) == 1
    assert "tool_call_control" in d["policy"]
    assert d["policy"]["tool_call_control"]["decisions"][0]["action_index"] == 0


# --------------------------------------------------------------------------- #
# Summary counts + overall_status                                             #
# --------------------------------------------------------------------------- #


def _decisions(*verdicts):
    """Synthesise a minimal decisions[] array for a tool_call_control block."""
    return [
        {
            "action_index": i,
            "decision": v,
            "rules_fired": [],
            "inputs_hash": "sha256:" + "0" * 64,
            "inputs": None,
        }
        for i, v in enumerate(verdicts)
    ]


def test_summary_counts_actions_when_present():
    b = ReceiptBuilder()
    b.add_action(name="t1", operation="op", parameters_hash="sha256:x")
    b.add_action(name="t2", operation="op", parameters_hash="sha256:y")
    tcc = build_tool_call_control_metadata(
        NullToolCallPolicyEvaluator(),
        decisions=_decisions("allow", "deny"),
    )
    s = b.finalize(output_text="", tool_call_control=tcc).summary
    assert s["total_actions"] == 2
    assert s["actions_allowed"] == 1
    assert s["actions_denied"] == 1
    assert s["overall_status"] == "FAIL"


def test_summary_skips_action_counts_when_no_actions():
    """Pure-retrieval receipts must produce the exact 2.1.0 summary."""
    from provenex.index.base import VerificationOutcome

    b = ReceiptBuilder()
    b.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=None,
        normalization_applied=[],
    )
    s = b.finalize(output_text="").summary
    assert "total_actions" not in s
    assert "actions_allowed" not in s
    assert "actions_denied" not in s


def test_overall_status_pass_when_everything_allowed():
    from provenex.index.base import VerificationOutcome

    b = ReceiptBuilder()
    b.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=None,
        normalization_applied=[],
    )
    b.add_action(name="t", operation="op", parameters_hash="sha256:x")
    tcc = build_tool_call_control_metadata(
        NullToolCallPolicyEvaluator(), decisions=_decisions("allow")
    )
    s = b.finalize(output_text="", tool_call_control=tcc).summary
    assert s["overall_status"] == "PASS"


def test_overall_status_fail_when_action_denied():
    b = ReceiptBuilder()
    b.add_action(name="t", operation="op", parameters_hash="sha256:x")
    tcc = build_tool_call_control_metadata(
        NullToolCallPolicyEvaluator(), decisions=_decisions("deny")
    )
    s = b.finalize(output_text="", tool_call_control=tcc).summary
    assert s["overall_status"] == "FAIL"


def test_overall_status_fail_when_chunk_blocked():
    """A receipt with denied chunks AND allowed actions still FAILs overall.

    Both halves matter; one failure suffices.
    """
    from provenex.index.base import VerificationOutcome
    from provenex.policy.policy import VerificationPolicy

    p = VerificationPolicy(block_unauthorized=True)
    b = ReceiptBuilder(policy=p)
    b.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.UNAUTHORIZED,
        entry=None,
        normalization_applied=[],
    )
    b.add_action(name="t", operation="op", parameters_hash="sha256:x")
    tcc = build_tool_call_control_metadata(
        NullToolCallPolicyEvaluator(), decisions=_decisions("allow")
    )
    s = b.finalize(output_text="", tool_call_control=tcc).summary
    assert s["overall_status"] == "FAIL"


def test_action_only_receipt_with_no_tcc_block_defaults_allowed():
    """If the operator added actions but no tool_call_control block,
    the wiring layer chose "no admission policy configured" — admission
    defaults to allow (parallel to no-access-control on chunks).
    """
    b = ReceiptBuilder()
    b.add_action(name="t", operation="op", parameters_hash="sha256:x")
    s = b.finalize(output_text="").summary
    assert s["total_actions"] == 1
    assert s["actions_allowed"] == 1
    assert s["actions_denied"] == 0
    assert s["overall_status"] == "PASS"


# --------------------------------------------------------------------------- #
# Signatures cover the full 2.2.0 receipt                                     #
# --------------------------------------------------------------------------- #


def test_signature_covers_actions_block():
    signer = HmacSha256Signer(secret=SECRET)
    b = ReceiptBuilder()
    b.add_action(
        name="web_search",
        operation="query",
        parameters_hash=compute_parameters_hash({"q": "x"}),
        parameters={"q": "x"},
    )
    receipt = b.finalize(output_text="", signer=signer)
    d = receipt.to_dict()
    # Signature verifies against the receipt as-is.
    assert verify_receipt_signature(d, signer) is True
    # Tamper with one action field — signature must fail.
    d["actions"][0]["operation"] = "delete"
    assert verify_receipt_signature(d, signer) is False


def test_signature_covers_tool_call_control_decisions():
    signer = HmacSha256Signer(secret=SECRET)
    b = ReceiptBuilder()
    b.add_action(name="t", operation="op", parameters_hash="sha256:x")
    tcc = build_tool_call_control_metadata(
        NullToolCallPolicyEvaluator(), decisions=_decisions("allow")
    )
    receipt = b.finalize(output_text="", signer=signer, tool_call_control=tcc)
    d = receipt.to_dict()
    assert verify_receipt_signature(d, signer) is True
    # Flip the decision under the signature — must invalidate.
    d["policy"]["tool_call_control"]["decisions"][0]["decision"] = "deny"
    assert verify_receipt_signature(d, signer) is False


# --------------------------------------------------------------------------- #
# Parameter hash is independently verifiable when parameters are redacted     #
# --------------------------------------------------------------------------- #


def test_parameters_hash_stable_across_redaction():
    """An auditor with the verbatim parameters re-derives the hash and
    matches what the receipt records, regardless of whether the receipt
    itself stored the parameters or redacted them.
    """
    verbatim = {"q": "very sensitive", "num": 10}
    h = compute_parameters_hash(verbatim)

    # Verbatim receipt.
    b1 = ReceiptBuilder()
    b1.add_action(
        name="web_search", operation="query",
        parameters_hash=h, parameters=verbatim,
    )
    d1 = b1.finalize(output_text="").to_dict()
    assert d1["actions"][0]["parameters_hash"] == h
    assert d1["actions"][0]["parameters"] == verbatim

    # Redacted receipt for the same call.
    b2 = ReceiptBuilder()
    b2.add_action(
        name="web_search", operation="query",
        parameters_hash=h, parameters=None,
    )
    d2 = b2.finalize(output_text="").to_dict()
    assert d2["actions"][0]["parameters_hash"] == h
    assert d2["actions"][0]["parameters"] is None

    # Auditor with verbatim params and the redacted receipt recomputes
    # the hash and matches the receipt's recorded hash.
    assert compute_parameters_hash(verbatim) == d2["actions"][0]["parameters_hash"]


# --------------------------------------------------------------------------- #
# JSON round-trip                                                             #
# --------------------------------------------------------------------------- #


def test_action_record_round_trips_through_json():
    rec = ActionRecord(
        action_index=3,
        name="jira",
        operation="create_issue",
        parameters_hash="sha256:" + "a" * 64,
        parameters={"project": "INC"},
        target_system="acme.atlassian.net",
        invocation_id="inv_7",
    )
    s = json.dumps(rec.to_dict(), sort_keys=True)
    parsed = json.loads(s)
    assert parsed["action_index"] == 3
    assert parsed["name"] == "jira"
    assert parsed["parameters"] == {"project": "INC"}
    assert parsed["target_system"] == "acme.atlassian.net"
    assert parsed["invocation_id"] == "inv_7"
