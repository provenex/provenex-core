"""Receipt schema tests for the 2.0.0 unified ``policy`` block.

Schema 2.0.0 unified the verification gate and the data-access gate under
a single top-level ``policy`` block. The receipt's ``policy.verification``
carries the five-outcome config; ``policy.access_control`` (optional)
carries the evaluator metadata and per-chunk decisions.

This is a breaking change from 1.x — old top-level ``policy.block_stale``
is now at ``policy.verification.block_stale``.
"""

from __future__ import annotations

import json
import os

from provenex.core.receipt import (
    SCHEMA_VERSION,
    HmacSha256Signer,
    ReceiptBuilder,
    verify_receipt_signature,
)
from provenex.index.base import VerificationOutcome


def _hmac_signer() -> HmacSha256Signer:
    os.environ.setdefault("PROVENEX_SIGNING_SECRET", "test-secret")
    return HmacSha256Signer()


def _make_access_control_block(*, fingerprint: str, decision: str = "allow") -> dict:
    return {
        "evaluator": "native_yaml",
        "policy_id": "hr-corpus-v3",
        "policy_version_hash": "sha256:" + "0" * 64,
        "policy_in_transparency_log": False,
        "decisions": [
            {
                "chunk_fingerprint": fingerprint,
                "decision": decision,
                "rules_fired": ["jurisdiction_eu_only"],
                "inputs_hash": "sha256:" + "1" * 64,
                "inputs": {
                    "chunk_metadata": {"residency": "EU"},
                    "request_context": {"jurisdiction": "EU"},
                },
            }
        ],
    }


def _build_receipt_with_one_source(*, access_control=None):
    signer = _hmac_signer()
    builder = ReceiptBuilder()
    fp = "sha256:" + "a" * 64
    builder.add_source(
        fingerprint=fp,
        outcome=VerificationOutcome.VERIFIED,
        entry=None,
    )
    receipt = builder.finalize(
        output_text="answer",
        signer=signer,
        access_control=access_control,
    )
    return receipt, fp


# --------------------------------------------------------------------------- #
# Schema version is always 2.0.0; verification always present                 #
# --------------------------------------------------------------------------- #


def test_schema_version_is_2_0_0():
    receipt, _ = _build_receipt_with_one_source(access_control=None)
    assert receipt.schema_version == SCHEMA_VERSION == "2.1.0"


def test_verification_block_always_present():
    """`policy.verification` is the always-present half — it carries the
    five-outcome config and never goes away, regardless of access control."""
    receipt, _ = _build_receipt_with_one_source(access_control=None)
    d = receipt.to_dict()
    assert "policy" in d
    assert "verification" in d["policy"]
    assert d["policy"]["verification"]["block_unauthorized"] is True
    # access_control is omitted when no evaluator is configured
    assert "access_control" not in d["policy"]


def test_access_control_block_emitted_when_provided():
    block = _make_access_control_block(fingerprint="sha256:" + "a" * 64)
    receipt, _ = _build_receipt_with_one_source(access_control=block)
    d = receipt.to_dict()
    assert d["policy"]["access_control"]["evaluator"] == "native_yaml"
    assert d["policy"]["access_control"]["policy_id"] == "hr-corpus-v3"
    assert d["policy"]["access_control"]["policy_in_transparency_log"] is False
    assert len(d["policy"]["access_control"]["decisions"]) == 1


# --------------------------------------------------------------------------- #
# Round-trip: serialize, parse, verify signature                              #
# --------------------------------------------------------------------------- #


def test_round_trip_with_access_control_signature_valid():
    block = _make_access_control_block(fingerprint="sha256:" + "a" * 64)
    receipt, _ = _build_receipt_with_one_source(access_control=block)
    serialized = json.loads(receipt.to_json())
    assert serialized["schema_version"] == "2.1.0"
    assert serialized["policy"]["access_control"]["policy_id"] == "hr-corpus-v3"
    assert verify_receipt_signature(serialized, _hmac_signer()) is True


def test_round_trip_without_access_control_signature_valid():
    receipt, _ = _build_receipt_with_one_source(access_control=None)
    serialized = json.loads(receipt.to_json())
    assert serialized["schema_version"] == "2.1.0"
    assert "access_control" not in serialized["policy"]
    assert verify_receipt_signature(serialized, _hmac_signer()) is True


def test_signature_covers_access_control_block():
    """Mutating the access_control block after signing must invalidate."""
    block = _make_access_control_block(fingerprint="sha256:" + "a" * 64)
    receipt, _ = _build_receipt_with_one_source(access_control=block)
    serialized = json.loads(receipt.to_json())
    serialized["policy"]["access_control"]["decisions"][0]["decision"] = "deny"
    assert verify_receipt_signature(serialized, _hmac_signer()) is False


def test_signature_covers_verification_block():
    """Mutating the verification half also invalidates."""
    receipt, _ = _build_receipt_with_one_source(access_control=None)
    serialized = json.loads(receipt.to_json())
    serialized["policy"]["verification"]["block_unauthorized"] = False
    assert verify_receipt_signature(serialized, _hmac_signer()) is False


# --------------------------------------------------------------------------- #
# Block contents and ordering                                                 #
# --------------------------------------------------------------------------- #


def test_access_control_block_preserves_decision_order():
    fp_a = "sha256:" + "a" * 64
    fp_b = "sha256:" + "b" * 64
    block = {
        "evaluator": "native_yaml",
        "policy_id": "p",
        "policy_version_hash": "sha256:" + "0" * 64,
        "policy_in_transparency_log": False,
        "decisions": [
            {
                "chunk_fingerprint": fp_a,
                "decision": "allow",
                "rules_fired": [],
                "inputs_hash": "sha256:" + "x" * 64,
                "inputs": None,
            },
            {
                "chunk_fingerprint": fp_b,
                "decision": "deny",
                "rules_fired": ["r1"],
                "inputs_hash": "sha256:" + "y" * 64,
                "inputs": None,
            },
        ],
    }
    signer = _hmac_signer()
    builder = ReceiptBuilder()
    builder.add_source(
        fingerprint=fp_a, outcome=VerificationOutcome.VERIFIED, entry=None
    )
    builder.add_source(
        fingerprint=fp_b, outcome=VerificationOutcome.VERIFIED, entry=None
    )
    receipt = builder.finalize(
        output_text="ans", signer=signer, access_control=block
    )
    d = receipt.to_dict()
    decisions = d["policy"]["access_control"]["decisions"]
    assert [x["chunk_fingerprint"] for x in decisions] == [fp_a, fp_b]


def test_policy_in_transparency_log_is_false_in_v0_4():
    """Forward-compat field; always False until Phase 2 lights it up."""
    block = _make_access_control_block(fingerprint="sha256:" + "a" * 64)
    receipt, _ = _build_receipt_with_one_source(access_control=block)
    d = receipt.to_dict()
    assert d["policy"]["access_control"]["policy_in_transparency_log"] is False
