"""Tests for the schema 1.4.0 additions:

    * Item 5 — per-source ``claims[]`` (self-attribution claims).
    * Item 6 — per-source ``content_source`` (origin classifier).

Both are additive optional fields on :class:`SourceRecord`. The signature
covers them when present; receipts without them are valid 1.4.0 receipts
and behave identically to earlier schema revisions.

The load-bearing semantic for claims: **claims are signed, not verified.**
Provenex binds the claim into the receipt so the asserting agent cannot
deny it, but does not verify the claim's correctness. The tests below
exercise the binding (tampering with claims invalidates the signature)
and the schema shape; they do not (cannot) verify the claim itself.
"""

from __future__ import annotations

import json

import provenex
from provenex.core.receipt import (
    CONTENT_SOURCE_INDEXED_CORPUS,
    CONTENT_SOURCE_LIVE_TOOL_OUTPUT,
    CONTENT_SOURCE_MEMORY_STORE,
    Claim,
    HmacSha256Signer,
    ReceiptBuilder,
    verify_receipt_signature,
)
from provenex.index.base import VerificationOutcome


SECRET = b"claims-test-secret"


# --------------------------------------------------------------------------- #
# Public API surface                                                          #
# --------------------------------------------------------------------------- #


def test_claim_is_exposed_at_top_level():
    assert provenex.Claim is Claim


def test_content_source_constants_are_exposed_at_top_level():
    assert provenex.CONTENT_SOURCE_INDEXED_CORPUS == "indexed_corpus"
    assert provenex.CONTENT_SOURCE_LIVE_TOOL_OUTPUT == "live_tool_output"
    assert provenex.CONTENT_SOURCE_MEMORY_STORE == "memory_store"
    assert provenex.CONTENT_SOURCE_COMPILED_ARTIFACT == "compiled_artifact"


# --------------------------------------------------------------------------- #
# Claim dataclass                                                             #
# --------------------------------------------------------------------------- #


def test_claim_minimal_serializes_required_fields_only():
    c = Claim(type="relevant", asserted_by="self_rag")
    d = c.to_dict()
    assert d == {"type": "relevant", "asserted_by": "self_rag"}


def test_claim_with_value_and_reason_serializes_them():
    c = Claim(
        type="supports_answer",
        asserted_by="self_rag",
        value="partial",
        reason="grounds the first sub-claim, not the second",
    )
    d = c.to_dict()
    assert d["value"] == "partial"
    assert d["reason"] == "grounds the first sub-claim, not the second"


def test_claim_with_boolean_value():
    c = Claim(type="model_used_in_answer", asserted_by="agent", value=True)
    assert c.to_dict()["value"] is True


def test_claim_is_immutable():
    c = Claim(type="t", asserted_by="a")
    try:
        c.type = "other"  # type: ignore[misc]
    except Exception:
        # FrozenInstanceError on a frozen dataclass.
        pass
    else:
        raise AssertionError("Claim should be frozen")


# --------------------------------------------------------------------------- #
# Receipt emission of claims[]                                                #
# --------------------------------------------------------------------------- #


def test_source_without_claims_omits_claims_field():
    """Backward compat: absent claims means absent field on JSON."""
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="")
    src = receipt.to_dict()["sources"][0]
    assert "claims" not in src


def test_source_with_claims_emits_array():
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.VERIFIED,
        claims=[
            Claim(type="model_used_in_answer", asserted_by="agent_x", value=True),
            Claim(
                type="supports_answer",
                asserted_by="agent_x",
                value="full",
                reason="directly quoted",
            ),
        ],
    )
    receipt = builder.finalize(output_text="")
    src = receipt.to_dict()["sources"][0]
    assert "claims" in src
    assert len(src["claims"]) == 2
    assert src["claims"][0]["type"] == "model_used_in_answer"
    assert src["claims"][0]["asserted_by"] == "agent_x"
    assert src["claims"][0]["value"] is True
    assert src["claims"][1]["reason"] == "directly quoted"


def test_empty_claims_list_is_omitted_not_emitted_as_empty_array():
    """Convention matching transparency_log: empty == omitted, not emitted
    as a noisy empty array."""
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64, VerificationOutcome.VERIFIED, claims=[]
    )
    receipt = builder.finalize(output_text="")
    src = receipt.to_dict()["sources"][0]
    assert "claims" not in src


def test_claims_are_covered_by_signature():
    """Tampering with a claim's value must invalidate the receipt signature."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.VERIFIED,
        claims=[Claim(type="model_used_in_answer", asserted_by="agent", value=True)],
    )
    receipt = builder.finalize(output_text="", signer=signer)
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, signer) is True
    # Tamper: flip the claim's value from True to False.
    parsed["sources"][0]["claims"][0]["value"] = False
    assert verify_receipt_signature(parsed, signer) is False


def test_claim_insertion_invalidates_signature():
    """Inserting a claim that the agent never asserted invalidates the
    signature — auditors can trust the claim list verbatim."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="", signer=signer)
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, signer) is True
    # Forge a claim that wasn't there.
    parsed["sources"][0]["claims"] = [
        {"type": "model_used_in_answer", "asserted_by": "forged_agent", "value": True}
    ]
    assert verify_receipt_signature(parsed, signer) is False


def test_claim_removal_invalidates_signature():
    """An agent cannot retroactively pretend it didn't make a claim."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.VERIFIED,
        claims=[Claim(type="relevant", asserted_by="agent", value=False)],
    )
    receipt = builder.finalize(output_text="", signer=signer)
    parsed = json.loads(receipt.to_json())
    # Strip the claims.
    parsed["sources"][0].pop("claims")
    assert verify_receipt_signature(parsed, signer) is False


# --------------------------------------------------------------------------- #
# content_source                                                              #
# --------------------------------------------------------------------------- #


def test_source_without_content_source_omits_field():
    builder = ReceiptBuilder()
    builder.add_source("sha256:" + "1" * 64, VerificationOutcome.VERIFIED)
    receipt = builder.finalize(output_text="")
    src = receipt.to_dict()["sources"][0]
    assert "content_source" not in src


def test_content_source_is_emitted_when_set():
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.UNVERIFIED,
        content_source=CONTENT_SOURCE_LIVE_TOOL_OUTPUT,
    )
    receipt = builder.finalize(output_text="")
    src = receipt.to_dict()["sources"][0]
    assert src["content_source"] == "live_tool_output"


def test_content_source_accepts_unknown_values_for_forward_compat():
    """Provenex names a handful of values but doesn't validate — unknown
    strings pass through so the schema can be extended without a bump."""
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.UNVERIFIED,
        content_source="custom_external_database",
    )
    receipt = builder.finalize(output_text="")
    src = receipt.to_dict()["sources"][0]
    assert src["content_source"] == "custom_external_database"


def test_content_source_is_covered_by_signature():
    """Tampering with content_source must invalidate — an attacker could
    otherwise hide that an UNVERIFIED chunk was supposed to be in the
    indexed corpus."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.UNVERIFIED,
        content_source=CONTENT_SOURCE_INDEXED_CORPUS,
    )
    receipt = builder.finalize(output_text="", signer=signer)
    parsed = json.loads(receipt.to_json())
    assert verify_receipt_signature(parsed, signer) is True
    # Forge: claim UNVERIFIED chunk was "live tool output" to dampen alarm.
    parsed["sources"][0]["content_source"] = "live_tool_output"
    assert verify_receipt_signature(parsed, signer) is False


def test_content_source_with_unverified_is_the_designed_signal():
    """The motivating use case: a live-tool chunk produces UNVERIFIED but
    the auditor knows from content_source that's expected."""
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.UNVERIFIED,
        content_source=CONTENT_SOURCE_LIVE_TOOL_OUTPUT,
    )
    src = builder.finalize(output_text="").to_dict()["sources"][0]
    assert src["verification_outcome"] == "UNVERIFIED"
    assert src["content_source"] == "live_tool_output"
    # The combination tells the auditor: "this UNVERIFIED is expected, not
    # an alarm — the bytes came from a live tool, not a pre-ingested doc."


# --------------------------------------------------------------------------- #
# claims + content_source combined                                            #
# --------------------------------------------------------------------------- #


def test_both_fields_can_coexist_on_one_source_record():
    """A live-tool chunk that the model self-attributes — both fields
    appear and both are signed."""
    signer = HmacSha256Signer(secret=SECRET)
    builder = ReceiptBuilder()
    builder.add_source(
        "sha256:" + "1" * 64,
        VerificationOutcome.UNVERIFIED,
        content_source=CONTENT_SOURCE_LIVE_TOOL_OUTPUT,
        claims=[
            Claim(type="model_used_in_answer", asserted_by="web_search_agent", value=True),
        ],
    )
    receipt = builder.finalize(output_text="", signer=signer)
    parsed = json.loads(receipt.to_json())
    src = parsed["sources"][0]
    assert src["content_source"] == "live_tool_output"
    assert src["claims"][0]["type"] == "model_used_in_answer"
    assert verify_receipt_signature(parsed, signer) is True


# --------------------------------------------------------------------------- #
# Schema version                                                              #
# --------------------------------------------------------------------------- #


def test_schema_version_is_current():
    receipt = ReceiptBuilder().finalize(output_text="")
    assert receipt.schema_version == "2.1.0"
    assert receipt.to_dict()["schema_version"] == "2.1.0"
