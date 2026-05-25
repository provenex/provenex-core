"""Tests for v1.0.0 operating modes (receipts_only / advisory / enforce).

The mode controls whether the engine acts on policy decisions or only
records them. Receipts are byte-identical between modes modulo the
``policy.mode`` field; the only difference at runtime is which chunks
land in ``result.kept`` vs ``result.blocked`` and whether the advisory
callback fires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest

from provenex import (
    HmacSha256Signer,
    MODE_ADVISORY,
    MODE_ENFORCE,
    MODE_RECEIPTS_ONLY,
    Policy,
    RequestContext,
    ToolCallContext,
    VerificationPolicy,
    admission_check,
    verify_chunks,
)
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor


SECRET = b"modes-v1-test-secret"


# --------------------------------------------------------------------------- #
# Policy.mode shape                                                           #
# --------------------------------------------------------------------------- #


def test_default_policy_mode_is_receipts_only():
    assert Policy().mode == MODE_RECEIPTS_ONLY


def test_three_modes_are_distinct():
    assert MODE_RECEIPTS_ONLY != MODE_ADVISORY != MODE_ENFORCE
    assert {MODE_RECEIPTS_ONLY, MODE_ADVISORY, MODE_ENFORCE} == {
        "receipts_only",
        "advisory",
        "enforce",
    }


def test_invalid_mode_rejected_at_construction():
    with pytest.raises(ValueError, match="mode must be one of"):
        Policy(mode="strict")


def test_acts_on_decisions_only_true_in_enforce_mode():
    assert not Policy(mode=MODE_RECEIPTS_ONLY).acts_on_decisions()
    assert not Policy(mode=MODE_ADVISORY).acts_on_decisions()
    assert Policy(mode=MODE_ENFORCE).acts_on_decisions()


# --------------------------------------------------------------------------- #
# YAML parsing                                                                #
# --------------------------------------------------------------------------- #


def test_yaml_mode_parsed():
    policy = Policy.from_text(
        """
        version: 1
        mode: advisory
        verification:
          block_unauthorized: true
        """
    )
    assert policy.mode == MODE_ADVISORY


def test_yaml_mode_default_is_receipts_only():
    policy = Policy.from_text(
        """
        version: 1
        verification:
          block_unauthorized: true
        """
    )
    assert policy.mode == MODE_RECEIPTS_ONLY


def test_yaml_invalid_mode_rejected():
    from provenex.policy.evaluator import PolicyParseError

    with pytest.raises(PolicyParseError, match="mode"):
        Policy.from_text(
            """
            version: 1
            mode: strict
            """
        )


def test_yaml_non_string_mode_rejected():
    from provenex.policy.evaluator import PolicyParseError

    with pytest.raises(PolicyParseError, match="mode"):
        Policy.from_text(
            """
            version: 1
            mode: 42
            """
        )


# --------------------------------------------------------------------------- #
# Retrieval enforcement                                                       #
# --------------------------------------------------------------------------- #


@dataclass
class _Doc:
    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def _index_with_one_unauthorized_chunk():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ProvenexIngestor(index=index).ingest(
        [_Doc(page_content="confidential pricing memo body.")],
        doc_id="memo_v1",
        authorized=False,
    )
    return index


def test_enforce_drops_unauthorized_chunk():
    index = _index_with_one_unauthorized_chunk()
    result = verify_chunks(
        "confidential pricing memo body.",
        index=index,
        policy=Policy(
            mode=MODE_ENFORCE,
            verification=VerificationPolicy(block_unauthorized=True),
        ),
        signer=HmacSha256Signer(secret=SECRET),
    )
    assert result.kept == []
    assert result.blocked == ["confidential pricing memo body."]


def test_receipts_only_passes_unauthorized_chunk_through():
    index = _index_with_one_unauthorized_chunk()
    result = verify_chunks(
        "confidential pricing memo body.",
        index=index,
        policy=Policy(
            mode=MODE_RECEIPTS_ONLY,
            verification=VerificationPolicy(block_unauthorized=True),
        ),
        signer=HmacSha256Signer(secret=SECRET),
    )
    assert result.kept == ["confidential pricing memo body."]
    assert result.blocked == []
    # Receipt still records the outcome verbatim — the policy decision
    # is intact even though the engine didn't act on it.
    src = result.receipt.to_dict()["sources"][0]
    assert src["verification_outcome"] == "UNAUTHORIZED"


def test_advisory_passes_through_and_fires_callback():
    index = _index_with_one_unauthorized_chunk()
    events: List[Dict[str, Any]] = []
    result = verify_chunks(
        "confidential pricing memo body.",
        index=index,
        policy=Policy(
            mode=MODE_ADVISORY,
            verification=VerificationPolicy(block_unauthorized=True),
            advisory_callback=events.append,
        ),
        signer=HmacSha256Signer(secret=SECRET),
    )
    assert result.kept == ["confidential pricing memo body."]
    assert result.blocked == []
    assert len(events) == 1
    event = events[0]
    assert event["gate"] == "retrieval"
    assert event["receipt_id"] == result.receipt.receipt_id
    assert event["would_have_blocked"][0]["outcome"] == "UNAUTHORIZED"
    assert event["would_have_blocked"][0]["reason"] == "verification"


def test_advisory_callback_not_fired_when_nothing_would_block():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ProvenexIngestor(index=index).ingest(
        [_Doc(page_content="ok content")],
        doc_id="ok",
        authorized=True,
    )
    events: List[Dict[str, Any]] = []
    verify_chunks(
        "ok content",
        index=index,
        policy=Policy(
            mode=MODE_ADVISORY,
            verification=VerificationPolicy(block_unauthorized=True),
            advisory_callback=events.append,
        ),
        signer=HmacSha256Signer(secret=SECRET),
    )
    assert events == []


def test_advisory_callback_exception_does_not_break_caller():
    index = _index_with_one_unauthorized_chunk()

    def boom(_event: Dict[str, Any]) -> None:
        raise RuntimeError("callback misbehaves")

    # Should not raise; the callback failure is swallowed.
    result = verify_chunks(
        "confidential pricing memo body.",
        index=index,
        policy=Policy(
            mode=MODE_ADVISORY,
            verification=VerificationPolicy(block_unauthorized=True),
            advisory_callback=boom,
        ),
        signer=HmacSha256Signer(secret=SECRET),
    )
    assert result.kept == ["confidential pricing memo body."]


def test_default_advisory_callback_logs_warning(caplog):
    index = _index_with_one_unauthorized_chunk()
    caplog.set_level("WARNING", logger="provenex.advisory")
    verify_chunks(
        "confidential pricing memo body.",
        index=index,
        policy=Policy(
            mode=MODE_ADVISORY,
            verification=VerificationPolicy(block_unauthorized=True),
        ),
        signer=HmacSha256Signer(secret=SECRET),
    )
    assert any("would have blocked" in rec.message for rec in caplog.records)


# --------------------------------------------------------------------------- #
# The "receipts_only == enforce modulo policy.mode" property                  #
# --------------------------------------------------------------------------- #


def test_receipts_only_and_enforce_produce_identical_receipts_modulo_mode():
    """The spec property: the receipt content is the same under both modes;
    only ``policy.mode`` and the ``signature`` differ. This is what makes
    advisory rollouts safe — flipping to enforce later does not change
    what the receipt records.
    """
    index = _index_with_one_unauthorized_chunk()

    def receipt_under(mode: str) -> Dict[str, Any]:
        r = verify_chunks(
            "confidential pricing memo body.",
            index=index,
            policy=Policy(
                mode=mode,
                verification=VerificationPolicy(block_unauthorized=True),
            ),
            signer=HmacSha256Signer(secret=SECRET),
        )
        d = r.receipt.to_dict()
        # Strip fields that legitimately differ per invocation.
        d.pop("receipt_id", None)
        d.pop("issued_at", None)
        d.pop("signature", None)
        # Strip the field the test is explicitly factoring out.
        d["policy"].pop("mode", None)
        return d

    enforce_dict = receipt_under(MODE_ENFORCE)
    receipts_only_dict = receipt_under(MODE_RECEIPTS_ONLY)
    assert enforce_dict == receipts_only_dict


# --------------------------------------------------------------------------- #
# Tool-call admission                                                         #
# --------------------------------------------------------------------------- #


_TOOL_POLICY_YAML = """
version: 1
policy_id: modes-tool-call-v1
mode: {mode}
tool_call_control:
  rules:
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search]
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


def _denied_tool_call_request():
    return (
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "weather"},
            target_system="bing_v7",  # not in allowlist
        ),
        RequestContext(
            caller={"role": "engineer"},
            jurisdiction="US",
            purpose="research",
            timestamp="2026-05-25T10:00:00Z",
        ),
    )


def test_tool_call_enforce_denies():
    tool, req = _denied_tool_call_request()
    policy = Policy.from_text(
        _TOOL_POLICY_YAML.replace("{mode}", MODE_ENFORCE)
    )
    result = admission_check(
        tool, req, policy=policy, signer=HmacSha256Signer(secret=SECRET)
    )
    assert result.decision == "deny"


def test_tool_call_receipts_only_allows_with_receipt_intact():
    tool, req = _denied_tool_call_request()
    policy = Policy.from_text(
        _TOOL_POLICY_YAML.replace("{mode}", MODE_RECEIPTS_ONLY)
    )
    result = admission_check(
        tool, req, policy=policy, signer=HmacSha256Signer(secret=SECRET)
    )
    assert result.decision == "allow"  # engine override
    # The receipt still records the evaluator's decision verbatim.
    tcc = result.receipt.to_dict()["policy"]["tool_call_control"]
    assert tcc["decisions"][0]["decision"] == "deny"


def test_tool_call_advisory_allows_and_fires_callback():
    tool, req = _denied_tool_call_request()
    events: List[Dict[str, Any]] = []
    policy = Policy.from_text(
        _TOOL_POLICY_YAML.replace("{mode}", MODE_ADVISORY)
    )
    policy_with_cb = Policy(
        mode=policy.mode,
        verification=policy.verification,
        access_control=policy.access_control,
        tool_call_control=policy.tool_call_control,
        availability=policy.availability,
        advisory_callback=events.append,
    )
    result = admission_check(
        tool, req, policy=policy_with_cb, signer=HmacSha256Signer(secret=SECRET)
    )
    assert result.decision == "allow"
    assert len(events) == 1
    assert events[0]["gate"] == "tool_call"
    assert events[0]["would_have_blocked"][0]["tool_name"] == "web_search"


# --------------------------------------------------------------------------- #
# Mode in the canonical signed payload                                        #
# --------------------------------------------------------------------------- #


def test_mode_lives_inside_signed_payload():
    """A tampered ``policy.mode`` must break signature verification —
    that is the whole point of putting it in the canonical payload.
    """
    from provenex.core.receipt import verify_receipt_signature

    index = _index_with_one_unauthorized_chunk()
    signer = HmacSha256Signer(secret=SECRET)
    result = verify_chunks(
        "confidential pricing memo body.",
        index=index,
        policy=Policy(
            mode=MODE_RECEIPTS_ONLY,
            verification=VerificationPolicy(block_unauthorized=True),
        ),
        signer=signer,
    )
    receipt_dict = result.receipt.to_dict()
    assert receipt_dict["policy"]["mode"] == MODE_RECEIPTS_ONLY
    assert verify_receipt_signature(receipt_dict, signer) is True

    # Flip the mode to enforce and confirm the signature now fails.
    tampered = {**receipt_dict, "policy": {**receipt_dict["policy"], "mode": MODE_ENFORCE}}
    assert verify_receipt_signature(tampered, signer) is False


def test_pre_1_0_0_receipt_without_mode_remains_valid():
    """Builders constructed without a mode emit no ``policy.mode`` field,
    preserving byte-identity with 2.5.0 receipts for downstream code
    that hasn't migrated.
    """
    from provenex.core.receipt import ReceiptBuilder

    builder = ReceiptBuilder(policy=VerificationPolicy())  # no mode= kwarg
    receipt = builder.finalize(output_text="x")
    assert "mode" not in receipt.to_dict()["policy"]
