"""Tests for the OCSF v1.3 mapping (0.6.7+).

Covers:

    * receipt_to_ocsf returns the right OCSF event class per
      situation (allowed retrieval → 6005; blocked retrieval →
      2004; allowed action → 6003; denied action → 2004).
    * Correlation: caller_hash, trajectory_id, session_id, step_kind
      flow into the OCSF metadata block correctly.
    * Severity: verification block → Critical (5); policy deny →
      High (4); allow → Informational (1).
    * Redaction: a redacted parameters/value/prompt on the receipt
      does NOT leak verbatim values onto the OCSF event.
    * OCSFAdapter: forwards converted events to a downstream
      ReceiptSink correctly, including the extra_metadata merge.
    * Unsigned receipts still convert.
    * Empty receipt (no sources, no actions) emits zero events.
    * JSON-serializability of every event.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import warnings

import pytest

from provenex import (
    HmacSha256Signer,
    OCSFAdapter,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    StdoutJSONLSink,
    ToolCallContext,
    admission_check,
    admit_memory_write,
    admit_model_inference,
    compute_caller_hash,
    receipt_to_ocsf,
    start_trajectory,
    verify_chunks,
)
from provenex.core.fingerprinter import Fingerprinter
from provenex.export.ocsf import (
    OCSF_CLASS_API_ACTIVITY,
    OCSF_CLASS_APPLICATION_ACTIVITY,
    OCSF_CLASS_DETECTION_FINDING,
    receipt_to_api_activity,
    receipt_to_application_activity,
    receipt_to_detection_finding_for_blocked_source,
    receipt_to_detection_finding_for_denied_action,
)


SECRET = b"test-ocsf-secret"


def _signer() -> HmacSha256Signer:
    return HmacSha256Signer(secret=SECRET)


def _request(role: str = "engineer", session_id: str | None = "sess-1") -> RequestContext:
    return RequestContext(
        caller={"id": "u_42", "role": role},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-15T11:30:00Z",
        session_id=session_id,
    )


def _make_index(tmp_path) -> SQLiteProvenanceIndex:
    return SQLiteProvenanceIndex(str(tmp_path / "p.db"), signing_secret=SECRET)


# ---------- Class selection ---------- #


def test_admission_allow_emits_api_activity():
    trj = start_trajectory(agent_id="a", session_id="sess-1")
    r = admission_check(
        tool=ToolCallContext(
            name="jira", operation="create_issue", parameters={"k": "v"}
        ),
        request=_request(),
        signer=_signer(),
        trajectory=trj,
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert len(events) == 1
    assert events[0]["class_uid"] == OCSF_CLASS_API_ACTIVITY
    assert events[0]["severity_id"] == 1  # Informational
    assert events[0]["metadata"]["event_code"] == "provenex.admission.allow"


def test_admission_deny_emits_detection_finding():
    policy = Policy.from_text(
        """
version: 1
policy_id: ocsf-test
tool_call_control:
  rules:
    - name: forbid_jira_for_viewers
      when: { tool.name: jira }
      require:
        request.caller.role: { in: [admin] }
      on_violation: deny
"""
    )
    r = admission_check(
        tool=ToolCallContext(name="jira", operation="create_issue", parameters={}),
        request=_request(role="viewer"),
        signer=_signer(),
        policy=policy,
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert len(events) == 1
    assert events[0]["class_uid"] == OCSF_CLASS_DETECTION_FINDING
    assert events[0]["severity_id"] == 4  # High
    assert events[0]["metadata"]["event_code"] == "provenex.admission.deny"
    assert "forbid_jira_for_viewers" in events[0]["finding_info"]["title"]


def test_retrieval_allowed_emits_application_activity(tmp_path):
    idx = _make_index(tmp_path)
    fp = Fingerprinter()
    chunk = "hello world"
    f = fp.fingerprint_chunk(chunk)
    idx.add(
        fingerprint=f,
        document_id="doc1",
        document_version="sha256:" + "a" * 64,
        chunk_offset=0,
        chunk_length=11,
        authorized=True,
    )
    r = verify_chunks(
        [chunk], idx, signer=_signer(), request_context=_request()
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert len(events) == 1
    assert events[0]["class_uid"] == OCSF_CLASS_APPLICATION_ACTIVITY
    assert events[0]["severity_id"] == 1
    assert events[0]["resources"][0]["data"]["fingerprint"] == f


def test_retrieval_blocked_emits_detection_finding_critical(tmp_path):
    # UNVERIFIED chunk + block_unverified=True → verification block.
    from provenex.policy.policy import VerificationPolicy

    idx = _make_index(tmp_path)
    r = verify_chunks(
        ["never-ingested chunk"],
        idx,
        signer=_signer(),
        policy=VerificationPolicy(block_unverified=True),
        request_context=_request(),
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert len(events) == 1
    assert events[0]["class_uid"] == OCSF_CLASS_DETECTION_FINDING
    assert events[0]["severity_id"] == 5  # Critical
    assert "UNVERIFIED" in events[0]["finding_info"]["types"]


def test_memory_write_admission_allow_emits_api_activity():
    r = admit_memory_write(
        memory_key="user_profile",
        value="x",
        request=_request(),
        signer=_signer(),
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert len(events) == 1
    assert events[0]["class_uid"] == OCSF_CLASS_API_ACTIVITY
    assert events[0]["api"]["service"]["name"] == "memory.write"
    assert events[0]["api"]["operation"] == "user_profile"


def test_model_inference_admission_allow_emits_api_activity():
    r = admit_model_inference(
        model_name="claude-opus-4-7",
        prompt="hi",
        request=_request(),
        target_provider="anthropic",
        signer=_signer(),
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert len(events) == 1
    assert events[0]["api"]["service"]["name"] == "claude-opus-4-7"
    assert "target_system:anthropic" in events[0]["api"]["service"]["labels"]


# ---------- Correlation fields ---------- #


def test_caller_hash_in_actor_user_uid():
    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert events[0]["actor"]["user"]["uid"] == r.receipt.to_dict()["caller_hash"]


def test_session_id_carried_as_session_uid():
    trj = start_trajectory(agent_id="a")
    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(session_id="sess-xyz"),
        signer=_signer(),
        trajectory=trj,
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert events[0]["metadata"]["session_uid"] == "sess-xyz"


def test_trajectory_id_carried_as_correlation_uid():
    trj = start_trajectory(agent_id="a")
    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        trajectory=trj,
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    assert events[0]["metadata"]["correlation_uid"] == trj.trajectory_id


def test_step_kind_emitted_as_label():
    trj = start_trajectory(agent_id="a")
    r = admit_memory_write(
        memory_key="k", value="v",
        request=_request(),
        signer=_signer(),
        trajectory=trj,
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    labels = events[0]["metadata"].get("labels", [])
    assert "step_kind:memory_write" in labels


def test_include_trajectory_correlator_can_be_suppressed():
    trj = start_trajectory(agent_id="a")
    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        trajectory=trj,
    )
    events = receipt_to_ocsf(
        r.receipt.to_dict(), include_trajectory_correlator=False
    )
    assert "correlation_uid" not in events[0]["metadata"]


# ---------- Redaction ---------- #


def test_redacted_value_not_leaked_to_ocsf():
    # admit_memory_write defaults to redact_value=True. The verbatim
    # value should NOT appear anywhere on the OCSF event.
    r = admit_memory_write(
        memory_key="user_profile",
        value="SECRET-PII-DO-NOT-LEAK",
        request=_request(),
        signer=_signer(),
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    blob = json.dumps(events)
    assert "SECRET-PII-DO-NOT-LEAK" not in blob


def test_redacted_prompt_not_leaked_to_ocsf():
    r = admit_model_inference(
        model_name="m",
        prompt="SECRET-PROMPT-DO-NOT-LEAK",
        request=_request(),
        signer=_signer(),
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    blob = json.dumps(events)
    assert "SECRET-PROMPT-DO-NOT-LEAK" not in blob


# ---------- extra_metadata + salted caller_hash ---------- #


def test_extra_metadata_merged_into_every_event():
    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
    )
    events = receipt_to_ocsf(
        r.receipt.to_dict(),
        extra_metadata={"organization_uid": "acme-corp", "environment": "prod"},
    )
    md = events[0]["metadata"]
    assert md["organization_uid"] == "acme-corp"
    assert md["environment"] == "prod"


def test_salted_caller_hash_prefix_survives():
    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        caller_hash_salt=b"deployment-secret",
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    uid = events[0]["actor"]["user"]["uid"]
    assert uid.startswith("hmac-sha256:")
    assert uid == compute_caller_hash(_request().caller, salt=b"deployment-secret")


# ---------- OCSFAdapter ---------- #


def test_ocsf_adapter_forwards_events_to_downstream():
    buf = io.StringIO()
    adapter = OCSFAdapter(
        downstream=StdoutJSONLSink(stream=buf),
        extra_metadata={"environment": "prod"},
    )
    admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=adapter,
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 1
    e = json.loads(lines[0])
    assert e["class_uid"] == OCSF_CLASS_API_ACTIVITY
    assert e["metadata"]["environment"] == "prod"


def test_ocsf_adapter_emits_multiple_events_from_one_receipt(tmp_path):
    # A receipt with 2 sources (allowed) emits 2 OCSF events; the
    # adapter forwards both via the downstream sink.
    idx = _make_index(tmp_path)
    fp = Fingerprinter()
    for text in ["chunk-a", "chunk-b"]:
        f = fp.fingerprint_chunk(text)
        idx.add(
            fingerprint=f,
            document_id="doc",
            document_version="sha256:" + "1" * 64,
            chunk_offset=0,
            chunk_length=len(text),
            authorized=True,
        )

    buf = io.StringIO()
    adapter = OCSFAdapter(downstream=StdoutJSONLSink(stream=buf))
    verify_chunks(
        ["chunk-a", "chunk-b"],
        idx,
        signer=_signer(),
        request_context=_request(),
        sink=adapter,
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 2
    for line in lines:
        e = json.loads(line)
        assert e["class_uid"] == OCSF_CLASS_APPLICATION_ACTIVITY


# ---------- Robustness ---------- #


def test_unsigned_receipt_still_converts():
    from provenex.core.receipt import ReceiptBuilder
    from provenex.policy.policy import VerificationPolicy

    b = ReceiptBuilder(policy=VerificationPolicy())
    receipt = b.finalize(output_text="")
    # Manually attach a caller_hash so it isn't a no-op.
    receipt_dict = receipt.to_dict()
    receipt_dict["caller_hash"] = "sha256:" + "a" * 64
    events = receipt_to_ocsf(receipt_dict)
    # No sources or actions → no events emitted.
    assert events == []


def test_class_specific_helpers_match_top_level_for_single_source(tmp_path):
    idx = _make_index(tmp_path)
    fp = Fingerprinter()
    chunk = "alpha"
    f = fp.fingerprint_chunk(chunk)
    idx.add(
        fingerprint=f,
        document_id="doc1",
        document_version="sha256:" + "a" * 64,
        chunk_offset=0,
        chunk_length=5,
        authorized=True,
    )
    r = verify_chunks([chunk], idx, signer=_signer(), request_context=_request())

    top_level = receipt_to_ocsf(r.receipt.to_dict())[0]
    direct = receipt_to_application_activity(
        r.receipt.to_dict(), r.receipt.to_dict()["sources"][0]
    )
    # The two should agree on every field except labels order (we
    # accumulate labels in different orders in some helper paths).
    for key in ("class_uid", "class_name", "category_uid", "severity_id"):
        assert top_level[key] == direct[key]


def test_all_events_json_serialisable():
    r = admit_model_inference(
        model_name="claude-opus-4-7",
        prompt=[{"role": "user", "content": "hi"}],
        request=_request(),
        target_provider="anthropic",
        signer=_signer(),
    )
    events = receipt_to_ocsf(r.receipt.to_dict())
    # The whole list round-trips through json without error.
    s = json.dumps(events)
    assert json.loads(s) == events


def test_empty_receipt_emits_zero_events():
    from provenex.core.receipt import ReceiptBuilder
    from provenex.policy.policy import VerificationPolicy

    receipt = ReceiptBuilder(policy=VerificationPolicy()).finalize(output_text="")
    assert receipt_to_ocsf(receipt.to_dict()) == []
