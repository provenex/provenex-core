"""Targeted tests for the sweep round's fixes.

Covered:
    * provenex.operator._check_owner_collision (collision detection
      for Policy -> ConfigMap fan-in)
    * SQSSink + PubSubSink pre-flight size checks (skipped without the
      respective extras)
    * KafkaSink acks="all" default merge (skipped without kafka-python)
    * ProvenexToolWrapper undrained-receipts soft warning
    * IngestRequest entries max_length=10000 (skipped without pydantic)

These touch surfaces the broader sweep flagged as customer-day-one
footguns; the assertions are deliberately small.
"""

from __future__ import annotations

import warnings

import pytest


# --------------------------------------------------------------------------- #
# Operator collision detection                                                 #
# --------------------------------------------------------------------------- #


def test_owner_collision_no_existing_cm_returns_none():
    from provenex.operator import _check_owner_collision

    assert _check_owner_collision(None, policy_name="p1", target_cm="cm1") is None


def test_owner_collision_no_annotations_returns_none():
    from provenex.operator import _check_owner_collision

    assert _check_owner_collision({}, policy_name="p1", target_cm="cm1") is None


def test_owner_collision_matching_owner_returns_none():
    from provenex.operator import _check_owner_collision

    annotations = {"provenex.io/source-policy": "p1"}
    assert (
        _check_owner_collision(annotations, policy_name="p1", target_cm="cm1")
        is None
    )


def test_owner_collision_different_owner_returns_rejection():
    from provenex.operator import _check_owner_collision

    annotations = {"provenex.io/source-policy": "p_first"}
    msg = _check_owner_collision(
        annotations, policy_name="p_second", target_cm="shared-cm"
    )
    assert msg is not None
    assert "shared-cm" in msg
    assert "p_first" in msg
    assert "refusing to overwrite" in msg


# --------------------------------------------------------------------------- #
# SQSSink size check                                                           #
# --------------------------------------------------------------------------- #


def _make_oversized_receipt_dict(target_bytes: int) -> dict:
    """Build a minimal receipt-shaped dict whose JSON > target_bytes."""
    # The sink JSON-serialises receipt.to_json(); we mimic that by
    # making a duck-typed receipt with to_json + receipt_id.
    return {
        "receipt_id": "prx_oversized_test",
        "filler": "x" * target_bytes,
    }


class _DuckReceipt:
    def __init__(self, payload: dict):
        self._payload = payload
        self.receipt_id = payload.get("receipt_id", "?")

    def to_json(self, indent=None) -> str:
        import json

        return json.dumps(self._payload, indent=indent)

    def to_dict(self) -> dict:
        return dict(self._payload)


def test_sqs_sink_rejects_oversized_payload():
    boto3 = pytest.importorskip("boto3")
    from unittest.mock import MagicMock
    from provenex.export.aws import SQSSink

    sink = SQSSink.__new__(SQSSink)
    sink._closed = False
    sink._queue_url = "https://example/q"
    sink._client = MagicMock()
    sink._attrs = {}

    big = _DuckReceipt(_make_oversized_receipt_dict(300_000))
    with pytest.raises(ValueError) as exc_info:
        sink.publish(big)
    assert "exceeds SQS limit" in str(exc_info.value)
    sink._client.send_message.assert_not_called()


def test_sqs_sink_allows_small_payload():
    pytest.importorskip("boto3")
    from unittest.mock import MagicMock
    from provenex.export.aws import SQSSink

    sink = SQSSink.__new__(SQSSink)
    sink._closed = False
    sink._queue_url = "https://example/q"
    sink._client = MagicMock()
    sink._attrs = {}

    small = _DuckReceipt({"receipt_id": "prx_small", "x": "ok"})
    sink.publish(small)
    sink._client.send_message.assert_called_once()


# --------------------------------------------------------------------------- #
# PubSubSink size check                                                        #
# --------------------------------------------------------------------------- #


def test_pubsub_sink_rejects_oversized_payload():
    pytest.importorskip("google.cloud.pubsub")
    from unittest.mock import MagicMock
    from provenex.export.gcp import PubSubSink

    sink = PubSubSink.__new__(PubSubSink)
    sink._closed = False
    sink._publisher = MagicMock()
    sink._topic_path = "projects/p/topics/t"
    sink._wait = False

    big = _DuckReceipt(
        _make_oversized_receipt_dict(11 * 1024 * 1024)  # 11MB > 10MB limit
    )
    with pytest.raises(ValueError) as exc_info:
        sink.publish(big)
    assert "Pub/Sub" in str(exc_info.value) or "exceeds" in str(exc_info.value)
    sink._publisher.publish.assert_not_called()


# --------------------------------------------------------------------------- #
# KafkaSink acks default                                                       #
# --------------------------------------------------------------------------- #


def test_kafka_sink_defaults_to_acks_all(monkeypatch):
    pytest.importorskip("kafka")
    from unittest.mock import MagicMock
    from provenex.export.kafka import KafkaSink

    producer_class = MagicMock()
    monkeypatch.setattr(
        "provenex.export.kafka._require_kafka_python",
        lambda: producer_class,
    )

    KafkaSink(bootstrap_servers="localhost:9092", topic="receipts")
    kwargs = producer_class.call_args.kwargs
    assert kwargs.get("acks") == "all", (
        "Receipts are audit records; KafkaSink should default to acks='all' "
        "for at-least-once delivery (kafka-python's default is acks=1 which "
        "can silently lose messages on broker failure)."
    )


def test_kafka_sink_caller_can_override_acks(monkeypatch):
    pytest.importorskip("kafka")
    from unittest.mock import MagicMock
    from provenex.export.kafka import KafkaSink

    producer_class = MagicMock()
    monkeypatch.setattr(
        "provenex.export.kafka._require_kafka_python",
        lambda: producer_class,
    )

    KafkaSink(
        bootstrap_servers="localhost:9092",
        topic="receipts",
        producer_kwargs={"acks": 1, "linger_ms": 50},
    )
    kwargs = producer_class.call_args.kwargs
    assert kwargs.get("acks") == 1, "Caller override of acks must win"
    assert kwargs.get("linger_ms") == 50


# --------------------------------------------------------------------------- #
# ProvenexToolWrapper undrained-receipts warning                               #
# --------------------------------------------------------------------------- #


def test_tool_wrapper_warns_on_undrained_receipts(monkeypatch):
    pytest.importorskip("langchain_core")
    from provenex import HmacSha256Signer, Policy, RequestContext
    from provenex.tool_call.integrations import langchain as lc_mod
    from provenex.tool_call.integrations.langchain import ProvenexToolWrapper

    # Drop the threshold so the test runs in <1 second.
    monkeypatch.setattr(lc_mod, "_RECEIPTS_DRAIN_WARN_THRESHOLD", 5)

    # Minimal duck-typed base_tool with .name and .invoke.
    class _Tool:
        name = "noop_tool"

        def invoke(self, input):
            return {"ok": True}

    policy = Policy.from_text(
        "version: 1\npolicy_id: drain-warn-test\n"
        "tool_call_control:\n  rules: []\n  defaults:\n    unknown_metadata: allow\n",
        source="drain-warn-test",
    )
    request = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-22T00:00:00Z",
    )
    wrapper = ProvenexToolWrapper(
        base_tool=_Tool(),
        policy=policy,
        signer=HmacSha256Signer(secret=b"drain-warn-test-32-bytes-min!!a"),
        request_factory=lambda _input: request,
    )

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(7):
            wrapper.invoke({"k": "v"})

    drain_warnings = [
        w
        for w in caught
        if "drain" in str(w.message) and "ProvenexToolWrapper" in str(w.message)
    ]
    assert len(drain_warnings) == 1, (
        f"Expected exactly one drain warning at the threshold, got "
        f"{len(drain_warnings)}: {[str(w.message) for w in drain_warnings]}"
    )


# --------------------------------------------------------------------------- #
# IngestRequest entries max_length                                             #
# --------------------------------------------------------------------------- #


def test_ingest_request_rejects_oversized_batch():
    pytest.importorskip("pydantic")
    from pydantic import ValidationError

    from provenex.server.models import IngestEntry, IngestRequest

    entry = {
        "fingerprint": "sha256:" + "a" * 64,
        "document_id": "d1",
        "document_version": "sha256:" + "b" * 64,
        "chunk_offset": 0,
        "chunk_length": 100,
    }
    # Just over the configured 10_000 max.
    with pytest.raises(ValidationError):
        IngestRequest(entries=[entry] * 10_001)


def test_ingest_request_accepts_batch_within_limit():
    pytest.importorskip("pydantic")
    from provenex.server.models import IngestRequest

    entry = {
        "fingerprint": "sha256:" + "a" * 64,
        "document_id": "d1",
        "document_version": "sha256:" + "b" * 64,
        "chunk_offset": 0,
        "chunk_length": 100,
    }
    # A few-thousand-entry request should still parse.
    req = IngestRequest(entries=[entry] * 5_000)
    assert len(req.entries) == 5_000


# --------------------------------------------------------------------------- #
# MCP decorator: non-tools/call passthrough                                    #
# --------------------------------------------------------------------------- #


def test_mcp_decorator_passes_through_non_tools_call_method():
    """A request whose method isn't ``tools/call`` (resources/list,
    prompts/get, initialize) must bypass admission entirely and reach
    the handler unchanged. Otherwise the decoder would build a
    ToolCallContext with an empty name and the policy would fire on
    meaningless metadata.
    """
    from provenex import HmacSha256Signer, Policy, RequestContext
    from provenex.tool_call.integrations.mcp import provenex_mcp_admission

    policy = Policy.from_text(
        "version: 1\npolicy_id: mcp-passthrough-test\n"
        "tool_call_control:\n  rules: []\n  defaults:\n    unknown_metadata: deny\n",
        source="mcp-passthrough-test",
    )
    request_ctx = RequestContext(
        caller={"id": "u_1"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-22T00:00:00Z",
    )

    receipts: list = []

    @provenex_mcp_admission(
        policy=policy,
        signer=HmacSha256Signer(secret=b"mcp-passthrough-secret-32-bytes!"),
        request_factory=lambda req: request_ctx,
        receipts_sink=receipts,
    )
    def handler(request):
        return {"echoed_method": request.get("method")}

    # tools/list is a real MCP method; it must reach handler() unchanged.
    out = handler({"method": "tools/list", "id": 1})
    assert out == {"echoed_method": "tools/list"}
    # No receipt should have been emitted for a passthrough call.
    assert receipts == []


def test_mcp_decorator_admission_still_runs_for_tools_call():
    """Sanity check: the passthrough only fires for non-tools/call.
    A tools/call request still flows through admission and produces
    a receipt.
    """
    from provenex import HmacSha256Signer, Policy, RequestContext
    from provenex.tool_call.integrations.mcp import provenex_mcp_admission

    policy = Policy.from_text(
        "version: 1\npolicy_id: mcp-passthrough-sanity\n"
        "tool_call_control:\n  rules: []\n  defaults:\n    unknown_metadata: allow\n",
        source="mcp-passthrough-sanity",
    )
    request_ctx = RequestContext(
        caller={"id": "u_1"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-22T00:00:00Z",
    )
    receipts: list = []

    @provenex_mcp_admission(
        policy=policy,
        signer=HmacSha256Signer(secret=b"mcp-sanity-secret-32-bytes-min!a"),
        request_factory=lambda req: request_ctx,
        receipts_sink=receipts,
    )
    def handler(request):
        return {"ok": True}

    handler({
        "method": "tools/call",
        "params": {"name": "noop", "arguments": {}},
        "id": 1,
    })
    assert len(receipts) == 1


# --------------------------------------------------------------------------- #
# LlamaIndex: broader exception handling in get_content()                      #
# --------------------------------------------------------------------------- #


def test_llamaindex_extract_text_falls_back_on_attribute_error():
    """If a node's ``get_content()`` raises AttributeError (some older
    LlamaIndex versions when the internal text store is unset), the
    extractor must fall back to ``.text`` rather than crashing.
    """
    pytest.importorskip("llama_index")
    from provenex.integrations.llamaindex.retriever import ProvenexRetriever

    class _BrokenNode:
        text = "fallback-text"

        def get_content(self, *args, **kwargs):
            raise AttributeError("internal text store missing")

    # ProvenexRetriever._extract_text is the relevant private helper.
    extractor = ProvenexRetriever.__dict__.get("_extract_text")
    assert extractor is not None, "extractor helper present in retriever"
    # Bind via __get__ on a dummy instance; the helper is logically static
    # except for ``self``, which it never uses.
    assert extractor(None, _BrokenNode()) == "fallback-text"


# --------------------------------------------------------------------------- #
# OCSF: opt-in event validation                                                #
# --------------------------------------------------------------------------- #


def test_ocsf_validate_accepts_real_events():
    """validate=True on a normal receipt must NOT raise."""
    from provenex import HmacSha256Signer, Policy, RequestContext, admission_check
    from provenex.tool_call.context import ToolCallContext
    from provenex.export.ocsf import receipt_to_ocsf

    request = RequestContext(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-22T00:00:00Z",
    )
    policy = Policy.from_text(
        "version: 1\npolicy_id: ocsf-validate\n"
        "tool_call_control:\n  rules: []\n  defaults:\n    unknown_metadata: allow\n",
        source="ocsf-validate",
    )
    result = admission_check(
        tool=ToolCallContext(
            name="noop", operation="invoke", parameters={"k": "v"}
        ),
        request=request,
        policy=policy,
        signer=HmacSha256Signer(secret=b"ocsf-test-secret-32-bytes-min!ab"),
    )
    events = receipt_to_ocsf(result.receipt.to_dict(), validate=True)
    assert events  # at least one event for the allowed action


def test_validate_ocsf_event_rejects_bad_severity():
    from provenex.export.ocsf import validate_ocsf_event

    event = {
        "class_uid": 6003,
        "category_uid": 6,
        "activity_id": 1,
        "severity_id": 6,  # out of valid 1..5 range
        "type_uid": 600301,
    }
    with pytest.raises(ValueError) as exc:
        validate_ocsf_event(event)
    assert "severity_id" in str(exc.value)


def test_validate_ocsf_event_rejects_inconsistent_type_uid():
    from provenex.export.ocsf import validate_ocsf_event

    event = {
        "class_uid": 6003,
        "category_uid": 6,
        "activity_id": 1,
        "severity_id": 1,
        "type_uid": 999_999,  # not class_uid*100 + activity_id
    }
    with pytest.raises(ValueError) as exc:
        validate_ocsf_event(event)
    assert "type_uid" in str(exc.value)


def test_validate_ocsf_event_rejects_unknown_class_uid():
    from provenex.export.ocsf import validate_ocsf_event

    event = {
        "class_uid": 9999,  # not in our emit set
        "category_uid": 6,
        "activity_id": 1,
        "severity_id": 1,
        "type_uid": 999_901,
    }
    with pytest.raises(ValueError) as exc:
        validate_ocsf_event(event)
    assert "class_uid" in str(exc.value)


def test_validate_ocsf_event_rejects_missing_required_field():
    from provenex.export.ocsf import validate_ocsf_event

    event = {
        "class_uid": 6003,
        "category_uid": 6,
        "activity_id": 1,
        # severity_id missing
        "type_uid": 600301,
    }
    with pytest.raises(ValueError) as exc:
        validate_ocsf_event(event)
    assert "severity_id" in str(exc.value)


# --------------------------------------------------------------------------- #
# Bloom wrapper: entry_kind forwarding (correctness)                           #
# --------------------------------------------------------------------------- #


def test_bloom_wrapper_forwards_entry_kind_to_base():
    """Without forwarding, window-only rows would silently get promoted
    to whole_chunk and start returning VERIFIED instead of UNVERIFIED.
    """
    from provenex import HmacSha256Signer, VerificationOutcome
    from provenex.index.base import ENTRY_KIND_WHOLE_CHUNK, ENTRY_KIND_WINDOW
    from provenex.index.bloom import BloomAcceleratedIndex
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    fp_chunk = "sha256:" + "a" * 64
    fp_window = "sha256:" + "b" * 64
    secret = b"bloom-entry-kind-test-32-bytes!a"

    base = SQLiteProvenanceIndex(":memory:", signing_secret=secret)
    try:
        wrapped = BloomAcceleratedIndex(base=base)
        # Whole-chunk goes through with the default kind.
        wrapped.add(
            fingerprint=fp_chunk,
            document_id="d1",
            document_version="sha256:" + "c" * 64,
            chunk_offset=0,
            chunk_length=100,
        )
        # Window entry: MUST forward entry_kind=ENTRY_KIND_WINDOW.
        wrapped.add(
            fingerprint=fp_window,
            document_id="d1",
            document_version="sha256:" + "c" * 64,
            chunk_offset=10,
            chunk_length=20,
            entry_kind=ENTRY_KIND_WINDOW,
        )

        # Whole-chunk row returns VERIFIED on verify.
        assert wrapped.verify(fp_chunk) == VerificationOutcome.VERIFIED
        # Window row MUST return UNVERIFIED (locator only); if entry_kind
        # had been dropped, it would have been promoted to whole_chunk
        # and returned VERIFIED.
        assert wrapped.verify(fp_window) == VerificationOutcome.UNVERIFIED
    finally:
        base.close()


def test_bloom_wrapper_verify_batch_routes_through_base_bulk_query():
    """verify_batch should screen via Bloom and then issue ONE bulk
    call to the wrapped backend for the hits, not N per-fingerprint
    calls.
    """
    from unittest.mock import patch

    from provenex import VerificationOutcome
    from provenex.index.bloom import BloomAcceleratedIndex
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    fp_a = "sha256:" + "a" * 64
    fp_b = "sha256:" + "b" * 64
    fp_c = "sha256:" + "c" * 64
    secret = b"bloom-verify-batch-test-32-bytes"

    base = SQLiteProvenanceIndex(":memory:", signing_secret=secret)
    try:
        base.add(
            fingerprint=fp_a,
            document_id="d",
            document_version="sha256:" + "0" * 64,
            chunk_offset=0,
            chunk_length=50,
        )
        base.add(
            fingerprint=fp_b,
            document_id="d",
            document_version="sha256:" + "0" * 64,
            chunk_offset=50,
            chunk_length=50,
        )
        wrapped = BloomAcceleratedIndex(base=base)

        with patch.object(
            base, "verify_batch", wraps=base.verify_batch
        ) as spy:
            results = wrapped.verify_batch([fp_a, fp_b, fp_c])
            assert spy.call_count == 1, "expected exactly one delegated bulk call"
            args, kwargs = spy.call_args
            # The delegated bulk call must include only the bloom-hit
            # fingerprints. With the NoopBloomFilter (OSS default) every
            # fingerprint reports "probably contains", so all three go
            # through; this still tests the bulk routing.
            assert list(args[0]) == [fp_a, fp_b, fp_c]
        outcomes = [r[0] for r in results]
        assert outcomes == [
            VerificationOutcome.VERIFIED,
            VerificationOutcome.VERIFIED,
            VerificationOutcome.UNVERIFIED,
        ]
    finally:
        base.close()


# --------------------------------------------------------------------------- #
# Simulator: zero-decision warning                                             #
# --------------------------------------------------------------------------- #


def test_simulator_warns_on_zero_decisions(tmp_path):
    """A corpus of receipts with no access_control decisions (e.g.,
    verification-only or schema 1.4.0) used to produce a silent
    empty diff. Now the report carries a note explaining the cause.
    """
    import json

    from provenex.policy.simulator import simulate
    from provenex.policy.unified import Policy

    # Two verification-only receipts: no policy.access_control block.
    for i in range(2):
        receipt = {
            "receipt_id": f"prx_{i}",
            "policy": {"verification": {"block_unverified": False}},
            "sources": [],
            "signature": {"algorithm": "hmac-sha256", "value": "0" * 64},
        }
        (tmp_path / f"r{i}.json").write_text(json.dumps(receipt))

    new_policy = Policy.from_text(
        "version: 1\npolicy_id: sim-warn-test\n"
        "access_control:\n  rules:\n    - name: r\n"
        "      require:\n        chunk.metadata.x: y\n"
        "      on_violation: deny\n",
        source="sim-warn-test",
    )
    report = simulate(new_policy, tmp_path)
    assert report.receipts_examined == 2
    assert report.decisions_examined == 0
    assert len(report.notes) == 1
    assert "no decisions examined" in report.notes[0]
    assert "verification-only" in report.notes[0]
    # The note is also reflected in human + JSON output.
    assert "Notes" in report.to_human_diff()
    assert report.to_dict()["notes"] == report.notes
