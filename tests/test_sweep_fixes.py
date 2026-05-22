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
