"""Tests for the streaming export adapters (0.6.6+).

Covers:

    * Core sinks (Stdout / File / Multi / RetryQueue) — publish
      shape, rotation, fan-out, close idempotence.
    * Error semantics — failing sinks swallowed via warnings.warn;
      the agent's hot path is never broken.
    * Wiring — every emission entrypoint (verify_chunks,
      admission_check, verify_memory, admit_memory_write,
      admit_model_inference) publishes to the supplied sink.
    * Auto-coerce — sink=[a, b] becomes MultiSink([a, b])
      automatically.

Network-sink tests (Kafka / SQS / S3 / Pub/Sub) live next to their
modules; here we only verify the contracts.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import warnings
from pathlib import Path
from typing import List

import pytest

from provenex import (
    FileJSONLSink,
    HmacSha256Signer,
    MultiSink,
    RequestContext,
    RetryQueueSink,
    SQLiteProvenanceIndex,
    SinkClosedError,
    StdoutJSONLSink,
    ToolCallContext,
    admission_check,
    admit_memory_write,
    admit_model_inference,
    start_trajectory,
    verify_chunks,
    verify_memory,
)


SECRET = b"test-streaming-secret"


def _signer() -> HmacSha256Signer:
    return HmacSha256Signer(secret=SECRET)


def _request(**kwargs) -> RequestContext:
    base = dict(
        caller={"id": "u_1", "role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-15T00:00:00Z",
    )
    base.update(kwargs)
    return RequestContext(**base)


def _make_index(tmp_path) -> SQLiteProvenanceIndex:
    return SQLiteProvenanceIndex(str(tmp_path / "p.db"), signing_secret=SECRET)


# ---------- StdoutJSONLSink ---------- #


def test_stdout_jsonl_emits_one_line_per_receipt():
    buf = io.StringIO()
    sink = StdoutJSONLSink(stream=buf)
    admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=sink,
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 1
    d = json.loads(lines[0])
    assert d["schema_version"] == "2.3.0"
    assert d["receipt_id"].startswith("prx_")


def test_stdout_jsonl_close_is_idempotent_and_blocks_publish():
    buf = io.StringIO()
    sink = StdoutJSONLSink(stream=buf)
    sink.close()
    sink.close()  # idempotent
    with pytest.raises(SinkClosedError):
        admission_check(
            tool=ToolCallContext(name="t", operation="op", parameters={}),
            request=_request(),
            signer=_signer(),
            sink=sink,
        )


# ---------- FileJSONLSink ---------- #


def test_file_jsonl_appends_one_line_per_receipt(tmp_path):
    sink = FileJSONLSink(directory=str(tmp_path))
    for _ in range(3):
        admission_check(
            tool=ToolCallContext(name="t", operation="op", parameters={}),
            request=_request(),
            signer=_signer(),
            sink=sink,
        )
    sink.close()
    files = list(tmp_path.glob("receipts-*.jsonl"))
    assert len(files) == 1
    lines = [line for line in files[0].read_text().splitlines() if line]
    assert len(lines) == 3
    for line in lines:
        assert json.loads(line)["schema_version"] == "2.3.0"


def test_file_jsonl_custom_prefix(tmp_path):
    sink = FileJSONLSink(directory=str(tmp_path), prefix="audit")
    admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=sink,
    )
    sink.close()
    files = list(tmp_path.glob("audit-*.jsonl"))
    assert len(files) == 1


def test_file_jsonl_creates_directory(tmp_path):
    target = tmp_path / "new" / "deeper"
    sink = FileJSONLSink(directory=str(target))
    admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=sink,
    )
    sink.close()
    assert target.exists()


def test_file_jsonl_rejects_traversal_in_prefix(tmp_path):
    import pytest
    with pytest.raises(ValueError, match="filename component"):
        FileJSONLSink(directory=str(tmp_path), prefix="../escape")
    with pytest.raises(ValueError):
        FileJSONLSink(directory=str(tmp_path), prefix="..")


def test_file_jsonl_refuses_symlink_target(tmp_path):
    """If the date-rotated filename pre-exists as a symlink, refuse to open.

    Without this check, an attacker who can write to the operator-configured
    directory could pre-create the expected receipt file as a symlink to a
    privileged file; the next publish would write JSON into it.
    """
    import datetime as _dt
    import pytest
    target = tmp_path / "victim.txt"
    target.write_text("untouched")
    today = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    expected = tmp_path / f"receipts-{today}.jsonl"
    expected.symlink_to(target)
    sink = FileJSONLSink(directory=str(tmp_path))
    # Call publish directly so the sink-level OSError surfaces — the
    # _safe_publish wrapper used by admission_check would swallow it.
    result = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
    )
    with pytest.raises(OSError, match="symlink"):
        sink.publish(result.receipt)
    # Victim file unmodified.
    assert target.read_text() == "untouched"


# ---------- MultiSink ---------- #


def test_multi_sink_fans_out():
    a, b = io.StringIO(), io.StringIO()
    sink = MultiSink([StdoutJSONLSink(stream=a), StdoutJSONLSink(stream=b)])
    admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=sink,
    )
    assert a.getvalue() and b.getvalue()
    assert a.getvalue() == b.getvalue()


def test_multi_sink_one_failure_doesnt_block_others():
    class Failing:
        def publish(self, r):
            raise RuntimeError("boom")
        def close(self):
            pass

    good_buf = io.StringIO()
    good = StdoutJSONLSink(stream=good_buf)
    sink = MultiSink([Failing(), good])

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        admission_check(
            tool=ToolCallContext(name="t", operation="op", parameters={}),
            request=_request(),
            signer=_signer(),
            sink=sink,
        )

    # Good sink got the receipt despite the failing one above it.
    assert good_buf.getvalue()
    # A warning was emitted for the failing sink.
    msgs = [str(x.message) for x in w]
    assert any("Failing" in m for m in msgs), msgs


def test_multi_sink_close_closes_every_child():
    closed: List[bool] = [False, False]

    class Tracker:
        def __init__(self, idx):
            self.idx = idx
        def publish(self, r):
            pass
        def close(self):
            closed[self.idx] = True

    sink = MultiSink([Tracker(0), Tracker(1)])
    sink.close()
    assert closed == [True, True]


# ---------- RetryQueueSink ---------- #


def test_retry_queue_buffers_then_drains():
    class Flake:
        def __init__(self):
            self.published = []
            self.fails_remaining = 2
        def publish(self, r):
            if self.fails_remaining > 0:
                self.fails_remaining -= 1
                raise RuntimeError("flake")
            self.published.append(r.receipt_id)
        def close(self):
            pass

    flake = Flake()
    retry = RetryQueueSink(flake, maxlen=10)
    rids = []
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        for _ in range(3):
            r = admission_check(
                tool=ToolCallContext(name="t", operation="op", parameters={}),
                request=_request(),
                signer=_signer(),
                sink=retry,
            )
            rids.append(r.receipt.receipt_id)

    # All three receipts make it through downstream in FIFO order.
    assert flake.published == rids
    assert retry.pending_count() == 0


def test_retry_queue_drops_oldest_on_overflow_and_warns():
    class AlwaysFails:
        def publish(self, r):
            raise RuntimeError("down")
        def close(self):
            pass

    retry = RetryQueueSink(AlwaysFails(), maxlen=2)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        for _ in range(5):
            admission_check(
                tool=ToolCallContext(name="t", operation="op", parameters={}),
                request=_request(),
                signer=_signer(),
                sink=retry,
            )
    # Queue is bounded; max 2.
    assert retry.pending_count() == 2
    # The full-queue transition must be surfaced — silent drop on an
    # audit-record queue is the bug we are protecting against.
    assert any("queue is full" in str(x.message) for x in w)


def test_retry_queue_close_warns_when_pending_remain():
    class AlwaysFails:
        def publish(self, r):
            raise RuntimeError("down")
        def close(self):
            pass

    retry = RetryQueueSink(AlwaysFails(), maxlen=10)
    admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=retry,
    )
    assert retry.pending_count() == 1
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        retry.close()
    # The receipt is still pending — close() must not silently abandon
    # it. The peek-before-pop pattern preserves the receipt in the queue.
    assert retry.pending_count() == 1
    assert any("still pending" in str(x.message) for x in w)


def test_retry_queue_close_drains_best_effort():
    published = []

    class GoodOnly:
        def publish(self, r):
            published.append(r.receipt_id)
        def close(self):
            pass

    retry = RetryQueueSink(GoodOnly(), maxlen=10)
    r = admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=retry,
    )
    retry.close()
    assert published == [r.receipt.receipt_id]


# ---------- Error semantics: hot path never broken ---------- #


def test_sink_exception_swallowed_with_warning():
    class FailingSink:
        def publish(self, r):
            raise RuntimeError("nope")
        def close(self):
            pass

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        result = admission_check(
            tool=ToolCallContext(name="t", operation="op", parameters={}),
            request=_request(),
            signer=_signer(),
            sink=FailingSink(),
        )
    assert result.receipt is not None
    assert any("FailingSink" in str(x.message) for x in w)


def test_sink_exception_doesnt_corrupt_trajectory_cursor():
    class FailingSink:
        def publish(self, r):
            raise RuntimeError("nope")
        def close(self):
            pass

    trj = start_trajectory(agent_id="a")
    sink = FailingSink()
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        r1 = admission_check(
            tool=ToolCallContext(name="t", operation="op", parameters={}),
            request=_request(),
            signer=_signer(),
            sink=sink,
            trajectory=trj,
        )
        r2 = admission_check(
            tool=ToolCallContext(name="t", operation="op", parameters={}),
            request=_request(),
            signer=_signer(),
            sink=sink,
            trajectory=r1.next_trajectory,
        )
    # Trajectory linkage intact despite sink failures.
    assert r2.receipt.to_dict()["trajectory"]["parent_step_ids"] == [
        r1.receipt.receipt_id
    ]


# ---------- Wiring across emission entrypoints ---------- #


def test_verify_chunks_publishes_to_sink(tmp_path):
    idx = _make_index(tmp_path)
    buf = io.StringIO()
    verify_chunks(
        chunks=["hello"],
        index=idx,
        signer=_signer(),
        request_context=_request(),
        sink=StdoutJSONLSink(stream=buf),
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["sources"]


def test_verify_memory_publishes_to_sink(tmp_path):
    idx = _make_index(tmp_path)
    buf = io.StringIO()
    verify_memory(
        ["memory entry"],
        index=idx,
        signer=_signer(),
        request_context=_request(),
        sink=StdoutJSONLSink(stream=buf),
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 1
    d = json.loads(lines[0])
    assert d["sources"][0]["content_source"] == "memory_store"


def test_admit_memory_write_publishes_to_sink():
    buf = io.StringIO()
    admit_memory_write(
        memory_key="user_profile",
        value="x",
        request=_request(),
        signer=_signer(),
        sink=StdoutJSONLSink(stream=buf),
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["actions"][0]["name"] == "memory.write"


def test_admit_model_inference_publishes_to_sink():
    buf = io.StringIO()
    admit_model_inference(
        model_name="claude-opus-4-7",
        prompt="p",
        request=_request(),
        signer=_signer(),
        sink=StdoutJSONLSink(stream=buf),
    )
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["actions"][0]["name"] == "claude-opus-4-7"


# ---------- Auto-coerce: sink=[a, b] -> MultiSink ---------- #


def test_sink_list_auto_wrapped_as_multi_sink():
    a, b, c = io.StringIO(), io.StringIO(), io.StringIO()
    admission_check(
        tool=ToolCallContext(name="t", operation="op", parameters={}),
        request=_request(),
        signer=_signer(),
        sink=[
            StdoutJSONLSink(stream=a),
            StdoutJSONLSink(stream=b),
            StdoutJSONLSink(stream=c),
        ],
    )
    assert a.getvalue() and b.getvalue() and c.getvalue()
    # Each got the same receipt JSON.
    assert a.getvalue() == b.getvalue() == c.getvalue()


# ---------- CrewAI session.add_sink ---------- #


def test_crewai_session_add_sink_accumulates():
    from provenex.integrations.crewai import ProvenexCrewSession

    with tempfile.TemporaryDirectory() as d:
        idx = SQLiteProvenanceIndex(os.path.join(d, "p.db"), signing_secret=SECRET)
        session = ProvenexCrewSession(index=idx, signer=_signer())

        a = io.StringIO()
        b = io.StringIO()
        session.add_sink(StdoutJSONLSink(stream=a))
        session.add_sink(StdoutJSONLSink(stream=b))

        session.verify_chunks("payload")
        assert a.getvalue() and b.getvalue()


def test_crewai_session_ctor_sink():
    from provenex.integrations.crewai import ProvenexCrewSession

    with tempfile.TemporaryDirectory() as d:
        idx = SQLiteProvenanceIndex(os.path.join(d, "p.db"), signing_secret=SECRET)
        buf = io.StringIO()
        session = ProvenexCrewSession(
            index=idx, signer=_signer(), sink=StdoutJSONLSink(stream=buf)
        )
        session.verify_chunks("payload")
        lines = [line for line in buf.getvalue().splitlines() if line]
        assert len(lines) == 1


# ---------- ReceiptSink Protocol shape ---------- #


def test_receipt_sink_protocol_runtime_check():
    """User-defined sinks satisfy the Protocol via structural typing."""
    from provenex import ReceiptSink

    class MyCustomSink:
        def publish(self, r):
            pass
        def close(self):
            pass

    assert isinstance(MyCustomSink(), ReceiptSink)


# ---------- Network sink: import-error message when extra missing ---------- #


def test_kafka_sink_clear_error_when_extra_missing():
    # If kafka-python is installed in dev, this test isn't meaningful;
    # the goal is verifying the lazy-import error message shape. We
    # just call the helper directly.
    from provenex.export.kafka import _require_kafka_python
    try:
        _require_kafka_python()
    except RuntimeError as e:
        assert "[export-kafka]" in str(e)
