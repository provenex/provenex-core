"""Tests for IndexDriftDetector.

Two layers:

  1. Unit-level: coalescing window semantics + transport stub asserts.
  2. Acceptance: 3 distinct UNVERIFIED chunks within the window
     produce exactly one coalesced webhook POST (matches the prompt's
     acceptance criterion).
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import pytest

from provenex.drift import IndexDriftDetector


class _StubTransport:
    """Records every POST so tests can assert on the wire shape."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, dict, Dict[str, str]]] = []

    def __call__(self, url: str, body: dict, headers: Dict[str, str]) -> None:
        self.calls.append((url, body, dict(headers)))


def test_first_unverified_fires_immediately_by_default():
    """Default min_distinct=1: the first UNVERIFIED triggers a flush."""
    t = _StubTransport()
    d = IndexDriftDetector(
        webhook_url="https://hook.example/drift",
        window_seconds=300.0,
        transport=t,
    )
    evt = d.record("sha256:" + "a" * 64)
    assert evt is not None
    assert evt.delivered is True
    assert len(t.calls) == 1
    url, body, headers = t.calls[0]
    assert url == "https://hook.example/drift"
    assert body["type"] == "provenex.index_drift"
    assert body["distinct_fingerprints"] == ["sha256:" + "a" * 64]
    assert body["window_seconds"] == 300.0
    assert headers["Content-Type"] == "application/json"


def test_coalesces_three_distinct_into_one_post():
    """The acceptance test: 3 distinct UNVERIFIED chunks -> one webhook POST."""
    t = _StubTransport()
    d = IndexDriftDetector(
        webhook_url="https://hook.example/drift",
        window_seconds=300.0,
        min_distinct_before_fire=3,
        transport=t,
    )
    assert d.record("sha256:a") is None
    assert d.record("sha256:b") is None
    evt = d.record("sha256:c")
    assert evt is not None
    assert evt.delivered is True
    assert len(t.calls) == 1
    _, body, _ = t.calls[0]
    assert set(body["distinct_fingerprints"]) == {
        "sha256:a", "sha256:b", "sha256:c"
    }


def test_duplicate_fingerprints_collapse_inside_window():
    """Same fingerprint 100x -> single distinct in the event."""
    t = _StubTransport()
    d = IndexDriftDetector(
        webhook_url="https://hook.example/drift",
        window_seconds=300.0,
        min_distinct_before_fire=2,
        transport=t,
    )
    for _ in range(100):
        d.record("sha256:x")
    # Only one distinct fingerprint -> threshold of 2 not reached.
    assert t.calls == []
    # Add a second distinct fingerprint -> flush exactly once.
    evt = d.record("sha256:y")
    assert evt is not None
    assert len(t.calls) == 1
    _, body, _ = t.calls[0]
    assert set(body["distinct_fingerprints"]) == {"sha256:x", "sha256:y"}


def test_window_buffer_clears_after_flush():
    """After a flush, the window is empty; the next distinct fp starts fresh."""
    t = _StubTransport()
    d = IndexDriftDetector(
        webhook_url="https://hook.example/drift",
        window_seconds=300.0,
        transport=t,
    )
    d.record("sha256:a")
    assert d.pending_distinct() == 0  # cleared on flush
    d.record("sha256:b")
    assert d.pending_distinct() == 0  # cleared on flush
    assert len(t.calls) == 2
    assert t.calls[0][1]["distinct_fingerprints"] == ["sha256:a"]
    assert t.calls[1][1]["distinct_fingerprints"] == ["sha256:b"]


def test_no_webhook_url_still_coalesces():
    """webhook_url=None: detector tracks distinct counts but never POSTs."""
    d = IndexDriftDetector(
        webhook_url=None,
        window_seconds=300.0,
        min_distinct_before_fire=2,
    )
    assert d.record("sha256:a") is None
    evt = d.record("sha256:b")
    assert evt is not None
    assert evt.delivered is True  # vacuously delivered (no URL configured)
    assert evt.distinct_fingerprints == ["sha256:a", "sha256:b"]


def test_window_prune_drops_stale_observations():
    """Observations older than window_seconds drop out of the buffer."""
    import time

    t = _StubTransport()
    d = IndexDriftDetector(
        webhook_url="https://hook.example/drift",
        window_seconds=0.05,  # 50 ms for the test
        min_distinct_before_fire=3,
        transport=t,
    )
    d.record("sha256:a")
    d.record("sha256:b")
    assert d.pending_distinct() == 2
    time.sleep(0.1)
    # The next record triggers prune; the old observations dropped out.
    d.record("sha256:c")
    assert d.pending_distinct() == 1
    # Only the recent fingerprint is in the buffer; threshold of 3 not reached.
    assert t.calls == []


def test_transport_failure_marks_event_undelivered():
    class _Boom:
        def __call__(self, *_a, **_kw):
            raise RuntimeError("network is down")

    d = IndexDriftDetector(
        webhook_url="https://hook.example/drift",
        window_seconds=300.0,
        transport=_Boom(),
    )
    evt = d.record("sha256:x")
    assert evt is not None
    assert evt.delivered is False
    assert "network is down" in (evt.error or "")
