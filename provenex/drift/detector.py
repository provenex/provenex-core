"""IndexDriftDetector: coalesce UNVERIFIED outcomes and fire a webhook.

Operator contract
-----------------

The detector records ``(fingerprint, timestamp)`` pairs as they pass
through the verify hot path. Distinct fingerprints inside a sliding
window (default 5 minutes) are coalesced into one webhook POST. If the
same fingerprint shows up 100 times in the window, the webhook fires
once. Flushes happen lazily on the next ``record(...)`` call when the
window is full or has filled past the threshold.

Body shape::

    POST <webhook_url>
    Content-Type: application/json
    {
      "type": "provenex.index_drift",
      "window_seconds": 300,
      "distinct_fingerprints": [
        "sha256:abc...",
        "sha256:def...",
        ...
      ],
      "first_seen_ts": "2026-05-20T19:14:11Z",
      "last_seen_ts": "2026-05-20T19:18:55Z"
    }

The detector does NOT retry on webhook failure; the operator can wrap
the POST in any HTTP retry surface they prefer. The trade-off is to
keep the verify hot path unaffected by webhook downstream behaviour.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional


def _now_utc_iso() -> str:
    return (
        _dt.datetime.now(tz=_dt.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


@dataclass
class DriftEvent:
    """One coalesced drift batch."""

    distinct_fingerprints: List[str]
    window_seconds: float
    first_seen_ts: str
    last_seen_ts: str
    delivered: bool = False
    error: Optional[str] = None


class IndexDriftDetector:
    """Sliding-window coalescer for UNVERIFIED outcomes.

    Args:
        webhook_url: HTTPS URL that receives the POST. If ``None``, the
            detector still coalesces but no HTTP call is made (useful
            for unit-tests and for embedding behind an external
            transport).
        window_seconds: Sliding window length. Distinct fingerprints
            seen inside this window are coalesced into one event.
            Default 5 minutes; matches the prompt brief.
        min_distinct_before_fire: Threshold of distinct fingerprints
            inside the window that triggers a flush. Default 1 so the
            first novel UNVERIFIED fires immediately; raise to e.g. 3
            if the operator wants to ignore single-incident noise.
        headers: Optional dict of HTTP headers (auth, etc.).
        transport: Optional callable ``(url, body, headers) -> None``
            used in place of :mod:`urllib.request`. Tests inject a
            stub to assert on calls.

    Thread-safety: ``record`` and ``flush_now`` are safe to call
    concurrently. The internal window dict is guarded by an RLock.
    """

    def __init__(
        self,
        webhook_url: Optional[str],
        *,
        window_seconds: float = 300.0,
        min_distinct_before_fire: int = 1,
        headers: Optional[Dict[str, str]] = None,
        transport=None,
    ) -> None:
        self._webhook = webhook_url
        self._window_seconds = window_seconds
        self._min_distinct = max(1, min_distinct_before_fire)
        self._headers = dict(headers or {})
        self._headers.setdefault("Content-Type", "application/json")
        self._transport = transport or self._default_transport

        self._lock = threading.RLock()
        # fingerprint -> first_seen_monotonic
        self._first_seen: Dict[str, float] = {}
        # fingerprint -> last_seen_monotonic
        self._last_seen: Dict[str, float] = {}
        # fingerprint -> first_seen_iso (for the wire-format event)
        self._first_iso: Dict[str, str] = {}
        self._last_iso: Dict[str, str] = {}

    # -- recording --------------------------------------------------------- #

    def record(self, fingerprint: str) -> Optional[DriftEvent]:
        """Record an UNVERIFIED fingerprint observation.

        Returns the :class:`DriftEvent` if a flush fired on this call,
        otherwise ``None``. The webhook POST happens inline; the
        caller pays at most one HTTP round-trip per flush. The internal
        lock is released BEFORE the HTTP POST so concurrent ``record()``
        calls are not blocked by webhook latency.
        """
        now_mono = time.monotonic()
        now_iso = _now_utc_iso()
        evt: Optional[DriftEvent]
        with self._lock:
            self._prune_locked(now_mono)
            if fingerprint not in self._first_seen:
                self._first_seen[fingerprint] = now_mono
                self._first_iso[fingerprint] = now_iso
            self._last_seen[fingerprint] = now_mono
            self._last_iso[fingerprint] = now_iso

            if len(self._first_seen) < self._min_distinct:
                return None
            evt = self._snapshot_and_clear_locked()
        # POST outside the lock so a slow webhook doesn't stall the
        # verify hot path.
        return self._deliver(evt)

    def flush_now(self) -> Optional[DriftEvent]:
        """Force-flush whatever is in the window; idempotent if empty."""
        with self._lock:
            if not self._first_seen:
                return None
            evt = self._snapshot_and_clear_locked()
        return self._deliver(evt)

    def pending_distinct(self) -> int:
        with self._lock:
            return len(self._first_seen)

    # -- internals -------------------------------------------------------- #

    def _prune_locked(self, now_mono: float) -> None:
        cutoff = now_mono - self._window_seconds
        stale = [
            fp for fp, t in self._last_seen.items() if t < cutoff
        ]
        for fp in stale:
            self._first_seen.pop(fp, None)
            self._last_seen.pop(fp, None)
            self._first_iso.pop(fp, None)
            self._last_iso.pop(fp, None)

    def _snapshot_and_clear_locked(self) -> DriftEvent:
        """Build the event from the current window and clear the buffers.

        Caller must hold ``self._lock``. Clears the window so a
        concurrent ``record()`` after the snapshot accumulates into
        the next window, not this one.
        """
        fingerprints = list(self._first_seen.keys())
        first_iso = min(self._first_iso.values())
        last_iso = max(self._last_iso.values())
        evt = DriftEvent(
            distinct_fingerprints=fingerprints,
            window_seconds=self._window_seconds,
            first_seen_ts=first_iso,
            last_seen_ts=last_iso,
        )
        self._first_seen.clear()
        self._last_seen.clear()
        self._first_iso.clear()
        self._last_iso.clear()
        return evt

    def _deliver(self, evt: DriftEvent) -> DriftEvent:
        """POST the event to the webhook. Called outside the lock."""
        if self._webhook is None:
            evt.delivered = True
            return evt
        body = {
            "type": "provenex.index_drift",
            "window_seconds": evt.window_seconds,
            "distinct_fingerprints": evt.distinct_fingerprints,
            "first_seen_ts": evt.first_seen_ts,
            "last_seen_ts": evt.last_seen_ts,
        }
        try:
            self._transport(self._webhook, body, self._headers)
            evt.delivered = True
        except Exception as exc:
            evt.delivered = False
            evt.error = str(exc)
        return evt

    @staticmethod
    def _default_transport(url: str, body: dict, headers: Dict[str, str]) -> None:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            # Drain the body so the connection releases cleanly.
            resp.read(0)
