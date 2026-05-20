"""Minimal Prometheus text-format metrics for the Provenex HTTP server.

Hand-rolled (no ``prometheus_client`` dep) because the core stays
stdlib-only. Counts a handful of admission-friendly counters and a
verify-latency histogram with operator-friendly buckets. Exposed at
``GET /metrics`` in the Prometheus text exposition format (v0.0.4).
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple


_VERIFY_BUCKETS_SEC = (
    0.0005, 0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500,
    1.0, 2.5, 5.0, 10.0,
)


class _Histogram:
    __slots__ = ("_buckets_le", "_counts", "_sum", "_count", "_lock")

    def __init__(self, buckets: Tuple[float, ...]) -> None:
        self._buckets_le = tuple(buckets) + (float("inf"),)
        self._counts: List[int] = [0] * len(self._buckets_le)
        self._sum: float = 0.0
        self._count: int = 0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for i, le in enumerate(self._buckets_le):
                if value <= le:
                    self._counts[i] += 1

    def render(self, name: str, labels: str = "") -> List[str]:
        with self._lock:
            counts = list(self._counts)
            total = self._sum
            n = self._count
        lines: List[str] = []
        for le, count in zip(self._buckets_le, counts):
            le_str = "+Inf" if le == float("inf") else str(le)
            sep = "," if labels else ""
            lines.append(f'{name}_bucket{{le="{le_str}"{sep}{labels}}} {count}')
        sep = "{" + labels + "}" if labels else ""
        lines.append(f"{name}_sum{sep} {total}")
        lines.append(f"{name}_count{sep} {n}")
        return lines


class Metrics:
    """In-process metrics store. One instance per server."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], int] = {}
        self._verify_latency = _Histogram(_VERIFY_BUCKETS_SEC)
        self._started_at = time.time()

    # -- counters ---------------------------------------------------------- #

    def incr(self, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + 1

    # -- histogram --------------------------------------------------------- #

    def observe_verify_latency(self, seconds: float) -> None:
        self._verify_latency.observe(seconds)

    # -- exposition ------------------------------------------------------- #

    def render(self) -> str:
        lines: List[str] = []
        lines.append("# HELP provenex_build_info Server identity.")
        lines.append("# TYPE provenex_build_info gauge")
        from .. import __version__

        lines.append(
            f'provenex_build_info{{version="{__version__}"}} 1'
        )
        lines.append("# HELP provenex_uptime_seconds Process uptime.")
        lines.append("# TYPE provenex_uptime_seconds gauge")
        lines.append(
            f"provenex_uptime_seconds {time.time() - self._started_at:.0f}"
        )
        with self._lock:
            counter_items = list(self._counters.items())
        # Group counter samples by name so we emit one HELP/TYPE block
        # per metric, with all label combinations beneath it.
        by_name: Dict[str, List[Tuple[Tuple[Tuple[str, str], ...], int]]] = {}
        for (name, labels), v in counter_items:
            by_name.setdefault(name, []).append((labels, v))
        for name, rows in sorted(by_name.items()):
            lines.append(f"# HELP {name} Counter.")
            lines.append(f"# TYPE {name} counter")
            for labels, v in rows:
                if labels:
                    label_str = ",".join(f'{k}="{v_}"' for k, v_ in labels)
                    lines.append(f"{name}{{{label_str}}} {v}")
                else:
                    lines.append(f"{name} {v}")
        lines.append("# HELP provenex_verify_latency_seconds Verify call latency.")
        lines.append("# TYPE provenex_verify_latency_seconds histogram")
        lines.extend(self._verify_latency.render("provenex_verify_latency_seconds"))
        return "\n".join(lines) + "\n"
