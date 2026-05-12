"""Lightweight latency + throughput metrics for the bench harness.

Stdlib only. We collect samples into a list and compute percentiles via
``statistics.quantiles`` at report time. For million-sample runs this is
~10 MB of float overhead — well under any laptop's memory budget — and
keeps the code dependency-free.
"""

from __future__ import annotations

import statistics
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, List


@dataclass
class LatencyHistogram:
    """Collects per-operation durations (seconds) and reports percentiles.

    Use :meth:`record` directly for already-measured durations, or the
    :meth:`time` context manager to time an operation inline.
    """

    name: str
    samples: List[float] = field(default_factory=list)

    def record(self, duration_seconds: float) -> None:
        self.samples.append(duration_seconds)

    @contextmanager
    def time(self) -> Iterator[None]:
        t0 = time.perf_counter()
        try:
            yield
        finally:
            self.samples.append(time.perf_counter() - t0)

    def percentiles(self) -> Dict[str, float]:
        """Return p50 / p95 / p99 / p999 / min / max / mean in seconds.

        Returns an empty dict when no samples were recorded.
        """
        if not self.samples:
            return {}
        s = sorted(self.samples)
        n = len(s)
        return {
            "count": n,
            "min": s[0],
            "p50": s[(n - 1) // 2],
            "p95": s[int(0.95 * (n - 1))],
            "p99": s[int(0.99 * (n - 1))],
            "p999": s[int(0.999 * (n - 1))],
            "max": s[-1],
            "mean": statistics.fmean(s),
        }


@dataclass
class ThroughputMeter:
    """Measures how many operations completed in a window of wall time."""

    name: str
    operations: int = 0
    started_at: float = 0.0
    ended_at: float = 0.0

    def start(self) -> None:
        self.started_at = time.perf_counter()

    def stop(self) -> None:
        self.ended_at = time.perf_counter()

    def add(self, n: int = 1) -> None:
        self.operations += n

    def elapsed_seconds(self) -> float:
        return max(1e-9, self.ended_at - self.started_at)

    def ops_per_second(self) -> float:
        return self.operations / self.elapsed_seconds()


def format_seconds(seconds: float) -> str:
    """Human-readable rendering for a duration.

    Picks ns / µs / ms / s based on magnitude so the bench reports are
    readable without log scales.
    """
    if seconds < 1e-6:
        return f"{seconds * 1e9:.1f} ns"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f} µs"
    if seconds < 1.0:
        return f"{seconds * 1e3:.2f} ms"
    if seconds < 60.0:
        return f"{seconds:.2f} s"
    return f"{seconds / 60:.1f} min"


def format_rate(per_second: float) -> str:
    if per_second >= 1e6:
        return f"{per_second / 1e6:.2f}M/s"
    if per_second >= 1e3:
        return f"{per_second / 1e3:.1f}k/s"
    return f"{per_second:.1f}/s"


def format_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"
