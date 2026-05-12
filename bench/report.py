"""Emit benchmark results as JSON (machine-readable) and Markdown (customer-ready).

The Markdown report leads with the headline numbers a prospect will scan
first — total chunks ingested, ingest rate, p99 verification latency,
proof size + offline verification time — and follows with the full
latency tables for an architecture team's deeper read.
"""

from __future__ import annotations

import json
import platform
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .metrics import (
    LatencyHistogram,
    ThroughputMeter,
    format_bytes,
    format_rate,
    format_seconds,
)
from .workloads import WorkloadResult


@dataclass
class BenchRun:
    """Aggregated output of a full benchmark pass."""

    scale_label: str
    config: Dict[str, object]
    results: List[WorkloadResult]
    started_at: float
    ended_at: float
    db_size_bytes: int
    tree_size: int
    tree_root: str

    @property
    def wall_seconds(self) -> float:
        return self.ended_at - self.started_at


# --------------------------------------------------------------------------- #
# JSON                                                                        #
# --------------------------------------------------------------------------- #


def _histogram_to_dict(h: LatencyHistogram) -> Dict[str, object]:
    return {"name": h.name, **h.percentiles()}


def _throughput_to_dict(t: Optional[ThroughputMeter]) -> Optional[Dict[str, object]]:
    if t is None:
        return None
    return {
        "name": t.name,
        "operations": t.operations,
        "elapsed_seconds": t.elapsed_seconds(),
        "ops_per_second": t.ops_per_second(),
    }


def to_json(run: BenchRun) -> str:
    payload: Dict[str, object] = {
        "scale_label": run.scale_label,
        "config": run.config,
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "wall_seconds": run.wall_seconds,
        "platform": {
            "python": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
        },
        "db_size_bytes": run.db_size_bytes,
        "tree_size": run.tree_size,
        "tree_root": run.tree_root,
        "workloads": [
            {
                "name": r.name,
                "throughput": _throughput_to_dict(r.throughput),
                "histograms": {
                    k: _histogram_to_dict(v) for k, v in r.histograms.items()
                },
                "extras": _serialize_extras(r.extras),
            }
            for r in run.results
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False)


def _serialize_extras(extras: Dict[str, object]) -> Dict[str, object]:
    """Drop non-JSON-serializable values (e.g. the live index instance)."""
    out: Dict[str, object] = {}
    for k, v in extras.items():
        if isinstance(v, ThroughputMeter):
            out[k] = _throughput_to_dict(v)
        elif isinstance(v, (int, float, str, bool)) or v is None:
            out[k] = v
        elif isinstance(v, dict):
            out[k] = v
        else:
            # Skip live objects like the index instance and the fingerprint
            # list (which is huge and not interesting for the report).
            continue
    return out


# --------------------------------------------------------------------------- #
# Markdown                                                                    #
# --------------------------------------------------------------------------- #


def to_markdown(run: BenchRun) -> str:
    """Render a customer-facing Markdown report.

    The structure deliberately puts the punch lines at the top:

        1. Hero: total chunks, ingest time, ingest rate, storage size
        2. Verification latency p50/p95/p99
        3. Proof size + offline verification time
        4. Full latency tables
        5. Reproducibility footer (config + platform)
    """
    lines: List[str] = []
    lines.append(f"# Provenex scale benchmark — {run.scale_label}")
    lines.append("")
    lines.append(
        f"_Generated {_format_iso(run.started_at)} on "
        f"{platform.system()} {platform.machine()} "
        f"(Python {platform.python_version()})._"
    )
    lines.append("")

    # Hero numbers.
    ingest = _find(run.results, "ingest")
    verify = _find(run.results, "verify")
    proof = _find(run.results, "proof")

    lines.append("## Headline")
    lines.append("")
    if ingest and ingest.throughput is not None:
        ingest_rate = ingest.throughput.ops_per_second()
        ingest_time = ingest.throughput.elapsed_seconds()
        lines.append(
            f"- **{ingest.throughput.operations:,} chunks ingested** in "
            f"**{format_seconds(ingest_time)}** "
            f"(**{format_rate(ingest_rate)}** sustained)"
        )
    lines.append(
        f"- **Index size on disk:** {format_bytes(run.db_size_bytes)} "
        f"({_per_chunk_storage(run)})"
    )
    if verify is not None and "verify" in verify.histograms:
        pcts = verify.histograms["verify"].percentiles()
        lines.append(
            f"- **Verification latency:** "
            f"p50 {format_seconds(pcts.get('p50', 0))} / "
            f"p95 {format_seconds(pcts.get('p95', 0))} / "
            f"p99 {format_seconds(pcts.get('p99', 0))}"
        )
    if proof is not None and proof.extras:
        mean_hashes = proof.extras.get("mean_proof_hashes", 0)
        max_hashes = proof.extras.get("max_proof_hashes", 0)
        v_hist = proof.histograms.get("proof_verify_offline")
        v_p50 = v_hist.percentiles().get("p50", 0.0) if v_hist else 0.0
        lines.append(
            f"- **Inclusion proof:** mean {mean_hashes:.1f} hashes "
            f"(max {max_hashes}), offline verify {format_seconds(v_p50)} p50"
        )
    lines.append(f"- **Transparency log head:** `{run.tree_root}`")
    lines.append("")

    # Workload sections.
    for r in run.results:
        lines.append(f"## Workload: `{r.name}`")
        lines.append("")
        if r.throughput is not None:
            t = r.throughput
            lines.append(
                f"- {t.operations:,} operations in {format_seconds(t.elapsed_seconds())} "
                f"({format_rate(t.ops_per_second())})"
            )
            lines.append("")
        if r.histograms:
            lines.append(
                "| histogram | count | p50 | p95 | p99 | p999 | max | mean |"
            )
            lines.append("|---|---|---|---|---|---|---|---|")
            for name, hist in r.histograms.items():
                p = hist.percentiles()
                if not p:
                    continue
                lines.append(
                    "| `{name}` | {count:,} | {p50} | {p95} | {p99} | {p999} | "
                    "{max} | {mean} |".format(
                        name=name,
                        count=p["count"],
                        p50=format_seconds(p["p50"]),
                        p95=format_seconds(p["p95"]),
                        p99=format_seconds(p["p99"]),
                        p999=format_seconds(p["p999"]),
                        max=format_seconds(p["max"]),
                        mean=format_seconds(p["mean"]),
                    )
                )
            lines.append("")
        if r.extras:
            lines.append("**Extras:**")
            lines.append("")
            for k, v in r.extras.items():
                if isinstance(v, (int, float, str, bool)) or v is None:
                    lines.append(f"- `{k}`: {v}")
                elif isinstance(v, dict):
                    lines.append(f"- `{k}`: {json.dumps(v)}")
            lines.append("")

    # Reproducibility footer.
    lines.append("## Reproducibility")
    lines.append("")
    lines.append("```")
    lines.append(json.dumps(run.config, indent=2, sort_keys=True))
    lines.append("```")
    lines.append("")
    lines.append(
        "Same seed + same config produces bit-identical fingerprints and the "
        "same tree head."
    )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _find(results: List[WorkloadResult], name: str) -> Optional[WorkloadResult]:
    for r in results:
        if r.name == name:
            return r
    return None


def _per_chunk_storage(run: BenchRun) -> str:
    if run.tree_size <= 0 or run.db_size_bytes <= 0:
        return "n/a per chunk"
    return f"{run.db_size_bytes / run.tree_size:.0f} bytes per chunk"


def _format_iso(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(ts))
