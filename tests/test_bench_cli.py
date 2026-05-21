"""Smoke tests for the shipped ``provenex bench`` reproducer.

These tests don't try to validate latency numbers — those are
hardware-dependent. They verify the CLI / subpackage wiring stays
intact and the JSON report carries the keys downstream tooling
expects.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from provenex.bench.scale import PRESETS, run


def test_presets_cover_all_scales():
    """A regression guard: don't accidentally drop a scale preset."""
    assert {"1k", "10k", "100k", "1m"}.issubset(PRESETS.keys())


def test_run_smallest_scale_produces_expected_shape(capsys):
    result = run(scale="1k", seed=42, verify_samples=200)
    d = result.to_dict()

    # Top-level keys downstream tooling reads.
    expected_top = {
        "provenex_version", "scale", "target_chunks", "seed", "chunk_chars",
        "platform", "ingest", "verify", "db_size_bytes",
        "elapsed_total_seconds",
    }
    assert expected_top.issubset(d.keys())

    # Stable percentile keys downstream tooling reads.
    for section in ("ingest", "verify"):
        pcts = d[section]["percentiles_seconds"]
        assert {"p50", "p95", "p99", "p999", "max", "mean", "min", "count"}.issubset(pcts.keys())
        # Percentiles are non-decreasing.
        assert pcts["p50"] <= pcts["p95"] <= pcts["p99"] <= pcts["p999"]
        assert pcts["min"] <= pcts["p50"]
        assert pcts["p999"] <= pcts["max"]


def test_run_determinism_in_corpus(capsys):
    """Same seed must produce the same chunk fingerprints and the same
    count of UNVERIFIED vs VERIFIED outcomes."""
    r1 = run(scale="1k", seed=42, verify_samples=500, unknown_rate=0.2)
    r2 = run(scale="1k", seed=42, verify_samples=500, unknown_rate=0.2)
    # Outcome counts are seeded — they must match across runs.
    assert r1.verify["outcome_counts"] == r2.verify["outcome_counts"]


def test_run_unknown_rate_zero_means_all_verified(capsys):
    r = run(scale="1k", seed=7, verify_samples=300, unknown_rate=0.0)
    counts = r.verify["outcome_counts"]
    # With unknown_rate=0, every sample is a known fingerprint -> VERIFIED.
    assert counts.get("UNVERIFIED", 0) == 0
    assert counts.get("VERIFIED", 0) == 300


def test_run_rejects_unknown_scale():
    with pytest.raises(ValueError):
        run(scale="42m", seed=42, verify_samples=100)


def test_cli_main_module_entry_point(tmp_path: Path):
    """`python -m provenex.bench.scale` must work as a module entry point."""
    out_file = tmp_path / "bench.json"
    proc = subprocess.run(
        [
            sys.executable, "-m", "provenex.bench.scale",
            "--scale", "1k",
            "--verify-samples", "100",
            "--out", str(out_file),
            "--json-only",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    # JSON to stdout
    payload = json.loads(proc.stdout)
    assert payload["scale"] == "1k"
    assert payload["verify"]["samples"] == 100
    # Same JSON also written to --out
    assert out_file.exists()
    assert json.loads(out_file.read_text())["scale"] == "1k"


def test_provenex_cli_bench_subcommand(tmp_path: Path):
    """The 'provenex bench' subcommand must dispatch into provenex.bench.scale."""
    proc = subprocess.run(
        [
            sys.executable, "-m", "provenex.cli.main",
            "bench",
            "--scale", "1k",
            "--verify-samples", "100",
            "--json-only",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["scale"] == "1k"
    assert payload["target_chunks"] == 1000
