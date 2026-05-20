"""Phase 1.1 benchmark — single-fingerprint vs batched verify on the index.

Measures the per-call latency of the **serial** path (loop calling
``verify`` + ``lookup`` per fingerprint, mirroring what
``verify_chunks`` did pre-1.1) against the **batched** path
(:meth:`ProvenanceIndex.verify_batch` with the whole list).

Runs against the SQLite backend always, and against Postgres when
``PROVENEX_TEST_POSTGRES_DSN`` is set. Reports throughput and the
batch-vs-serial speedup at typical retrieval k values (1, 5, 10, 25).

Usage::

    python -m bench.batch_verify
    python -m bench.batch_verify --backend sqlite --corpus 10000 --k 1,5,10,25
    PROVENEX_TEST_POSTGRES_DSN=postgresql://... python -m bench.batch_verify

The harness is stdlib-only (plus psycopg when Postgres is selected). It
seeds the index once, then alternates serial/batched calls at each ``k``
with a small warmup. Latency samples are collected into a
``LatencyHistogram`` for percentile reporting.
"""

from __future__ import annotations

import argparse
import os
import random
import secrets
import statistics
import string
import sys
import time
import uuid
from typing import List, Tuple

# Make the project importable when invoked from a checkout without install.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from provenex.index.base import ProvenanceIndex, VerificationOutcome  # noqa: E402
from provenex.index.sqlite_index import SQLiteProvenanceIndex  # noqa: E402

SECRET = b"bench-batch-verify-secret"


def _build_sqlite_index(corpus_size: int) -> Tuple[SQLiteProvenanceIndex, List[str]]:
    """Seed an in-memory SQLite index with ``corpus_size`` known fingerprints."""
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    fingerprints: List[str] = []
    doc_version = "sha256:" + "0" * 64
    for i in range(corpus_size):
        fp = "sha256:" + secrets.token_hex(32)
        idx.add(
            fingerprint=fp,
            document_id=f"doc_{i // 100}",
            document_version=doc_version,
            chunk_offset=(i % 100) * 256,
            chunk_length=256,
        )
        fingerprints.append(fp)
    return idx, fingerprints


def _build_postgres_index(
    dsn: str, corpus_size: int
) -> Tuple[ProvenanceIndex, List[str], str]:
    """Seed a per-run schema on the target Postgres with ``corpus_size`` rows."""
    import psycopg

    from provenex.index.postgres_index import PostgresProvenanceIndex

    schema = f"provenex_bench_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(dsn, autocommit=True) as setup:
        with setup.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in dsn else "?"
    test_dsn = f"{dsn}{sep}options=-csearch_path%3D{schema}"
    idx = PostgresProvenanceIndex(dsn=test_dsn, signing_secret=SECRET)
    fingerprints: List[str] = []
    doc_version = "sha256:" + "0" * 64
    for i in range(corpus_size):
        fp = "sha256:" + secrets.token_hex(32)
        idx.add(
            fingerprint=fp,
            document_id=f"doc_{i // 100}",
            document_version=doc_version,
            chunk_offset=(i % 100) * 256,
            chunk_length=256,
        )
        fingerprints.append(fp)
    return idx, fingerprints, schema


def _drop_postgres_schema(dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as teardown:
        with teardown.cursor() as cur:
            cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


def _serial_pass(
    idx: ProvenanceIndex, fingerprints: List[str]
) -> List[Tuple[VerificationOutcome, object]]:
    """Pre-1.1 verify_chunks path: verify + lookup per fingerprint."""
    return [(idx.verify(fp), idx.lookup(fp)) for fp in fingerprints]


def _percentiles(samples_sec: List[float]) -> dict:
    if not samples_sec:
        return {}
    s = sorted(samples_sec)
    n = len(s)

    def q(p: float) -> float:
        if n == 1:
            return s[0]
        return s[min(n - 1, int(p * (n - 1)))]

    return {
        "count": n,
        "p50_us": q(0.50) * 1e6,
        "p95_us": q(0.95) * 1e6,
        "p99_us": q(0.99) * 1e6,
        "max_us": s[-1] * 1e6,
        "mean_us": statistics.fmean(s) * 1e6,
    }


def _run_one(
    idx: ProvenanceIndex,
    fingerprints: List[str],
    k: int,
    iters: int,
    rng: random.Random,
) -> dict:
    """Time ``iters`` retrievals of ``k`` random fingerprints under both paths."""
    # Warmup
    sample = rng.sample(fingerprints, k=min(k, len(fingerprints)))
    _serial_pass(idx, sample)
    idx.verify_batch(sample)

    serial_samples: List[float] = []
    batch_samples: List[float] = []
    for _ in range(iters):
        sample = rng.sample(fingerprints, k=min(k, len(fingerprints)))
        t0 = time.perf_counter()
        _serial_pass(idx, sample)
        serial_samples.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        idx.verify_batch(sample)
        batch_samples.append(time.perf_counter() - t0)

    serial = _percentiles(serial_samples)
    batch = _percentiles(batch_samples)
    speedup = serial["p50_us"] / batch["p50_us"] if batch.get("p50_us") else 0.0
    return {
        "k": k,
        "iters": iters,
        "serial_p50_us": serial["p50_us"],
        "serial_p99_us": serial["p99_us"],
        "batch_p50_us": batch["p50_us"],
        "batch_p99_us": batch["p99_us"],
        "speedup_at_p50": speedup,
    }


def _print_report(backend: str, corpus_size: int, results: List[dict]) -> None:
    print(f"Backend: {backend}   Corpus size: {corpus_size}")
    print(
        f"{'k':>3}   {'serial p50':>10}   {'serial p99':>10}   "
        f"{'batch p50':>10}   {'batch p99':>10}   {'speedup':>8}"
    )
    print("-" * 70)
    for r in results:
        print(
            f"{r['k']:>3}   "
            f"{r['serial_p50_us']:>9.1f}us   "
            f"{r['serial_p99_us']:>9.1f}us   "
            f"{r['batch_p50_us']:>9.1f}us   "
            f"{r['batch_p99_us']:>9.1f}us   "
            f"{r['speedup_at_p50']:>7.2f}x"
        )
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--backend",
        choices=("sqlite", "postgres", "both"),
        default="both",
        help="Which backend to measure (default: both, postgres skipped without DSN).",
    )
    ap.add_argument(
        "--corpus", type=int, default=10000, help="Number of seeded fingerprints."
    )
    ap.add_argument(
        "--k",
        default="1,5,10,25",
        help="Comma-separated retrieval sizes to measure.",
    )
    ap.add_argument(
        "--iters", type=int, default=1000, help="Samples per (backend, k)."
    )
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    ks = [int(s) for s in args.k.split(",") if s.strip()]

    # ----- SQLite -----
    if args.backend in ("sqlite", "both"):
        idx, fps = _build_sqlite_index(args.corpus)
        try:
            results = [_run_one(idx, fps, k, args.iters, rng) for k in ks]
        finally:
            idx.close()
        _print_report("SQLite (in-memory)", args.corpus, results)

    # ----- Postgres -----
    if args.backend in ("postgres", "both"):
        dsn = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")
        if not dsn:
            print("Postgres: skipped (PROVENEX_TEST_POSTGRES_DSN not set).")
            return
        idx, fps, schema = _build_postgres_index(dsn, args.corpus)
        try:
            results = [_run_one(idx, fps, k, args.iters, rng) for k in ks]
        finally:
            idx.close()
            _drop_postgres_schema(dsn, schema)
        _print_report("Postgres", args.corpus, results)


if __name__ == "__main__":
    main()
