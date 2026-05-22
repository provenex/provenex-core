"""Async verify throughput vs sync-in-threadpool.

Two configurations against the same pre-ingested Postgres backend:

    * **sync_pool**: ``concurrent.futures.ThreadPoolExecutor`` of N threads,
      each calling ``verify_chunks(sync_index, ...)``. This is what a
      pure-sync app pod looks like when serving concurrent requests
      through a threadpool. Sync psycopg releases the GIL during socket
      I/O, so multiple threads can be in flight at once.

    * **asyncio_gather**: ``asyncio.gather`` of N coroutines, each
      calling ``verify_chunks_async(async_index, ...)``. This is the
      shape a FastAPI / Starlette / aiohttp handler takes when it
      doesn't have to dispatch to a threadpool.

Both configurations issue the same total number of verify operations.
We measure wall time and ops/sec, then compare the two shapes to land
the headline "async is at least as fast as sync threadpool, and you
don't have to wrap the call site in ``asyncio.to_thread``."

Usage::

    PROVENEX_TEST_POSTGRES_DSN='postgresql://postgres@/postgres?host=/tmp&port=55432' \\
        python -m bench.async_verify --concurrency 1,10,50,100 --total 500

DSN resolution: ``--dsn``, then ``PROVENEX_TEST_POSTGRES_DSN``, then a
default of ``postgresql://postgres@/postgres?host=/tmp&port=55432`` for
ephemeral-pg CI.

Determinism: same ``--seed`` produces bit-identical fingerprints; the
latency / throughput distributions vary with hardware noise.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import random
import secrets
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Allow ``python -m bench.async_verify`` from a checkout without install.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


_DEFAULT_DSN = "postgresql://postgres@/postgres?host=/tmp&port=55432"


def _resolve_dsn(arg: Optional[str]) -> str:
    if arg:
        return arg
    env = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")
    if env:
        return env
    return _DEFAULT_DSN


def _schema_dsn(base_dsn: str, schema: str) -> str:
    sep = "&" if "?" in base_dsn else "?"
    return f"{base_dsn}{sep}options=-csearch_path%3D{schema}"


def _percentiles(samples_sec: List[float]) -> Dict[str, float]:
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


def _make_chunks(n: int, prefix: str) -> List[str]:
    return [f"{prefix}-chunk-{i:06d}" for i in range(n)]


def _fp(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _doc_version(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Ingest: pre-populate a fresh schema with N chunks                           #
# --------------------------------------------------------------------------- #


def _ingest_corpus(
    base_dsn: str, schema: str, corpus: List[str], signing_secret: bytes
) -> None:
    import psycopg

    from provenex.index.postgres_index import PostgresProvenanceIndex

    with psycopg.connect(base_dsn, autocommit=True) as setup:
        with setup.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            cur.execute(f'CREATE SCHEMA "{schema}"')

    dsn = _schema_dsn(base_dsn, schema)
    idx = PostgresProvenanceIndex(dsn=dsn, signing_secret=signing_secret)
    try:
        for i, text in enumerate(corpus):
            idx.add(
                fingerprint=_fp(text),
                document_id=f"doc-{i // 100:06d}",
                document_version=_doc_version(f"doc-{i // 100}-v1"),
                chunk_offset=0,
                chunk_length=len(text),
            )
    finally:
        idx.close()


# --------------------------------------------------------------------------- #
# Sync-threadpool harness                                                     #
# --------------------------------------------------------------------------- #


def _sync_worker(args: Tuple[str, bytes, List[str]]) -> List[float]:
    dsn, signing_secret, chunks = args
    from provenex.core.verify import verify_chunks
    from provenex.core.receipt import HmacSha256Signer
    from provenex.index.postgres_index import PostgresProvenanceIndex

    idx = PostgresProvenanceIndex(
        dsn=dsn, signing_secret=signing_secret, min_size=1, max_size=2
    )
    signer = HmacSha256Signer(secret=b"bench-async-verify-receipt-secret")
    samples: List[float] = []
    try:
        for chunk_batch in chunks:
            t = time.perf_counter()
            verify_chunks(chunks=chunk_batch, index=idx, signer=signer)
            samples.append(time.perf_counter() - t)
    finally:
        idx.close()
    return samples


def run_sync_pool(
    base_dsn: str,
    schema: str,
    chunks_per_call: int,
    total_calls: int,
    concurrency: int,
    signing_secret: bytes,
    corpus: List[str],
    seed: int,
) -> Dict:
    dsn = _schema_dsn(base_dsn, schema)
    rng = random.Random(seed)
    # Pre-build per-thread workloads: each worker gets total/concurrency calls.
    per_worker = total_calls // concurrency
    worker_args = []
    for _ in range(concurrency):
        worker_chunks = []
        for _ in range(per_worker):
            worker_chunks.append(rng.sample(corpus, chunks_per_call))
        worker_args.append((dsn, signing_secret, worker_chunks))

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(_sync_worker, worker_args))
    wall = time.perf_counter() - t0

    all_samples = [s for r in results for s in r]
    pct = _percentiles(all_samples)
    pct.update(
        concurrency=concurrency,
        total_calls=len(all_samples),
        wall_seconds=wall,
        throughput_ops_per_sec=len(all_samples) / wall if wall else 0.0,
        chunks_per_call=chunks_per_call,
    )
    return pct


# --------------------------------------------------------------------------- #
# Async-gather harness                                                        #
# --------------------------------------------------------------------------- #


async def _async_run(
    base_dsn: str,
    schema: str,
    chunks_per_call: int,
    total_calls: int,
    concurrency: int,
    signing_secret: bytes,
    corpus: List[str],
    seed: int,
) -> Dict:
    from provenex import (
        AsyncPostgresProvenanceIndex,
        HmacSha256Signer,
        verify_chunks_async,
    )

    dsn = _schema_dsn(base_dsn, schema)
    signer = HmacSha256Signer(secret=b"bench-async-verify-receipt-secret")

    # Pool sized to the concurrency so we measure async parallelism, not
    # pool contention. Cap at 50 server-side connections so the pg side
    # is not starved.
    pool_size = min(max(concurrency, 1), 50)
    async with AsyncPostgresProvenanceIndex(
        dsn=dsn,
        signing_secret=signing_secret,
        min_size=pool_size,
        max_size=pool_size,
    ) as idx:
        # Warmup so shared_buffers is hot before we measure.
        await idx.verify_batch_async([_fp(corpus[0])])

        rng = random.Random(seed)
        batches = [rng.sample(corpus, chunks_per_call) for _ in range(total_calls)]
        samples: List[float] = []

        async def one_call(batch: List[str]) -> None:
            t = time.perf_counter()
            await verify_chunks_async(chunks=batch, index=idx, signer=signer)
            samples.append(time.perf_counter() - t)

        sem = asyncio.Semaphore(concurrency)

        async def gated(batch: List[str]) -> None:
            async with sem:
                await one_call(batch)

        t0 = time.perf_counter()
        await asyncio.gather(*(gated(b) for b in batches))
        wall = time.perf_counter() - t0

    pct = _percentiles(samples)
    pct.update(
        concurrency=concurrency,
        total_calls=len(samples),
        wall_seconds=wall,
        throughput_ops_per_sec=len(samples) / wall if wall else 0.0,
        chunks_per_call=chunks_per_call,
    )
    return pct


# --------------------------------------------------------------------------- #
# Reporting                                                                   #
# --------------------------------------------------------------------------- #


def _write_report(out_dir: Path, results: Dict) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"async_verify_{ts}"
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")

    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    with open(md_path, "w") as f:
        f.write(f"# Async verify bench — {ts}\n\n")
        f.write(
            f"- Corpus size: {results['corpus_size']:,} chunks pre-ingested "
            f"into schema `{results['schema']}`\n"
            f"- chunks per verify call: {results['chunks_per_call']}\n"
            f"- total calls per row: {results['total_calls']}\n\n"
        )
        f.write("## Sync threadpool (concurrent.futures.ThreadPoolExecutor)\n\n")
        f.write("| concurrency | throughput (ops/s) | p50 (µs) | p95 (µs) | p99 (µs) | wall (s) |\n")
        f.write("|---|---|---|---|---|---|\n")
        for r in results["sync"]:
            f.write(
                f"| {r['concurrency']} | {r['throughput_ops_per_sec']:.0f} | "
                f"{r.get('p50_us', 0):.0f} | {r.get('p95_us', 0):.0f} | "
                f"{r.get('p99_us', 0):.0f} | {r['wall_seconds']:.2f} |\n"
            )
        f.write("\n## Async gather (asyncio.gather + AsyncPostgresProvenanceIndex)\n\n")
        f.write("| concurrency | throughput (ops/s) | p50 (µs) | p95 (µs) | p99 (µs) | wall (s) |\n")
        f.write("|---|---|---|---|---|---|\n")
        for r in results["async"]:
            f.write(
                f"| {r['concurrency']} | {r['throughput_ops_per_sec']:.0f} | "
                f"{r.get('p50_us', 0):.0f} | {r.get('p95_us', 0):.0f} | "
                f"{r.get('p99_us', 0):.0f} | {r['wall_seconds']:.2f} |\n"
            )
        f.write("\n## Async vs sync at matched concurrency\n\n")
        sync_by_c = {r["concurrency"]: r for r in results["sync"]}
        async_by_c = {r["concurrency"]: r for r in results["async"]}
        f.write("| concurrency | sync ops/s | async ops/s | async / sync |\n")
        f.write("|---|---|---|---|\n")
        for c in sorted(set(sync_by_c) & set(async_by_c)):
            s = sync_by_c[c]["throughput_ops_per_sec"]
            a = async_by_c[c]["throughput_ops_per_sec"]
            ratio = a / s if s else 0.0
            f.write(f"| {c} | {s:.0f} | {a:.0f} | {ratio:.2f}x |\n")
    return json_path, md_path


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> None:
    p = argparse.ArgumentParser(prog="bench.async_verify", description=__doc__)
    p.add_argument("--dsn", help="Postgres DSN. Default: ephemeral on /tmp:55432.")
    p.add_argument(
        "--schema",
        default="provenex_bench_async",
        help="Schema for the test corpus.",
    )
    p.add_argument(
        "--corpus-size",
        type=int,
        default=50_000,
        help="Number of chunks to pre-ingest.",
    )
    p.add_argument(
        "--chunks-per-call",
        type=int,
        default=10,
        help="Top-k batch size on each verify call.",
    )
    p.add_argument(
        "--total",
        type=int,
        default=500,
        help="Total verify calls per concurrency row.",
    )
    p.add_argument(
        "--concurrency",
        default="1,10,50,100",
        help="Comma-separated concurrency values for both shapes.",
    )
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--secret",
        default="bench-async-verify-index-secret",
        help="Index signing secret. Use the same value across runs.",
    )
    p.add_argument("--out-dir", type=Path, default=Path("./bench_reports"))
    p.add_argument(
        "--skip-ingest",
        action="store_true",
        help="Reuse an existing pre-ingested schema (must match --corpus-size).",
    )
    args = p.parse_args(argv)

    base_dsn = _resolve_dsn(args.dsn)
    signing_secret = args.secret.encode("utf-8")
    concurrencies = [int(s) for s in args.concurrency.split(",")]

    # Stable per-bench seed for fingerprint reproducibility.
    secrets_seed = args.seed
    random.Random(secrets_seed)
    corpus = _make_chunks(args.corpus_size, prefix=f"async-{secrets_seed}")

    if not args.skip_ingest:
        print(
            f"[ingest] {args.corpus_size:,} chunks -> schema={args.schema}",
            flush=True,
        )
        _ingest_corpus(base_dsn, args.schema, corpus, signing_secret)

    results: Dict = {
        "corpus_size": args.corpus_size,
        "chunks_per_call": args.chunks_per_call,
        "total_calls": args.total,
        "schema": args.schema,
        "sync": [],
        "async": [],
    }

    print("[sync_pool] threadpool baseline:")
    for c in concurrencies:
        out = run_sync_pool(
            base_dsn=base_dsn,
            schema=args.schema,
            chunks_per_call=args.chunks_per_call,
            total_calls=args.total,
            concurrency=c,
            signing_secret=signing_secret,
            corpus=corpus,
            seed=args.seed,
        )
        results["sync"].append(out)
        print(
            f"  c={c:>3}: {out['throughput_ops_per_sec']:.0f} ops/s, "
            f"p50 {out.get('p50_us', 0):.0f} µs, p99 {out.get('p99_us', 0):.0f} µs, "
            f"wall {out['wall_seconds']:.2f}s"
        )

    print("[asyncio_gather] async-pool path:")
    for c in concurrencies:
        out = asyncio.run(
            _async_run(
                base_dsn=base_dsn,
                schema=args.schema,
                chunks_per_call=args.chunks_per_call,
                total_calls=args.total,
                concurrency=c,
                signing_secret=signing_secret,
                corpus=corpus,
                seed=args.seed,
            )
        )
        results["async"].append(out)
        print(
            f"  c={c:>3}: {out['throughput_ops_per_sec']:.0f} ops/s, "
            f"p50 {out.get('p50_us', 0):.0f} µs, p99 {out.get('p99_us', 0):.0f} µs, "
            f"wall {out['wall_seconds']:.2f}s"
        )

    json_path, md_path = _write_report(args.out_dir, results)
    print(f"\nwrote {json_path}")
    print(f"wrote {md_path}")


if __name__ == "__main__":
    main()
