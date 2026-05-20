"""Provenex Postgres scale benchmark.

The companion to ``bench.scale`` (which exercises SQLite + Merkle), this
harness measures the multi-node-deployment-shape index — a Postgres
backend — at the scales tier-2 enterprises actually run. It answers the
four questions ``docs/scaling.md`` flagged as "not yet published":

    1. Verify p50/p95/p99 at 1M and 10M chunks, warm cache.
    2. Cold-cache verify (clear shared_buffers between runs).
    3. Concurrent reader+writer p99 (verify under load while ingest runs).
    4. Connection-budget sensitivity (1 vs N concurrent verifiers).

Run the slices independently::

    # ~ 8-15 minutes for 1M ingest on a laptop
    python -m bench.postgres_scale ingest --scale 1m

    # Each verify slice is ~10-30 seconds
    python -m bench.postgres_scale verify-warm --scale 1m
    python -m bench.postgres_scale verify-cold --scale 1m
    python -m bench.postgres_scale concurrent --scale 1m --duration 30

The ``all`` subcommand runs them sequentially; expect ~15-20 minutes for
the 1m run end-to-end on commodity hardware.

DSN resolution: ``--dsn``, then ``PROVENEX_TEST_POSTGRES_DSN``, then a
default of ``postgresql://postgres@/postgres?host=/tmp&port=55432`` to
match the ephemeral-pg pattern used in CI.

Determinism: same ``--seed`` produces bit-identical fingerprints; latency
distributions will vary with hardware noise, but shapes hold.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import secrets
import statistics
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# Allow ``python -m bench.postgres_scale`` from a checkout without install.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from provenex.core.fingerprinter import Fingerprinter, FingerprinterConfig  # noqa: E402
from provenex.index.base import VerificationOutcome  # noqa: E402

# Scale tier presets - same shape as bench.scale for parity.
_PRESETS: Dict[str, Tuple[int, int, int]] = {
    "100k": (100_000, 100, 800),
    "1m": (1_000_000, 100, 800),
    "10m": (10_000_000, 100, 800),
}

_DEFAULT_DSN = "postgresql://postgres@/postgres?host=/tmp&port=55432"


def _resolve_dsn(arg: Optional[str]) -> str:
    if arg:
        return arg
    env = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")
    if env:
        return env
    return _DEFAULT_DSN


def _schema_dsn(base_dsn: str, schema: str) -> str:
    """Attach ``search_path=<schema>`` to a base DSN."""
    sep = "&" if "?" in base_dsn else "?"
    return f"{base_dsn}{sep}options=-csearch_path%3D{schema}"


# --------------------------------------------------------------------------- #
# Latency stats                                                               #
# --------------------------------------------------------------------------- #


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
        "p999_us": q(0.999) * 1e6,
        "max_us": s[-1] * 1e6,
        "mean_us": statistics.fmean(s) * 1e6,
    }


# --------------------------------------------------------------------------- #
# Corpus / fingerprint generation                                             #
# --------------------------------------------------------------------------- #


def _generate_chunks(
    target_chunks: int,
    mean_chunks_per_doc: int,
    mean_chunk_chars: int,
    seed: int,
) -> Iterator[Tuple[str, str, int, int]]:
    """Yield ``(document_id, chunk_text, chunk_offset, chunk_length)`` tuples.

    Streams; never holds more than one document's chunks in memory.
    Matches ``bench.corpus.SyntheticCorpus`` semantics but inlined to
    keep this harness self-contained.
    """
    import string

    alphabet = string.ascii_letters + string.digits + " "
    rng = random.Random(seed)
    remaining = target_chunks
    doc_idx = 0
    while remaining > 0:
        # Log-normal chunks per document.
        import math

        n_chunks = max(
            1,
            int(
                round(
                    rng.lognormvariate(
                        math.log(max(1, mean_chunks_per_doc)), 0.3
                    )
                )
            ),
        )
        n_chunks = min(n_chunks, remaining)
        doc_id = f"doc_{doc_idx:08d}"
        offset = 0
        for _ in range(n_chunks):
            size = max(
                64,
                int(
                    rng.lognormvariate(
                        math.log(max(1, mean_chunk_chars)), 0.4
                    )
                ),
            )
            text = "".join(rng.choices(alphabet, k=size))
            yield (doc_id, text, offset, size)
            offset += size
        remaining -= n_chunks
        doc_idx += 1


# --------------------------------------------------------------------------- #
# Schema management                                                           #
# --------------------------------------------------------------------------- #


def _bench_schema_name() -> str:
    return "provenex_bench"


def _create_schema(base_dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(base_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            cur.execute(f'CREATE SCHEMA "{schema}"')


def _drop_schema(base_dsn: str, schema: str) -> None:
    import psycopg

    with psycopg.connect(base_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


def _row_count(dsn: str) -> int:
    import psycopg

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM provenex_fingerprints")
            (n,) = cur.fetchone()
    return int(n)


# --------------------------------------------------------------------------- #
# Slice: ingest                                                               #
# --------------------------------------------------------------------------- #


def run_ingest(
    base_dsn: str,
    schema: str,
    target_chunks: int,
    mean_chunks_per_doc: int,
    mean_chunk_chars: int,
    seed: int,
    signing_secret: bytes,
    reset_schema: bool = True,
) -> Dict:
    """Stream the synthetic corpus into a fresh schema; report throughput."""
    from provenex.index.postgres_index import PostgresProvenanceIndex

    if reset_schema:
        _create_schema(base_dsn, schema)

    dsn = _schema_dsn(base_dsn, schema)
    idx = PostgresProvenanceIndex(dsn=dsn, signing_secret=signing_secret)
    fp = Fingerprinter(FingerprinterConfig())

    t0 = time.perf_counter()
    n = 0
    last_log = t0
    last_log_n = 0
    try:
        for doc_id, text, offset, length in _generate_chunks(
            target_chunks=target_chunks,
            mean_chunks_per_doc=mean_chunks_per_doc,
            mean_chunk_chars=mean_chunk_chars,
            seed=seed,
        ):
            fingerprint = fp.fingerprint_chunk(text)
            # Use a stable document_version per doc_id; ingest is a
            # write-once corpus, so versions don't matter beyond
            # the structural sanity check.
            doc_version = (
                "sha256:"
                + ("0" * 56)
                + format(int(doc_id.rsplit("_", 1)[1]) % (16**8), "08x")
            )
            idx.add(
                fingerprint=fingerprint,
                document_id=doc_id,
                document_version=doc_version,
                chunk_offset=offset,
                chunk_length=length,
            )
            n += 1
            now = time.perf_counter()
            if now - last_log >= 30.0:
                rate = (n - last_log_n) / (now - last_log)
                pct = 100.0 * n / target_chunks
                print(
                    f"  ingested {n}/{target_chunks} ({pct:5.1f}%); "
                    f"recent rate {rate:6.0f} chunks/s",
                    flush=True,
                )
                last_log = now
                last_log_n = n
    finally:
        idx.close()

    elapsed = time.perf_counter() - t0
    return {
        "target_chunks": target_chunks,
        "ingested_chunks": n,
        "elapsed_seconds": elapsed,
        "throughput_chunks_per_sec": n / elapsed if elapsed > 0 else 0.0,
    }


# --------------------------------------------------------------------------- #
# Slice: warm-cache verify                                                    #
# --------------------------------------------------------------------------- #


def _sample_fingerprints(
    base_dsn: str, schema: str, n: int, seed: int
) -> List[str]:
    """Pull ``n`` random known fingerprints from the index for the verify pool."""
    import psycopg

    dsn = _schema_dsn(base_dsn, schema)
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM provenex_fingerprints")
            (total,) = cur.fetchone()
            sample_n = min(n, int(total))
            # ``ORDER BY random()`` over millions of rows is expensive;
            # use TABLESAMPLE for fast approximate sampling, then trim
            # to exactly ``sample_n`` rows in Python.
            cur.execute(
                "SELECT fingerprint FROM provenex_fingerprints "
                "TABLESAMPLE SYSTEM (5) LIMIT %s",
                (sample_n * 4,),  # over-sample then trim
            )
            rows = [r[0] for r in cur.fetchall()]
    rng = random.Random(seed)
    rng.shuffle(rows)
    return rows[:sample_n]


def run_verify_warm(
    base_dsn: str,
    schema: str,
    iters: int,
    k: int,
    unknown_rate: float,
    seed: int,
    signing_secret: bytes,
) -> Dict:
    """Measure verify_batch latency on a warm cache.

    Pulls ``iters * k`` candidate fingerprints from the index, mixes in
    ``unknown_rate * 100`` percent unindexed fingerprints, and times
    ``iters`` calls to ``verify_batch`` (each with ``k`` fingerprints).
    """
    from provenex.index.postgres_index import PostgresProvenanceIndex

    dsn = _schema_dsn(base_dsn, schema)
    known = _sample_fingerprints(base_dsn, schema, n=iters * k, seed=seed)
    rng = random.Random(seed)
    # The PostgresProvenanceIndex pool warms its first connection on
    # construction; we add an extra warmup verify_batch call below.
    idx = PostgresProvenanceIndex(dsn=dsn, signing_secret=signing_secret)
    try:
        # Warmup: a single batch verify to prime shared_buffers / pool.
        idx.verify_batch(known[:k])
        samples_sec: List[float] = []
        # Track per-outcome counts as a sanity check.
        outcomes: Dict[str, int] = {o.value: 0 for o in VerificationOutcome}
        for i in range(iters):
            batch = list(known[(i * k) % len(known) : (i * k) % len(known) + k])
            while len(batch) < k:
                batch.append(known[rng.randrange(len(known))])
            # Mix in unknowns at the configured rate.
            for j in range(k):
                if rng.random() < unknown_rate:
                    batch[j] = "sha256:" + secrets.token_hex(32)
            t0 = time.perf_counter()
            results = idx.verify_batch(batch)
            samples_sec.append(time.perf_counter() - t0)
            for outcome, _ in results:
                outcomes[outcome.value] += 1
    finally:
        idx.close()

    pct = _percentiles(samples_sec)
    pct["k"] = k
    pct["iters"] = iters
    pct["outcomes"] = outcomes
    # Per-fingerprint percentile too (divide by k).
    pct["per_fingerprint_p50_us"] = pct.get("p50_us", 0) / k
    pct["per_fingerprint_p99_us"] = pct.get("p99_us", 0) / k
    return pct


# --------------------------------------------------------------------------- #
# Slice: cold-cache verify                                                    #
# --------------------------------------------------------------------------- #


def _drop_buffer_cache(base_dsn: str, pg_data_dir: Optional[str]) -> bool:
    """Best-effort: restart Postgres to drop shared_buffers.

    Returns True if a full restart succeeded (shared_buffers actually
    dropped); False if we could only do CHECKPOINT (numbers are then
    approximately-warm, not true-cold; the report flags this).

    Note: restart drops Postgres's shared_buffers but not the OS page
    cache. True cold-cache on macOS requires ``sudo purge``; on Linux,
    ``echo 3 > /proc/sys/vm/drop_caches``. The harness doesn't attempt
    those (they need root); the Docker Compose rig under
    ``bench/postgres/`` documents how to do it inside the container.
    """
    if pg_data_dir and os.path.isdir(pg_data_dir):
        try:
            # ``-m fast`` lets in-flight transactions finish, but a 1M
            # index has lots of dirty buffers to flush; allow up to
            # 5 minutes for the shutdown checkpoint.
            subprocess.run(
                ["pg_ctl", "-D", pg_data_dir, "-m", "fast", "-w", "restart"],
                check=True,
                capture_output=True,
                timeout=900,
            )
            time.sleep(2)
            return True
        except Exception as exc:
            print(f"  pg_ctl restart failed ({exc}); falling back to CHECKPOINT")
    import psycopg

    with psycopg.connect(base_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("CHECKPOINT")
    return False


def run_verify_cold(
    base_dsn: str,
    schema: str,
    iters: int,
    k: int,
    seed: int,
    signing_secret: bytes,
    pg_data_dir: Optional[str],
) -> Dict:
    """Measure verify_batch latency after dropping shared_buffers.

    Drops the buffer cache (Postgres restart when ``pg_data_dir`` is
    provided), then runs ``iters`` ``verify_batch`` calls *without* a
    warmup. The first few samples should show the cold-page-fault tail.
    """
    # Sample fingerprints BEFORE the restart so we don't have to
    # repopulate the cache to even build the sample pool.
    known = _sample_fingerprints(base_dsn, schema, n=iters * k, seed=seed)
    full_restart = _drop_buffer_cache(base_dsn, pg_data_dir)

    from provenex.index.postgres_index import PostgresProvenanceIndex

    dsn = _schema_dsn(base_dsn, schema)
    idx = PostgresProvenanceIndex(dsn=dsn, signing_secret=signing_secret)
    try:
        samples_sec: List[float] = []
        first_batch_sec: Optional[float] = None
        for i in range(iters):
            batch = list(known[(i * k) % len(known) : (i * k) % len(known) + k])
            while len(batch) < k:
                batch.append(known[(i * k + 1) % len(known)])
            t0 = time.perf_counter()
            idx.verify_batch(batch)
            d = time.perf_counter() - t0
            if first_batch_sec is None:
                first_batch_sec = d
            samples_sec.append(d)
    finally:
        idx.close()

    pct = _percentiles(samples_sec)
    pct["k"] = k
    pct["iters"] = iters
    pct["first_batch_us"] = (first_batch_sec or 0.0) * 1e6
    pct["per_fingerprint_p50_us"] = pct.get("p50_us", 0) / k
    pct["per_fingerprint_p99_us"] = pct.get("p99_us", 0) / k
    pct["full_restart_succeeded"] = full_restart
    return pct


# --------------------------------------------------------------------------- #
# Slice: concurrent reader + writer                                           #
# --------------------------------------------------------------------------- #


@dataclass
class _ReaderResult:
    samples: List[float] = field(default_factory=list)
    errors: int = 0


def run_concurrent(
    base_dsn: str,
    schema: str,
    duration_sec: float,
    reader_threads: int,
    writer_rate: float,
    k: int,
    seed: int,
    signing_secret: bytes,
) -> Dict:
    """Reader threads issue verify_batch while a writer thread ingests.

    Each reader gets its own ``PostgresProvenanceIndex`` (independent
    connection pool). The writer ingests at ``writer_rate`` chunks/sec.
    Run for ``duration_sec`` seconds, then report reader p50/p95/p99.
    """
    from provenex.index.postgres_index import PostgresProvenanceIndex

    dsn = _schema_dsn(base_dsn, schema)
    known = _sample_fingerprints(
        base_dsn, schema, n=max(10_000, reader_threads * k * 10), seed=seed
    )
    stop_event = threading.Event()

    # --- reader workers ---
    def reader_loop(worker_id: int) -> _ReaderResult:
        local_rng = random.Random(seed + worker_id)
        idx = PostgresProvenanceIndex(
            dsn=dsn, signing_secret=signing_secret, min_size=1, max_size=2
        )
        res = _ReaderResult()
        try:
            while not stop_event.is_set():
                batch = [
                    known[local_rng.randrange(len(known))] for _ in range(k)
                ]
                t0 = time.perf_counter()
                try:
                    idx.verify_batch(batch)
                    res.samples.append(time.perf_counter() - t0)
                except Exception:
                    res.errors += 1
        finally:
            idx.close()
        return res

    # --- writer worker ---
    def writer_loop() -> int:
        writer_idx = PostgresProvenanceIndex(
            dsn=dsn, signing_secret=signing_secret, min_size=1, max_size=2
        )
        fp = Fingerprinter(FingerprinterConfig())
        # Each iteration mints fresh fingerprints under a unique doc_id
        # so we don't fight on the same supersession lock as the
        # original corpus.
        doc_counter = 0
        period = 1.0 / max(writer_rate, 0.001)
        next_t = time.perf_counter()
        n_writes = 0
        try:
            while not stop_event.is_set():
                now = time.perf_counter()
                if now < next_t:
                    time.sleep(min(0.01, next_t - now))
                    continue
                doc_id = f"concurrent_doc_{doc_counter:08d}"
                doc_counter += 1
                doc_version = (
                    "sha256:" + ("0" * 56) + format(doc_counter & 0xFFFFFFFF, "08x")
                )
                text = secrets.token_hex(64)
                writer_idx.add(
                    fingerprint=fp.fingerprint_chunk(text),
                    document_id=doc_id,
                    document_version=doc_version,
                    chunk_offset=0,
                    chunk_length=len(text),
                )
                n_writes += 1
                next_t += period
        finally:
            writer_idx.close()
        return n_writes

    # --- run ---
    with ThreadPoolExecutor(max_workers=reader_threads + 1) as pool:
        reader_futures = [pool.submit(reader_loop, i) for i in range(reader_threads)]
        writer_future = pool.submit(writer_loop)
        time.sleep(duration_sec)
        stop_event.set()
        reader_results = [f.result() for f in reader_futures]
        writes = writer_future.result()

    all_samples: List[float] = []
    total_errors = 0
    for r in reader_results:
        all_samples.extend(r.samples)
        total_errors += r.errors

    pct = _percentiles(all_samples)
    pct["k"] = k
    pct["reader_threads"] = reader_threads
    pct["writer_rate"] = writer_rate
    pct["writes_completed"] = writes
    pct["reader_errors"] = total_errors
    pct["duration_seconds"] = duration_sec
    return pct


# --------------------------------------------------------------------------- #
# Slice: connection-budget sensitivity                                        #
# --------------------------------------------------------------------------- #


def run_connection_budget(
    base_dsn: str,
    schema: str,
    duration_sec: float,
    thread_counts: List[int],
    k: int,
    seed: int,
    signing_secret: bytes,
) -> List[Dict]:
    """Measure verify throughput as concurrent reader count grows.

    The point: connection cost dominates before query latency. This
    slice doesn't include PgBouncer (that lives in the Docker Compose
    rig); it just shows the raw curve.
    """
    out: List[Dict] = []
    for n_threads in thread_counts:
        result = run_concurrent(
            base_dsn=base_dsn,
            schema=schema,
            duration_sec=duration_sec,
            reader_threads=n_threads,
            writer_rate=0.0001,  # effectively idle writer
            k=k,
            seed=seed,
            signing_secret=signing_secret,
        )
        total_ops = result.get("count", 0)
        result["throughput_ops_per_sec"] = total_ops / duration_sec
        result["concurrent_readers"] = n_threads
        out.append(result)
    return out


# --------------------------------------------------------------------------- #
# Reporting                                                                   #
# --------------------------------------------------------------------------- #


def _write_report(out_dir: Path, scale: str, results: Dict) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    base = out_dir / f"postgres_scale_{scale}_{ts}"
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")

    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    with open(md_path, "w") as f:
        f.write(f"# Postgres scale bench — {scale}\n\n")
        f.write(f"Generated: {ts}\n\n")
        if "ingest" in results:
            i = results["ingest"]
            f.write("## Ingest\n\n")
            f.write(f"- Target chunks: {i['target_chunks']:,}\n")
            f.write(f"- Ingested: {i['ingested_chunks']:,}\n")
            f.write(f"- Wall time: {i['elapsed_seconds']:.1f} s\n")
            f.write(
                f"- Throughput: **{i['throughput_chunks_per_sec']:.0f} chunks/s**\n\n"
            )
        for slice_name in ("verify_warm", "verify_cold"):
            if slice_name in results:
                r = results[slice_name]
                title = (
                    "Verify, warm cache" if slice_name == "verify_warm"
                    else "Verify, cold cache (after pg_ctl restart)"
                )
                f.write(f"## {title}\n\n")
                f.write(
                    f"- k per batch: {r['k']}; iters: {r['iters']}\n"
                    f"- Per-batch p50/p95/p99: "
                    f"**{r.get('p50_us', 0):.0f} µs** / "
                    f"{r.get('p95_us', 0):.0f} µs / "
                    f"{r.get('p99_us', 0):.0f} µs\n"
                    f"- Per-fingerprint p50/p99: "
                    f"{r.get('per_fingerprint_p50_us', 0):.0f} µs / "
                    f"{r.get('per_fingerprint_p99_us', 0):.0f} µs\n"
                )
                if "first_batch_us" in r:
                    f.write(f"- First cold batch: {r['first_batch_us']:.0f} µs\n")
                f.write("\n")
        if "concurrent" in results:
            r = results["concurrent"]
            f.write("## Concurrent reader+writer\n\n")
            f.write(
                f"- Readers: {r['reader_threads']}; writer rate: "
                f"{r['writer_rate']} ops/s\n"
                f"- Duration: {r['duration_seconds']:.0f} s\n"
                f"- Reader verify_batch p50/p95/p99: "
                f"**{r.get('p50_us', 0):.0f} µs** / "
                f"{r.get('p95_us', 0):.0f} µs / "
                f"{r.get('p99_us', 0):.0f} µs\n"
                f"- Reads: {r.get('count', 0)}; writes: {r.get('writes_completed', 0)};"
                f" reader errors: {r.get('reader_errors', 0)}\n\n"
            )
        if "connection_budget" in results:
            f.write("## Connection-budget sensitivity\n\n")
            f.write("| Readers | Throughput (ops/s) | p50 (µs) | p99 (µs) |\n")
            f.write("|---|---|---|---|\n")
            for r in results["connection_budget"]:
                f.write(
                    f"| {r['concurrent_readers']} | "
                    f"{r['throughput_ops_per_sec']:.0f} | "
                    f"{r.get('p50_us', 0):.0f} | "
                    f"{r.get('p99_us', 0):.0f} |\n"
                )
            f.write("\n")
    return json_path, md_path


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #


def main(argv: Optional[List[str]] = None) -> None:
    p = argparse.ArgumentParser(prog="bench.postgres_scale", description=__doc__)
    p.add_argument(
        "slice",
        choices=(
            "ingest",
            "verify-warm",
            "verify-cold",
            "concurrent",
            "connection-budget",
            "all",
        ),
        help="Which slice to run.",
    )
    p.add_argument("--dsn", help="Postgres DSN. Default: ephemeral on /tmp:55432.")
    p.add_argument("--schema", default=_bench_schema_name())
    p.add_argument("--scale", choices=sorted(_PRESETS.keys()), default="100k")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--verify-samples", type=int, default=2000)
    p.add_argument("--k", type=int, default=10)
    p.add_argument("--unknown-rate", type=float, default=0.1)
    p.add_argument("--reader-threads", type=int, default=8)
    p.add_argument("--writer-rate", type=float, default=50.0)
    p.add_argument("--duration", type=float, default=30.0)
    p.add_argument(
        "--connection-budget-threads",
        default="1,4,16,64",
        help="Comma-separated thread counts for the connection-budget slice.",
    )
    p.add_argument(
        "--pg-data-dir",
        help="Postgres data dir (for pg_ctl restart in the cold-cache slice).",
    )
    p.add_argument(
        "--secret",
        default="bench-postgres-scale-secret",
        help="Index signing secret. Use the same value across ingest/verify slices.",
    )
    p.add_argument("--out-dir", type=Path, default=Path("./bench_reports"))
    args = p.parse_args(argv)

    target, mean_per_doc, mean_chars = _PRESETS[args.scale]
    base_dsn = _resolve_dsn(args.dsn)
    signing_secret = args.secret.encode("utf-8")

    results: Dict = {"scale": args.scale, "dsn_sanitised": _redact_dsn(base_dsn)}

    if args.slice in ("ingest", "all"):
        print(f"[ingest] target={target:,} chunks; schema={args.schema}")
        t0 = time.perf_counter()
        results["ingest"] = run_ingest(
            base_dsn=base_dsn,
            schema=args.schema,
            target_chunks=target,
            mean_chunks_per_doc=mean_per_doc,
            mean_chunk_chars=mean_chars,
            seed=args.seed,
            signing_secret=signing_secret,
        )
        print(
            f"  done in {time.perf_counter() - t0:.1f} s "
            f"({results['ingest']['throughput_chunks_per_sec']:.0f} chunks/s)"
        )

    if args.slice in ("verify-warm", "all"):
        print(
            f"[verify-warm] iters={args.verify_samples}; k={args.k}; "
            f"unknown_rate={args.unknown_rate}"
        )
        results["verify_warm"] = run_verify_warm(
            base_dsn=base_dsn,
            schema=args.schema,
            iters=args.verify_samples,
            k=args.k,
            unknown_rate=args.unknown_rate,
            seed=args.seed,
            signing_secret=signing_secret,
        )
        print(
            f"  per-batch p50/p99: "
            f"{results['verify_warm'].get('p50_us', 0):.0f} µs / "
            f"{results['verify_warm'].get('p99_us', 0):.0f} µs"
        )

    if args.slice in ("verify-cold", "all"):
        print(f"[verify-cold] iters={args.verify_samples}; k={args.k}")
        results["verify_cold"] = run_verify_cold(
            base_dsn=base_dsn,
            schema=args.schema,
            iters=args.verify_samples,
            k=args.k,
            seed=args.seed,
            signing_secret=signing_secret,
            pg_data_dir=args.pg_data_dir,
        )
        print(
            f"  per-batch p50/p99: "
            f"{results['verify_cold'].get('p50_us', 0):.0f} µs / "
            f"{results['verify_cold'].get('p99_us', 0):.0f} µs; "
            f"first-batch: {results['verify_cold'].get('first_batch_us', 0):.0f} µs"
        )

    if args.slice in ("concurrent", "all"):
        print(
            f"[concurrent] readers={args.reader_threads}; "
            f"writer_rate={args.writer_rate}; duration={args.duration}"
        )
        results["concurrent"] = run_concurrent(
            base_dsn=base_dsn,
            schema=args.schema,
            duration_sec=args.duration,
            reader_threads=args.reader_threads,
            writer_rate=args.writer_rate,
            k=args.k,
            seed=args.seed,
            signing_secret=signing_secret,
        )
        print(
            f"  reader p50/p99: "
            f"{results['concurrent'].get('p50_us', 0):.0f} µs / "
            f"{results['concurrent'].get('p99_us', 0):.0f} µs; "
            f"writes={results['concurrent'].get('writes_completed', 0)}"
        )

    if args.slice in ("connection-budget", "all"):
        thread_counts = [int(s) for s in args.connection_budget_threads.split(",")]
        print(f"[connection-budget] threads={thread_counts}")
        results["connection_budget"] = run_connection_budget(
            base_dsn=base_dsn,
            schema=args.schema,
            duration_sec=args.duration,
            thread_counts=thread_counts,
            k=args.k,
            seed=args.seed,
            signing_secret=signing_secret,
        )
        for r in results["connection_budget"]:
            print(
                f"  readers={r['concurrent_readers']:>3}: "
                f"{r['throughput_ops_per_sec']:>6.0f} ops/s, "
                f"p50 {r.get('p50_us', 0):.0f} µs, "
                f"p99 {r.get('p99_us', 0):.0f} µs"
            )

    json_path, md_path = _write_report(args.out_dir, args.scale, results)
    print(f"\nwrote {json_path}")
    print(f"wrote {md_path}")


def _redact_dsn(dsn: str) -> str:
    """Strip any embedded password from a DSN before recording it."""
    import re

    return re.sub(r"://([^:]+):[^@]+@", r"://\1@", dsn)


if __name__ == "__main__":
    main()
