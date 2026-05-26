"""In-process SQLite reproducer for the README headline numbers.

Run via ``provenex bench`` (preferred) or
``python -m provenex.bench.scale``. Produces a JSON report (and a
short summary to stderr) covering ingest throughput + per-call
verify latency for a synthetic corpus of the requested size.

The output JSON has stable keys so customers can compare their run
to ours, and so a CI job can baseline against a prior run.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import resource
import secrets
import statistics
import string
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# These are public from the package surface; the bench module deliberately
# uses the same imports a caller would.
from .. import (
    Ed25519Signer,
    Fingerprinter,
    FingerprinterConfig,
    HmacSha256Signer,
    Policy,
    SQLiteProvenanceIndex,
    __version__,
    verify_chunks,
)


def _max_rss_bytes() -> int:
    """Peak resident set size of this process, in bytes.

    ``ru_maxrss`` is in kilobytes on Linux and bytes on macOS; normalize
    to bytes so the JSON report is platform-portable.
    """
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if platform.system() == "Linux":
        return rss * 1024
    return int(rss)


# Headline scales reproducing the README's published p50/p95/p99/p999
# numbers (Pattern A — in-process SQLite). 1k is the smoke-test tier:
# small enough to finish in a couple of seconds, large enough to give
# meaningful percentiles for an end-to-end sanity check.
PRESETS: Dict[str, int] = {
    "1k": 1_000,
    "10k": 10_000,
    "100k": 100_000,
    "1m": 1_000_000,
}


def _percentiles(samples: List[float]) -> Dict[str, float]:
    """Return p50/p95/p99/p999 + min/max/mean over a list of durations."""
    if not samples:
        return {}
    s = sorted(samples)
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


def _format_seconds(seconds: float) -> str:
    if seconds < 1e-6:
        return f"{seconds * 1e9:.1f} ns"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f} µs"
    if seconds < 1.0:
        return f"{seconds * 1e3:.2f} ms"
    return f"{seconds:.2f} s"


def _generate_chunk(rng: random.Random, length: int) -> str:
    """Generate one synthetic chunk of approximately ``length`` characters.

    The corpus is deterministic in ``seed``: a given seed reproduces
    the same chunks, the same fingerprints, and (modulo hardware
    noise) the same latency distribution.
    """
    alphabet = string.ascii_letters + " "
    return "".join(rng.choices(alphabet, k=length))


@dataclass
class BenchResult:
    """Single bench run summary suitable for JSON serialization."""

    provenex_version: str
    scale: str
    target_chunks: int
    seed: int
    chunk_chars: int
    platform: Dict[str, str]
    ingest: Dict[str, Any]
    verify: Dict[str, Any]
    db_size_bytes: int
    elapsed_total_seconds: float
    # v1.0.0 additions:
    # - ``receipt_generation`` measures the full end-to-end producer path
    #   (fingerprint + index lookup + canonicalisation + signature). Only
    #   present when ``--receipt-samples`` > 0.
    # - ``verifier_verification`` measures the offline auditor path using
    #   the standalone ``provenex-verifier`` library (signature only, no
    #   index). Only present when ``provenex_verifier`` is installed.
    # - ``memory.peak_rss_bytes`` is the process peak RSS after ingest.
    receipt_generation: Optional[Dict[str, Any]] = None
    verifier_verification: Optional[Dict[str, Any]] = None
    memory: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "provenex_version": self.provenex_version,
            "scale": self.scale,
            "target_chunks": self.target_chunks,
            "seed": self.seed,
            "chunk_chars": self.chunk_chars,
            "platform": self.platform,
            "ingest": self.ingest,
            "verify": self.verify,
            "db_size_bytes": self.db_size_bytes,
            "elapsed_total_seconds": self.elapsed_total_seconds,
        }
        if self.receipt_generation is not None:
            d["receipt_generation"] = self.receipt_generation
        if self.verifier_verification is not None:
            d["verifier_verification"] = self.verifier_verification
        if self.memory is not None:
            d["memory"] = self.memory
        return d


def run(
    *,
    scale: str = "10k",
    seed: int = 42,
    verify_samples: int = 10_000,
    chunk_chars: int = 800,
    unknown_rate: float = 0.1,
    receipt_samples: int = 1_000,
    verifier_samples: int = 1_000,
    log: Optional[Any] = None,
) -> BenchResult:
    """Run one in-process SQLite bench and return the result.

    Args:
        scale: One of the keys in :data:`PRESETS` (``"1k"``, ``"10k"``,
            ``"100k"``, ``"1m"``).
        seed: PRNG seed. Deterministic: same seed reproduces the same
            corpus and the same percentile shape.
        verify_samples: Number of single-fingerprint verify calls
            after ingest. The reported percentiles are over this set.
        chunk_chars: Approximate per-chunk character length.
        unknown_rate: Fraction of verify queries that target
            unindexed fingerprints (exercises the UNVERIFIED path).
        receipt_samples: Number of full end-to-end ``verify_chunks``
            calls (fingerprint + index lookup + canonicalisation +
            Ed25519 signature). Pass 0 to skip. Each sample produces a
            single-chunk signed receipt.
        verifier_samples: Number of receipts to verify with the
            standalone ``provenex-verifier`` library (the offline auditor
            path). Capped at ``receipt_samples``. Skipped silently when
            ``provenex_verifier`` is not installed.
        log: Optional file-like object for human-readable progress
            messages. Defaults to ``sys.stderr`` when ``None``.
    """
    if scale not in PRESETS:
        raise ValueError(
            f"unknown scale {scale!r}; expected one of {sorted(PRESETS)}"
        )
    if verify_samples < 1:
        raise ValueError(
            f"verify_samples must be >= 1, got {verify_samples}"
        )
    if chunk_chars < 1:
        raise ValueError(
            f"chunk_chars must be >= 1, got {chunk_chars}"
        )
    if not 0.0 <= unknown_rate <= 1.0:
        raise ValueError(
            f"unknown_rate must be in [0.0, 1.0], got {unknown_rate}"
        )
    target_chunks = PRESETS[scale]
    log = log if log is not None else sys.stderr
    rng = random.Random(seed)
    fp = Fingerprinter(FingerprinterConfig())
    signing_secret = secrets.token_bytes(32)

    overall_t0 = time.perf_counter()

    workdir = Path(tempfile.mkdtemp(prefix="provenex-bench-"))
    db_path = workdir / "bench.sqlite"
    print(
        f"[provenex bench] pattern=A (in-process SQLite) scale={scale} "
        f"target_chunks={target_chunks:,} chunk_chars={chunk_chars} "
        f"seed={seed}",
        file=log,
    )

    index = SQLiteProvenanceIndex(str(db_path), signing_secret=signing_secret)
    fingerprints: List[str] = []
    ingest_latencies: List[float] = []
    print(f"[provenex bench] ingesting...", file=log)
    ingest_t0 = time.perf_counter()
    for i in range(target_chunks):
        text = _generate_chunk(rng, chunk_chars)
        finger = fp.fingerprint_chunk(text)
        fingerprints.append(finger)
        op_t0 = time.perf_counter()
        index.add(
            fingerprint=finger,
            document_id=f"doc-{i // 100}",
            document_version="sha256:" + "0" * 64,
            chunk_offset=(i % 100) * chunk_chars,
            chunk_length=chunk_chars,
        )
        ingest_latencies.append(time.perf_counter() - op_t0)
    ingest_elapsed = time.perf_counter() - ingest_t0
    db_size_bytes = db_path.stat().st_size
    print(
        f"[provenex bench]   ingested {target_chunks:,} chunks in "
        f"{ingest_elapsed:.2f} s ({target_chunks / ingest_elapsed:,.0f} ops/s) "
        f"-> {db_size_bytes / 1024 / 1024:.1f} MB on disk",
        file=log,
    )

    # Verify: mix of known + unknown fingerprints.
    sample_rng = random.Random(seed + 1)
    sample_fps: List[str] = []
    for _ in range(verify_samples):
        if unknown_rate > 0 and sample_rng.random() < unknown_rate:
            # Unknown: never-ingested fingerprint. Hits the UNVERIFIED path.
            sample_fps.append(
                "sha256:" + sample_rng.randbytes(32).hex()
            )
        else:
            sample_fps.append(sample_rng.choice(fingerprints))

    print(
        f"[provenex bench] verifying {verify_samples:,} samples "
        f"({int(unknown_rate * 100)}% unknown)...",
        file=log,
    )
    verify_latencies: List[float] = []
    outcome_counts: Dict[str, int] = {}
    verify_t0 = time.perf_counter()
    for f in sample_fps:
        op_t0 = time.perf_counter()
        outcome = index.verify(f)
        verify_latencies.append(time.perf_counter() - op_t0)
        key = outcome.value if hasattr(outcome, "value") else str(outcome)
        outcome_counts[key] = outcome_counts.get(key, 0) + 1
    verify_elapsed = time.perf_counter() - verify_t0
    print(
        f"[provenex bench]   verified {verify_samples:,} in "
        f"{verify_elapsed:.2f} s ({verify_samples / verify_elapsed:,.0f} ops/s)",
        file=log,
    )

    # v1.0.0: full end-to-end receipt-generation latency. Uses
    # Ed25519 (the v1.0.0 default) so the numbers reflect what
    # production deployments actually emit.
    receipt_block: Optional[Dict[str, Any]] = None
    saved_receipts: List[Dict[str, Any]] = []
    if receipt_samples > 0:
        signer = Ed25519Signer.generate()
        policy = Policy(mode="enforce")  # enforce mirrors the 0.x semantics
        gen_rng = random.Random(seed + 2)
        # Re-use a slice of the ingested chunks so verify_chunks finds
        # them in the index and produces VERIFIED outcomes.
        gen_chunks: List[str] = []
        rng_for_gen = random.Random(seed + 3)
        for _ in range(receipt_samples):
            # Re-derive the same chunk text bytes deterministically by
            # picking a known fingerprint and re-generating its content.
            # The bench's _generate_chunk path is deterministic given the
            # same seed; we re-seed per pick so callers can reproduce.
            text = _generate_chunk(rng_for_gen, chunk_chars)
            gen_chunks.append(text)
        # The gen_chunks are independent random bytes; they will be
        # UNVERIFIED in the index, but the receipt path measures the
        # same number of operations regardless of outcome. Honest
        # comparison: production deployments hit a mix.
        print(
            f"[provenex bench] generating {receipt_samples:,} signed receipts (Ed25519)...",
            file=log,
        )
        receipt_latencies: List[float] = []
        gen_t0 = time.perf_counter()
        for text in gen_chunks:
            op_t0 = time.perf_counter()
            result = verify_chunks(
                text,
                index=index,
                policy=policy,
                signer=signer,
            )
            receipt_latencies.append(time.perf_counter() - op_t0)
            if len(saved_receipts) < verifier_samples:
                saved_receipts.append(result.receipt.to_dict())
        gen_elapsed = time.perf_counter() - gen_t0
        print(
            f"[provenex bench]   produced {receipt_samples:,} receipts in "
            f"{gen_elapsed:.2f} s "
            f"({receipt_samples / gen_elapsed:,.0f} receipts/s)",
            file=log,
        )
        receipt_block = {
            "samples": receipt_samples,
            "elapsed_seconds": gen_elapsed,
            "ops_per_second": receipt_samples / gen_elapsed,
            "signer_algorithm": signer.algorithm,
            "percentiles_seconds": _percentiles(receipt_latencies),
        }

    # v1.0.0: standalone-verifier verification latency. Only the
    # cryptographic envelope; no index lookups. This is the number an
    # external auditor sees when running ``provenex-verifier`` against
    # a hand-off receipt.
    verifier_block: Optional[Dict[str, Any]] = None
    if saved_receipts:
        try:
            from provenex_verifier import verify_receipt as _verify_receipt
        except ImportError:
            print(
                "[provenex bench] provenex-verifier not installed; skipping "
                "verifier-verification bench. `pip install provenex-verifier` "
                "to include it.",
                file=log,
            )
        else:
            pub_pem = signer.public_key_pem()
            print(
                f"[provenex bench] verifying {len(saved_receipts):,} receipts "
                f"via provenex-verifier...",
                file=log,
            )
            verifier_latencies: List[float] = []
            verifier_t0 = time.perf_counter()
            for r_dict in saved_receipts:
                op_t0 = time.perf_counter()
                _verify_receipt(r_dict, pub_pem)
                verifier_latencies.append(time.perf_counter() - op_t0)
            verifier_elapsed = time.perf_counter() - verifier_t0
            print(
                f"[provenex bench]   verified {len(saved_receipts):,} in "
                f"{verifier_elapsed:.2f} s "
                f"({len(saved_receipts) / verifier_elapsed:,.0f} ops/s)",
                file=log,
            )
            verifier_block = {
                "samples": len(saved_receipts),
                "elapsed_seconds": verifier_elapsed,
                "ops_per_second": len(saved_receipts) / verifier_elapsed,
                "percentiles_seconds": _percentiles(verifier_latencies),
            }

    index.close()

    # Memory snapshot after every measured pass — captures peak RSS for
    # the whole benchmark run. ``ru_maxrss`` is monotonic-peak so the
    # value reflects whichever phase was the heaviest (ingest or verify
    # for large corpora; receipt-gen for small ones).
    memory_block = {
        "peak_rss_bytes": _max_rss_bytes(),
    }

    overall_elapsed = time.perf_counter() - overall_t0

    return BenchResult(
        provenex_version=__version__,
        scale=scale,
        target_chunks=target_chunks,
        seed=seed,
        chunk_chars=chunk_chars,
        platform={
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        ingest={
            "chunks": target_chunks,
            "elapsed_seconds": ingest_elapsed,
            "ops_per_second": target_chunks / ingest_elapsed,
            "percentiles_seconds": _percentiles(ingest_latencies),
        },
        verify={
            "samples": verify_samples,
            "elapsed_seconds": verify_elapsed,
            "ops_per_second": verify_samples / verify_elapsed,
            "outcome_counts": outcome_counts,
            "percentiles_seconds": _percentiles(verify_latencies),
        },
        db_size_bytes=db_size_bytes,
        elapsed_total_seconds=overall_elapsed,
        receipt_generation=receipt_block,
        verifier_verification=verifier_block,
        memory=memory_block,
    )


def _format_summary(result: BenchResult) -> str:
    """Human-readable one-screen summary, written to stdout."""
    v = result.verify["percentiles_seconds"]
    lines = [
        "",
        f"Provenex bench — Pattern A (in-process SQLite) — scale={result.scale}",
        f"  provenex-core {result.provenex_version} on "
        f"{result.platform['system']} {result.platform['machine']} "
        f"(python {result.platform['python']})",
        "",
        f"  Ingest: {result.target_chunks:,} chunks in "
        f"{result.ingest['elapsed_seconds']:.2f} s "
        f"({result.ingest['ops_per_second']:,.0f} ops/s)",
        f"  DB size: {result.db_size_bytes / 1024 / 1024:.1f} MB on disk",
        "",
        f"  Verify per call (over {result.verify['samples']:,} samples):",
        f"    p50:  {_format_seconds(v['p50'])}",
        f"    p95:  {_format_seconds(v['p95'])}",
        f"    p99:  {_format_seconds(v['p99'])}",
        f"    p999: {_format_seconds(v['p999'])}",
        f"    max:  {_format_seconds(v['max'])}",
        f"  Throughput: {result.verify['ops_per_second']:,.0f} ops/s",
        "",
    ]
    if result.receipt_generation:
        rg = result.receipt_generation["percentiles_seconds"]
        lines.extend(
            [
                f"  Receipt generation end-to-end (over "
                f"{result.receipt_generation['samples']:,} samples, "
                f"{result.receipt_generation['signer_algorithm']}):",
                f"    p50:  {_format_seconds(rg['p50'])}",
                f"    p95:  {_format_seconds(rg['p95'])}",
                f"    p99:  {_format_seconds(rg['p99'])}",
                f"  Throughput: "
                f"{result.receipt_generation['ops_per_second']:,.0f} receipts/s",
                "",
            ]
        )
    if result.verifier_verification:
        vv = result.verifier_verification["percentiles_seconds"]
        lines.extend(
            [
                f"  Receipt verification via provenex-verifier (over "
                f"{result.verifier_verification['samples']:,} receipts):",
                f"    p50:  {_format_seconds(vv['p50'])}",
                f"    p95:  {_format_seconds(vv['p95'])}",
                f"    p99:  {_format_seconds(vv['p99'])}",
                f"  Throughput: "
                f"{result.verifier_verification['ops_per_second']:,.0f} ops/s",
                "",
            ]
        )
    if result.memory:
        lines.extend(
            [
                f"  Peak RSS: "
                f"{result.memory['peak_rss_bytes'] / 1024 / 1024:,.1f} MB",
                "",
            ]
        )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="provenex bench",
        description=(
            "Reproduce the README's Pattern A (in-process SQLite) verify "
            "and ingest numbers on your hardware."
        ),
    )
    p.add_argument(
        "--scale",
        choices=sorted(PRESETS.keys()),
        default="10k",
        help="Corpus size preset (default: 10k, ~10s on a laptop).",
    )
    p.add_argument(
        "--seed", type=int, default=42, help="PRNG seed (default: 42)."
    )
    p.add_argument(
        "--verify-samples",
        type=int,
        default=10_000,
        help="Verify-call sample size (default: 10_000).",
    )
    p.add_argument(
        "--chunk-chars",
        type=int,
        default=800,
        help="Synthetic chunk length in characters (default: 800).",
    )
    p.add_argument(
        "--unknown-rate",
        type=float,
        default=0.1,
        help=(
            "Fraction of verify queries that target unindexed fingerprints "
            "(default: 0.1, exercises the UNVERIFIED path)."
        ),
    )
    p.add_argument(
        "--receipt-samples",
        type=int,
        default=1_000,
        help=(
            "Number of end-to-end receipt-generation samples (Ed25519). "
            "0 disables the receipt + verifier passes. Default: 1_000."
        ),
    )
    p.add_argument(
        "--verifier-samples",
        type=int,
        default=1_000,
        help=(
            "Number of receipts to verify with the standalone "
            "provenex-verifier library. Capped at --receipt-samples. "
            "Default: 1_000."
        ),
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="If set, write the JSON report to this path (in addition to stdout summary).",
    )
    p.add_argument(
        "--json-only",
        action="store_true",
        help="Emit only the JSON report to stdout; suppress the human summary.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point used by ``provenex bench`` and ``python -m provenex.bench.scale``."""
    args = _build_parser().parse_args(argv)
    result = run(
        scale=args.scale,
        seed=args.seed,
        verify_samples=args.verify_samples,
        chunk_chars=args.chunk_chars,
        unknown_rate=args.unknown_rate,
        receipt_samples=args.receipt_samples,
        verifier_samples=args.verifier_samples,
    )
    if args.json_only:
        json.dump(result.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(_format_summary(result))
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result.to_dict(), indent=2))
        print(f"[provenex bench] wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
