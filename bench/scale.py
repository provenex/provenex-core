"""Provenex scale benchmark — CLI entry point.

Usage::

    python -m bench.scale --scale 10k    # smoke test (~5s)
    python -m bench.scale --scale 100k   # mid-enterprise (~30s)
    python -m bench.scale --scale 1m     # large enterprise (target tier)
    python -m bench.scale --scale 1m --out-dir reports/

Output: two files in ``--out-dir`` (default: ``./bench_reports``)::

    bench_<scale>_<timestamp>.json     # full metrics, machine-readable
    bench_<scale>_<timestamp>.md       # customer-facing report

The benchmark is deterministic: a given ``--seed`` produces bit-identical
fingerprints, the same tree head, and comparable latency distributions
(modulo hardware noise).
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Tuple

from .corpus import CorpusConfig, SyntheticCorpus
from .report import BenchRun, to_json, to_markdown
from .workloads import run_ingest, run_proof, run_verify


# Scale tier presets.
# target_chunks, mean_chunks_per_doc, mean_chunk_chars
_PRESETS: Dict[str, Tuple[int, int, int]] = {
    "10k": (10_000, 50, 800),
    "100k": (100_000, 100, 800),
    "1m": (1_000_000, 100, 800),
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="bench.scale",
        description="Provenex scale benchmark — ingest, verify, prove at enterprise scale.",
    )
    parser.add_argument(
        "--scale",
        choices=sorted(_PRESETS.keys()),
        default="10k",
        help="Preset corpus size (default: 10k for fast iteration).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="PRNG seed for the synthetic corpus.",
    )
    parser.add_argument(
        "--verify-samples",
        type=int,
        default=10_000,
        help="Number of verification queries to run after ingest.",
    )
    parser.add_argument(
        "--proof-samples",
        type=int,
        default=1_000,
        help="Number of inclusion proofs to generate and offline-verify.",
    )
    parser.add_argument(
        "--unknown-rate",
        type=float,
        default=0.1,
        help="Fraction of verification queries that target unindexed "
        "fingerprints (exercises the UNVERIFIED path). 0.0 disables.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("bench_reports"),
        help="Directory to write JSON and Markdown reports into.",
    )
    parser.add_argument(
        "--keep-db",
        action="store_true",
        help="Keep the temporary SQLite file in --out-dir for inspection.",
    )
    parser.add_argument(
        "--corpus",
        choices=("synthetic", "wiki"),
        default="synthetic",
        help="Corpus source. 'synthetic' uses the seeded ASCII generator "
        "(default). 'wiki' streams real Wikipedia article text from the "
        "snapshot at --wiki-cache-dir.",
    )
    parser.add_argument(
        "--wiki-cache-dir",
        type=Path,
        default=Path("bench/wiki_cache"),
        help="Cache populated by `python -m bench.wiki_fetch`. "
        "Only consulted when --corpus=wiki.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    target_chunks, mean_chunks_per_doc, mean_chunk_chars = _PRESETS[args.scale]

    corpus_config: object
    if args.corpus == "synthetic":
        corpus_config = CorpusConfig(
            seed=args.seed,
            target_chunks=target_chunks,
            mean_chunks_per_doc=mean_chunks_per_doc,
            mean_chunk_chars=mean_chunk_chars,
        )
        corpus = SyntheticCorpus(corpus_config)
    else:
        from .wiki_corpus import WikiCorpus, WikiCorpusConfig

        corpus_config = WikiCorpusConfig(
            cache_dir=args.wiki_cache_dir,
            target_chunks=target_chunks,
            mean_chunk_chars=mean_chunk_chars,
            seed=args.seed,
        )
        corpus = WikiCorpus(corpus_config)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    tag = f"{args.scale}_{args.corpus}"
    db_path = args.out_dir / f"bench_{tag}_{timestamp}.db"
    json_path = args.out_dir / f"bench_{tag}_{timestamp}.json"
    md_path = args.out_dir / f"bench_{tag}_{timestamp}.md"
    signing_secret = secrets.token_bytes(32)

    started_at = time.time()

    print(
        f"[bench] corpus={args.corpus} scale={args.scale} "
        f"target_chunks={target_chunks:,} mean_chunk_chars={mean_chunk_chars}",
        file=sys.stderr,
    )

    print(f"[bench] ingesting into {db_path}...", file=sys.stderr)
    ingest_result = run_ingest(corpus, str(db_path), signing_secret=signing_secret)
    idx = ingest_result.extras["index"]
    fingerprints = ingest_result.extras["fingerprints"]
    db_size_bytes = ingest_result.extras["db_size_bytes"]
    tree_root = ingest_result.extras["tree_root"]
    tree_size = ingest_result.extras["tree_size"]
    print(
        f"[bench]   ingested {tree_size:,} chunks "
        f"({db_size_bytes / 1024 / 1024:.1f} MB on disk)",
        file=sys.stderr,
    )

    print(
        f"[bench] verifying {args.verify_samples:,} samples...", file=sys.stderr
    )
    verify_result = run_verify(
        idx,
        fingerprints,
        sample_size=args.verify_samples,
        unknown_rate=args.unknown_rate,
        seed=args.seed,
    )

    print(
        f"[bench] generating {args.proof_samples:,} inclusion proofs...",
        file=sys.stderr,
    )
    proof_result = run_proof(
        idx,
        fingerprints,
        sample_size=args.proof_samples,
        seed=args.seed,
    )

    idx.close()
    ended_at = time.time()

    corpus_config_dict = asdict(corpus_config)
    # Path objects don't survive JSON serialization; coerce to str.
    for k, v in list(corpus_config_dict.items()):
        if isinstance(v, Path):
            corpus_config_dict[k] = str(v)

    run = BenchRun(
        scale_label=f"{args.scale}_{args.corpus}",
        config={
            "scale": args.scale,
            "corpus_kind": args.corpus,
            "corpus": corpus_config_dict,
            "verify_samples": args.verify_samples,
            "proof_samples": args.proof_samples,
            "unknown_rate": args.unknown_rate,
        },
        results=[ingest_result, verify_result, proof_result],
        started_at=started_at,
        ended_at=ended_at,
        db_size_bytes=db_size_bytes,
        tree_size=tree_size,
        tree_root=tree_root,
    )

    json_path.write_text(to_json(run))
    md_path.write_text(to_markdown(run))

    if not args.keep_db:
        try:
            os.unlink(db_path)
        except OSError:
            pass

    print(f"[bench] wrote {json_path}", file=sys.stderr)
    print(f"[bench] wrote {md_path}", file=sys.stderr)
    print(
        f"[bench] total wall time: {ended_at - started_at:.2f} s",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
