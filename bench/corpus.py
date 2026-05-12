"""Deterministic synthetic corpus generator.

The benchmark intentionally does not use real prose. What we're measuring —
fingerprinting throughput, index insertion rate, lookup latency, proof
generation — depends on chunk *size and count*, not chunk content. Random
ASCII characters drawn from a seeded PRNG give us reproducible runs that
exercise every code path without bundling text data with the repo.

A run with the same seed produces bit-identical documents, so a customer
running ``bench.scale`` on their hardware can compare results against a
prior run head-to-head.

Documents are streamed; the corpus iterator never holds more than one
document's worth of text in memory at a time.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass
from typing import Iterator, List


_ALPHABET = string.ascii_letters + string.digits + " "


@dataclass(frozen=True)
class CorpusConfig:
    """Shape of the corpus to generate.

    Attributes:
        seed: PRNG seed. Same seed always produces the same corpus.
        target_chunks: Total number of chunks to emit across all documents.
        mean_chunks_per_doc: Average chunks per document. Document count is
            derived as ``target_chunks // mean_chunks_per_doc``.
        mean_chunk_chars: Mean chunk length in characters. Actual sizes are
            drawn from a log-normal distribution around this mean so the
            corpus has realistic spread (many short chunks, some long).
        chunk_size_sigma: Standard deviation parameter for the log-normal
            chunk-size distribution. 0.4 yields a moderate spread.
    """

    seed: int = 42
    target_chunks: int = 10_000
    mean_chunks_per_doc: int = 100
    mean_chunk_chars: int = 800
    chunk_size_sigma: float = 0.4


@dataclass(frozen=True)
class SyntheticDocument:
    """One generated document.

    Attributes:
        document_id: Stable identifier for this document (``doc_00000001``).
        chunks: The chunk texts, in order.
    """

    document_id: str
    chunks: List[str]


class SyntheticCorpus:
    """Stream synthetic documents to drive the benchmark.

    Usage::

        corpus = SyntheticCorpus(CorpusConfig(target_chunks=100_000))
        for doc in corpus:
            ...  # ingest doc.chunks under doc.document_id
        # Total chunks emitted == config.target_chunks (exactly).
    """

    def __init__(self, config: CorpusConfig) -> None:
        self._config = config

    @property
    def config(self) -> CorpusConfig:
        return self._config

    @property
    def estimated_doc_count(self) -> int:
        """Approximate number of documents that will be emitted."""
        return max(1, self._config.target_chunks // self._config.mean_chunks_per_doc)

    def __iter__(self) -> Iterator[SyntheticDocument]:
        cfg = self._config
        rng = random.Random(cfg.seed)
        # Log-normal parameter so the *median* chunk length is close to the
        # configured mean. ln(mean) shifts the mode of the distribution.
        size_mu = float(_safe_log(cfg.mean_chunk_chars))
        size_sigma = cfg.chunk_size_sigma

        remaining = cfg.target_chunks
        doc_idx = 0
        while remaining > 0:
            # Number of chunks for this document: log-normal around the mean.
            n_chunks = max(
                1,
                int(round(rng.lognormvariate(_safe_log(cfg.mean_chunks_per_doc), 0.3))),
            )
            n_chunks = min(n_chunks, remaining)

            chunks: List[str] = []
            for _ in range(n_chunks):
                size = max(64, int(rng.lognormvariate(size_mu, size_sigma)))
                chunks.append("".join(rng.choices(_ALPHABET, k=size)))

            yield SyntheticDocument(
                document_id=f"doc_{doc_idx:08d}",
                chunks=chunks,
            )
            remaining -= n_chunks
            doc_idx += 1


def _safe_log(x: float) -> float:
    """Natural log, but never log(0)."""
    import math

    return math.log(max(1.0, float(x)))
