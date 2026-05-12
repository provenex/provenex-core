"""Wikipedia-backed corpus that drops into the existing bench workloads.

Mirrors the public surface of :class:`bench.corpus.SyntheticCorpus` so
``run_ingest`` and friends consume it without modification. The only
difference is where the chunk text comes from:

    SyntheticCorpus -> random ASCII with log-normal sizes
    WikiCorpus      -> real article text split into ~mean_chunk_chars windows

Chunking policy: real RAG pipelines split text into fixed-ish character
windows (LangChain's RecursiveCharacterTextSplitter, LlamaIndex's
TokenTextSplitter, etc.). We mimic that — a target window with small
seeded jitter — rather than emulating the synthetic log-normal shape.
This is the distribution a customer's pipeline actually produces, so
numbers measured here generalize to what they'll see in their own RAG
stack.

Prerequisite: the cache must be populated by ``python -m bench.wiki_fetch``
before instantiating this corpus.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List

from .corpus import SyntheticDocument  # reuse the document shape


@dataclass(frozen=True)
class WikiCorpusConfig:
    """Shape of the corpus to emit from the Wikipedia cache.

    Attributes:
        cache_dir: Path containing ``manifest.txt`` and ``articles/``.
        target_chunks: Stop once this many chunks have been emitted.
        mean_chunk_chars: Target chunk window. Each chunk is
            ``mean_chunk_chars * (1 + jitter)`` characters, where jitter
            is drawn uniformly from ``[-chunk_size_jitter, +chunk_size_jitter]``.
        chunk_size_jitter: Fractional spread around ``mean_chunk_chars``.
            0.2 yields chunks in roughly the 640-960 char range when
            mean is 800.
        seed: PRNG seed for the (small) jitter.
    """

    cache_dir: Path
    target_chunks: int = 10_000
    mean_chunk_chars: int = 800
    chunk_size_jitter: float = 0.2
    seed: int = 42


class WikiCorpus:
    """Stream Wikipedia-backed documents to drive the benchmark.

    Reads article titles from ``<cache_dir>/manifest.txt``, then the
    plaintext body of each from ``<cache_dir>/articles/<hash>.txt``,
    chunks on character windows, and yields :class:`SyntheticDocument`
    instances. Stops once ``target_chunks`` is reached.
    """

    def __init__(self, config: WikiCorpusConfig) -> None:
        self._config = config
        manifest = (config.cache_dir / "manifest.txt").read_text().splitlines()
        self._titles: List[str] = [t.strip() for t in manifest if t.strip()]
        if not self._titles:
            raise FileNotFoundError(
                f"Wikipedia cache at {config.cache_dir} has no manifest entries; "
                f"run `python -m bench.wiki_fetch --cache-dir {config.cache_dir}` first."
            )

    @property
    def config(self) -> WikiCorpusConfig:
        return self._config

    @property
    def estimated_doc_count(self) -> int:
        """Conservative ceiling on documents we'll emit."""
        return len(self._titles)

    def __iter__(self) -> Iterator[SyntheticDocument]:
        cfg = self._config
        rng = random.Random(cfg.seed)
        articles_dir = cfg.cache_dir / "articles"

        remaining = cfg.target_chunks
        doc_idx = 0

        for title in self._titles:
            if remaining <= 0:
                return
            slug = _slug(title)
            path = articles_dir / f"{slug}.txt"
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            if not text:
                continue

            chunks = list(_window_chunks(
                text=text,
                mean=cfg.mean_chunk_chars,
                jitter=cfg.chunk_size_jitter,
                rng=rng,
                max_chunks=remaining,
            ))
            if not chunks:
                continue

            yield SyntheticDocument(
                document_id=f"wiki_{doc_idx:08d}",
                chunks=chunks,
            )
            remaining -= len(chunks)
            doc_idx += 1


def _slug(title: str) -> str:
    """Must match ``bench.wiki_fetch._slug`` exactly."""
    import hashlib

    return hashlib.sha256(title.encode("utf-8")).hexdigest()[:24]


def _window_chunks(
    text: str,
    mean: int,
    jitter: float,
    rng: random.Random,
    max_chunks: int,
) -> Iterator[str]:
    """Split ``text`` into chunks of length ``mean * (1 +/- jitter)``.

    Stops after ``max_chunks`` chunks even if ``text`` has more to give.
    A final chunk shorter than half the mean is merged into the previous
    chunk so we don't pollute the latency histogram with degenerate
    tiny inputs.
    """
    if max_chunks <= 0 or not text:
        return
    n = len(text)
    pos = 0
    emitted = 0
    while pos < n and emitted < max_chunks:
        spread = max(1, int(mean * jitter))
        size = mean + rng.randint(-spread, spread)
        end = min(n, pos + size)
        # If the leftover would be a stub, absorb it into this chunk.
        if n - end < mean // 2:
            end = n
        yield text[pos:end]
        emitted += 1
        pos = end
