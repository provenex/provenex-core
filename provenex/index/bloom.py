"""Bloom-filter acceleration interface (commercial slot).

The Provenex commercial product ships a Bloom-filter layer that sits in
front of the index and serves O(1) probabilistic negative lookups: if
the filter says a fingerprint is absent, it is definitely absent (no
full-index hit needed); if the filter says it is present, the full index
is consulted exactly as before.

At enterprise scale (>10M chunks) the Bloom filter is a meaningful
verify-path win: the deep-dive sizing puts a 10M-chunk filter at
roughly 143 MB at a 0.1% FPR. Below that scale, the SQLite index is
fast enough on its own and the Bloom filter is unnecessary overhead.

**This module is a stub.** The open-source core does not ship a working
Bloom filter — it ships the interface (:class:`BloomFilterIndex`) and a
no-op implementation (:class:`NoopBloomFilter`) that always reports
"probably contains" so the verify path degrades to the unaccelerated
SQLite lookup. The commercial implementation extends
:class:`BloomFilterIndex` and is dropped in via
:class:`BloomAcceleratedIndex` without changing the receipt schema, the
fingerprint algorithm, or any caller-visible API. See provenex.ai.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Sequence, Tuple

from .base import (
    ENTRY_KIND_WHOLE_CHUNK,
    IndexEntry,
    ProvenanceIndex,
    VerificationOutcome,
)


class BloomFilterIndex(ABC):
    """The probabilistic side-channel a commercial Bloom layer implements.

    Implementations MUST satisfy:

    * **No false negatives.** If :meth:`probably_contains` returns
      ``False``, the fingerprint is GUARANTEED absent from the underlying
      index. A false negative would silently turn a `VERIFIED` chunk
      into an `UNVERIFIED` one, which is a correctness bug, not a
      performance tradeoff.
    * **Configurable false positives.** A small false-positive rate
      (1e-3 typical) is acceptable; the verify path falls through to the
      full index on a positive match and re-checks. The FPR is a
      memory / accuracy knob, not a security one.
    * **Append-only behaviour.** :meth:`add` is the only mutation. The
      Bloom filter never shrinks; the commercial implementation rebuilds
      periodically to keep the FPR bounded under growth.
    """

    @abstractmethod
    def probably_contains(self, fingerprint: str) -> bool:
        """Return ``True`` if the fingerprint *might* be in the index.

        ``False`` is a guaranteed-absent answer. ``True`` requires a
        full-index follow-up to disambiguate.
        """

    @abstractmethod
    def add(self, fingerprint: str) -> None:
        """Record that a new fingerprint was added to the underlying index."""

    @property
    @abstractmethod
    def size(self) -> int:
        """Number of fingerprints inserted (cardinality, not byte size)."""


class NoopBloomFilter(BloomFilterIndex):
    """The OSS no-op Bloom filter.

    Always reports "probably contains", so the verify path falls through
    to the full SQLite lookup every time — exactly the existing OSS
    behaviour. Wrap an index with :class:`BloomAcceleratedIndex` if you
    want the Bloom-shaped surface available for substitution by a
    commercial implementation, without paying a real Bloom filter's
    memory cost.

    Use this when:

    * You are writing code that wants to be commercial-ready (the
      Bloom-accelerated wrapper) without depending on the commercial
      package at install time.
    * You are testing the wrapper without paying real filter overhead.

    Do NOT use this in production at scales where the commercial Bloom
    filter would actually help; it does nothing.
    """

    def __init__(self) -> None:
        self._n = 0

    def probably_contains(self, fingerprint: str) -> bool:  # noqa: D401
        return True

    def add(self, fingerprint: str) -> None:
        self._n += 1

    @property
    def size(self) -> int:
        return self._n


class BloomAcceleratedIndex(ProvenanceIndex):
    """Compose a :class:`BloomFilterIndex` in front of any ProvenanceIndex.

    The wrapper performs the Bloom check first; on "probably contains"
    it falls through to the wrapped index. With the OSS
    :class:`NoopBloomFilter` the behavior is identical to the wrapped
    index (one extra always-True check per verify call). With a real
    commercial Bloom filter, the negative path serves in microseconds
    without touching SQLite.

    Receipt schema and fingerprint algorithm are unchanged.
    """

    def __init__(
        self,
        base: ProvenanceIndex,
        bloom: Optional[BloomFilterIndex] = None,
    ) -> None:
        self._base = base
        self._bloom = bloom or NoopBloomFilter()

    def add(
        self,
        fingerprint: str,
        document_id: str,
        document_version: str,
        chunk_offset: int,
        chunk_length: int,
        authorized: bool = True,
        entry_kind: str = ENTRY_KIND_WHOLE_CHUNK,
    ) -> None:
        # entry_kind MUST be forwarded; without it the base class's
        # default of whole_chunk would silently promote window-only
        # locator rows to verification-eligible rows, which would then
        # return VERIFIED instead of UNVERIFIED on retrieval. Real
        # correctness bug if dropped.
        self._base.add(
            fingerprint=fingerprint,
            document_id=document_id,
            document_version=document_version,
            chunk_offset=chunk_offset,
            chunk_length=chunk_length,
            authorized=authorized,
            entry_kind=entry_kind,
        )
        self._bloom.add(fingerprint)

    def verify(self, fingerprint: str) -> VerificationOutcome:
        if not self._bloom.probably_contains(fingerprint):
            return VerificationOutcome.UNVERIFIED
        return self._base.verify(fingerprint)

    def verify_batch(
        self,
        fingerprints: "Sequence[str]",
    ) -> "List[Tuple[VerificationOutcome, Optional[IndexEntry]]]":
        """Bloom-screen the batch, then delegate hits to the base in one call.

        The base class's default ``verify_batch`` loops per-fingerprint,
        which works correctly but pays the backend's per-row round-trip
        cost once per call. Backends override ``verify_batch`` for bulk
        ``IN (...)``-style queries. Without an override here, the wrapped
        backend's bulk optimisation would be bypassed. Bloom screening
        plus a bulk query for the residual hits recovers both savings.

        Bloom misses are returned as ``(UNVERIFIED, None)``. Bloom
        false-positives (the only kind a Bloom filter produces) flow
        through to the base ``verify_batch``, which resolves them
        correctly against the underlying rows.
        """
        contains = [self._bloom.probably_contains(fp) for fp in fingerprints]
        hits = [fp for fp, ok in zip(fingerprints, contains) if ok]
        if not hits:
            return [
                (VerificationOutcome.UNVERIFIED, None) for _ in fingerprints
            ]
        hit_results = self._base.verify_batch(hits)
        # Stitch back into the original order.
        hit_iter = iter(hit_results)
        out = []
        for fp, ok in zip(fingerprints, contains):
            if ok:
                out.append(next(hit_iter))
            else:
                out.append((VerificationOutcome.UNVERIFIED, None))
        return out

    def lookup(self, fingerprint: str) -> Optional[IndexEntry]:
        if not self._bloom.probably_contains(fingerprint):
            return None
        return self._base.lookup(fingerprint)

    def set_authorization(self, document_id: str, authorized: bool) -> None:
        self._base.set_authorization(document_id, authorized)

    def supersede(self, document_id: str, new_version: str) -> int:
        return self._base.supersede(document_id, new_version)

    def close(self) -> None:
        self._base.close()
