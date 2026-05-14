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
from typing import Optional

from .base import IndexEntry, ProvenanceIndex, VerificationOutcome


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
    ) -> None:
        self._base.add(
            fingerprint=fingerprint,
            document_id=document_id,
            document_version=document_version,
            chunk_offset=chunk_offset,
            chunk_length=chunk_length,
            authorized=authorized,
        )
        self._bloom.add(fingerprint)

    def verify(self, fingerprint: str) -> VerificationOutcome:
        if not self._bloom.probably_contains(fingerprint):
            return VerificationOutcome.UNVERIFIED
        return self._base.verify(fingerprint)

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
