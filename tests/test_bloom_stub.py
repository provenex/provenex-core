"""Tests for the Bloom-filter interface stub (commercial slot).

The OSS ships:
* :class:`BloomFilterIndex` ABC documenting the interface.
* :class:`NoopBloomFilter` — always reports "probably contains".
* :class:`BloomAcceleratedIndex` — wraps any ProvenanceIndex, delegates
  every read through the bloom check first.

These tests assert the OSS shape: with a noop bloom, the wrapper behaves
identically to the wrapped index. The real Bloom implementation is
commercial.
"""

from __future__ import annotations

import os

from provenex.index.base import VerificationOutcome
from provenex.index.bloom import (
    BloomAcceleratedIndex,
    BloomFilterIndex,
    NoopBloomFilter,
)
from provenex.index.sqlite_index import SQLiteProvenanceIndex


def _make_index(tmp_path):
    os.environ.setdefault("PROVENEX_SIGNING_SECRET", "test-secret")
    return SQLiteProvenanceIndex(str(tmp_path / "idx.db"))


def test_noop_bloom_always_reports_contains():
    bloom = NoopBloomFilter()
    assert bloom.probably_contains("sha256:" + "a" * 64) is True
    assert bloom.probably_contains("sha256:" + "z" * 64) is True


def test_noop_bloom_tracks_size():
    bloom = NoopBloomFilter()
    assert bloom.size == 0
    bloom.add("sha256:" + "a" * 64)
    bloom.add("sha256:" + "b" * 64)
    assert bloom.size == 2


def test_bloom_filter_index_is_abstract():
    """The interface is abstract — no direct instantiation."""
    import abc

    assert issubclass(BloomFilterIndex, abc.ABC)
    # Cannot instantiate ABC directly.
    try:
        BloomFilterIndex()  # type: ignore[abstract]
    except TypeError:
        pass
    else:
        raise AssertionError("BloomFilterIndex should be abstract")


def test_accelerated_index_with_noop_behaves_like_wrapped(tmp_path):
    """With a NoopBloomFilter, the wrapper produces the same outcomes as
    the unwrapped index. This is the OSS contract: zero behavioural
    change, ready to swap in a commercial Bloom impl."""
    base = _make_index(tmp_path)
    wrapped = BloomAcceleratedIndex(base, NoopBloomFilter())

    fp = "sha256:" + "a" * 64
    wrapped.add(
        fingerprint=fp,
        document_id="d",
        document_version="sha256:" + "v" * 64,
        chunk_offset=0,
        chunk_length=10,
    )

    # Known fingerprint: VERIFIED.
    assert wrapped.verify(fp) == VerificationOutcome.VERIFIED
    entry = wrapped.lookup(fp)
    assert entry is not None
    assert entry.document_id == "d"

    # Unknown fingerprint: UNVERIFIED (passes through noop bloom,
    # hits underlying index).
    unknown = "sha256:" + "z" * 64
    assert wrapped.verify(unknown) == VerificationOutcome.UNVERIFIED

    base.close()


class _DenyAllBloom(BloomFilterIndex):
    """For testing only: a bloom that always says 'no'.

    A real Bloom filter MUST NEVER do this (no false negatives). We use
    this to confirm the wrapper short-circuits on a no answer without
    consulting the underlying index — useful as a property test of the
    wrapper, not of any real bloom implementation.
    """

    def probably_contains(self, fingerprint: str) -> bool:
        return False

    def add(self, fingerprint: str) -> None:
        pass

    @property
    def size(self) -> int:
        return 0


def test_accelerated_index_short_circuits_on_bloom_negative(tmp_path):
    """When the bloom says 'no', verify returns UNVERIFIED without
    consulting the underlying index. This is the perf property — and the
    correctness contract that bloom MUST NEVER produce false negatives."""
    base = _make_index(tmp_path)
    wrapped = BloomAcceleratedIndex(base, _DenyAllBloom())

    fp = "sha256:" + "a" * 64
    # Insert into base directly, bypassing the wrapper, so the bloom
    # doesn't know about it.
    base.add(
        fingerprint=fp,
        document_id="d",
        document_version="sha256:" + "v" * 64,
        chunk_offset=0,
        chunk_length=10,
    )

    # Bloom says no → wrapper returns UNVERIFIED, never touches base.verify.
    assert wrapped.verify(fp) == VerificationOutcome.UNVERIFIED
    assert wrapped.lookup(fp) is None

    base.close()
