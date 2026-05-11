"""Tests for the rolling hash and SHA-256 fingerprinting."""

from __future__ import annotations

import pytest

from provenex.core.hasher import (
    RollingHasher,
    iter_window_hashes,
    sha256_fingerprint,
)


def test_sha256_format():
    fp = sha256_fingerprint("hello")
    assert fp.startswith("sha256:")
    # 64 hex chars after the prefix
    assert len(fp) == len("sha256:") + 64
    # All hex
    int(fp.split(":")[1], 16)


def test_sha256_is_deterministic():
    assert sha256_fingerprint("hello") == sha256_fingerprint("hello")


def test_sha256_changes_on_input_change():
    assert sha256_fingerprint("hello") != sha256_fingerprint("hellp")


def test_rolling_hasher_requires_prime():
    h = RollingHasher(window_size=3)
    with pytest.raises(RuntimeError):
        h.roll(1, 2)


def test_rolling_hasher_prime_validates_length():
    h = RollingHasher(window_size=3)
    with pytest.raises(ValueError):
        h.prime([1, 2])


def test_rolling_hasher_window_size_positive():
    with pytest.raises(ValueError):
        RollingHasher(window_size=0)


def test_rolling_hash_matches_naive_recomputation():
    """The whole point of Rabin-Karp: rolling and recomputing must agree."""
    text = "the quick brown fox jumps over the lazy dog"
    W = 5
    cps = [ord(c) for c in text]

    def naive_hash(window: list[int]) -> int:
        # Same parameters as RollingHasher.
        from provenex.core.hasher import _BASE, _MOD  # type: ignore[attr-defined]
        h = 0
        for cp in window:
            h = (h * _BASE + cp) % _MOD
        return h

    h = RollingHasher(window_size=W)
    h.prime(cps[:W])
    assert h.value == naive_hash(cps[:W])

    for i in range(1, len(cps) - W + 1):
        h.roll(cps[i - 1], cps[i + W - 1])
        expected = naive_hash(cps[i : i + W])
        assert h.value == expected, f"mismatch at offset {i}"


def test_iter_window_hashes_basic():
    text = "abcdefghij"
    windows = list(iter_window_hashes(text, window_size=4, stride=2))
    # Expected window starts: 0, 2, 4, 6
    assert [w.offset for w in windows] == [0, 2, 4, 6]
    assert all(w.length == 4 for w in windows)
    assert all(w.fingerprint.startswith("sha256:") for w in windows)


def test_iter_window_hashes_stride_one():
    text = "abcdef"
    windows = list(iter_window_hashes(text, window_size=3, stride=1))
    assert [w.offset for w in windows] == [0, 1, 2, 3]


def test_iter_window_hashes_short_text_emits_one_window():
    windows = list(iter_window_hashes("hi", window_size=10, stride=1))
    assert len(windows) == 1
    assert windows[0].offset == 0
    assert windows[0].length == 2


def test_iter_window_hashes_empty_text():
    assert list(iter_window_hashes("", window_size=4, stride=1)) == []


def test_iter_window_hashes_fingerprints_match_sha256():
    text = "hello world"
    windows = list(iter_window_hashes(text, window_size=5, stride=1))
    # First window should be sha256("hello").
    assert windows[0].fingerprint == sha256_fingerprint("hello")
    # Second window should be sha256("ello ").
    assert windows[1].fingerprint == sha256_fingerprint("ello ")


def test_iter_window_hashes_validates_params():
    with pytest.raises(ValueError):
        list(iter_window_hashes("text", window_size=0, stride=1))
    with pytest.raises(ValueError):
        list(iter_window_hashes("text", window_size=2, stride=0))


def test_unicode_in_windows():
    """Window offsets are codepoint offsets, not byte offsets."""
    text = "café latte"  # 10 codepoints
    windows = list(iter_window_hashes(text, window_size=4, stride=2))
    # Offsets should be at codepoint positions 0, 2, 4, 6.
    assert [w.offset for w in windows] == [0, 2, 4, 6]
    # First window text is text[0:4] = "café"
    assert windows[0].fingerprint == sha256_fingerprint("café")
