"""Rolling hash (Rabin-Karp) plus SHA-256 strengthening.

Two-stage fingerprinting:

    1. A Rabin-Karp rolling hash provides O(1) per-window updates, so we can
       slide across a document in O(N) total work regardless of window size.
    2. Each window's content is passed through SHA-256 to produce a
       collision-resistant 256-bit fingerprint that is what we actually store
       and compare.

The rolling hash on its own is a *non-cryptographic* hash — collisions are
expected for adversarial input. SHA-256 over the same window bytes provides
the cryptographic strengthening. We keep the rolling hash because it lets us
cheaply detect when content has changed at all and decide whether to recompute
SHA-256, but the SHA-256 digest is the one we trust for identity.

This module is pure stdlib (``hashlib``) so the algorithm is auditable without
pulling in any third-party crypto.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterator

# Rabin-Karp parameters.
#
# BASE is a small prime larger than the maximum codepoint we expect to see in
# any single position. We hash over Unicode codepoints (not bytes), so we pick
# a base comfortably larger than the Basic Multilingual Plane. 1_000_003 is a
# prime used in many Rabin-Karp implementations.
#
# MOD is a large prime that keeps the rolling hash inside a 61-bit window
# (a Mersenne prime). This gives a low collision rate while staying well
# within Python's arbitrary-precision int performance sweet spot.
_BASE: int = 1_000_003
_MOD: int = (1 << 61) - 1  # 2**61 - 1, Mersenne prime


def _codepoints(text: str) -> list[int]:
    """Return the Unicode codepoint sequence for ``text``."""
    return [ord(ch) for ch in text]


@dataclass(frozen=True)
class WindowHash:
    """A single window's hash output.

    Attributes:
        offset: Character offset of the window's start within the normalized
            text.
        length: Window length in characters.
        rolling_hash: The Rabin-Karp rolling hash value at this position. Used
            internally; not part of the stored fingerprint.
        fingerprint: The cryptographic fingerprint string in the form
            ``"sha256:<hex>"``. This is what is stored in the provenance index
            and compared at verification time.
    """

    offset: int
    length: int
    rolling_hash: int
    fingerprint: str


def sha256_fingerprint(text: str) -> str:
    """Compute the canonical SHA-256 fingerprint for a chunk of text.

    The text is encoded as UTF-8 before hashing. The output is prefixed with
    the algorithm identifier so the fingerprint is self-describing on disk.

    Args:
        text: The (already normalized) chunk of text to fingerprint.

    Returns:
        A string of the form ``"sha256:<64 hex chars>"``.
    """
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class RollingHasher:
    """Rabin-Karp rolling hash over a fixed-size window.

    The hasher operates on a sequence of Unicode codepoints. After
    :meth:`prime` is called with the first ``window_size`` codepoints, each
    subsequent :meth:`roll` call replaces the oldest codepoint with a new one
    in O(1) using the recurrence:

        H(i+1) = (H(i) - text[i] * B^(W-1)) * B + text[i+W]    (mod MOD)

    Example:
        >>> hasher = RollingHasher(window_size=4)
        >>> hasher.prime([ord(c) for c in "abcd"])
        >>> h0 = hasher.value
        >>> hasher.roll(ord("a"), ord("e"))
        >>> h1 = hasher.value
        >>> h0 != h1
        True
    """

    def __init__(self, window_size: int) -> None:
        """Initialize the rolling hasher.

        Args:
            window_size: The fixed window size W in codepoints. Must be >= 1.

        Raises:
            ValueError: If ``window_size`` is less than 1.
        """
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self._window_size = window_size
        # B^(W-1) mod MOD, used in the roll equation.
        self._top_power = pow(_BASE, window_size - 1, _MOD)
        self._value: int = 0
        self._primed: bool = False

    @property
    def window_size(self) -> int:
        """The fixed window size W in codepoints."""
        return self._window_size

    @property
    def value(self) -> int:
        """The current rolling hash value."""
        return self._value

    def prime(self, codepoints: list[int]) -> None:
        """Initialize the rolling hash from the first ``window_size`` codepoints.

        Args:
            codepoints: A sequence of exactly ``window_size`` Unicode
                codepoints representing the initial window.

        Raises:
            ValueError: If ``len(codepoints) != window_size``.
        """
        if len(codepoints) != self._window_size:
            raise ValueError(
                f"prime() requires exactly {self._window_size} codepoints, "
                f"got {len(codepoints)}"
            )
        h = 0
        for cp in codepoints:
            h = (h * _BASE + cp) % _MOD
        self._value = h
        self._primed = True

    def roll(self, out_codepoint: int, in_codepoint: int) -> int:
        """Advance the window by one position.

        Args:
            out_codepoint: The codepoint that is leaving the window (the
                oldest one).
            in_codepoint: The codepoint that is entering the window (the
                newest one).

        Returns:
            The new rolling hash value.

        Raises:
            RuntimeError: If :meth:`prime` has not been called.
        """
        if not self._primed:
            raise RuntimeError("RollingHasher must be primed before rolling")
        # H(i+1) = (H(i) - out * B^(W-1)) * B + in
        h = (self._value - out_codepoint * self._top_power) % _MOD
        h = (h * _BASE + in_codepoint) % _MOD
        self._value = h
        return h


def iter_window_hashes(
    text: str, window_size: int, stride: int
) -> Iterator[WindowHash]:
    """Yield a :class:`WindowHash` for each sliding window over ``text``.

    Both a Rabin-Karp rolling hash and a SHA-256 fingerprint are computed for
    every window. The rolling hash advances in O(1) per step; SHA-256 is
    recomputed per window over the window's text content (this is unavoidable
    if we want collision-resistant identity).

    If ``text`` is shorter than ``window_size``, a single window covering the
    whole text is emitted.

    Args:
        text: The normalized text to fingerprint.
        window_size: Window length W in codepoints. Must be >= 1.
        stride: Step size S in codepoints between consecutive window starts.
            Must be >= 1. ``stride < window_size`` produces overlapping windows
            (recommended for retrieval robustness).

    Yields:
        :class:`WindowHash` instances, one per window, in left-to-right order.

    Raises:
        ValueError: If ``window_size`` or ``stride`` is less than 1.
    """
    if window_size < 1:
        raise ValueError("window_size must be >= 1")
    if stride < 1:
        raise ValueError("stride must be >= 1")

    cps = _codepoints(text)
    n = len(cps)

    # Short-text fallback: emit one window covering the whole text.
    if n <= window_size:
        if n == 0:
            return
        rh = RollingHasher(window_size=n)
        rh.prime(cps)
        yield WindowHash(
            offset=0,
            length=n,
            rolling_hash=rh.value,
            fingerprint=sha256_fingerprint(text),
        )
        return

    hasher = RollingHasher(window_size=window_size)
    hasher.prime(cps[:window_size])

    # Emit the first window at offset 0.
    yield WindowHash(
        offset=0,
        length=window_size,
        rolling_hash=hasher.value,
        fingerprint=sha256_fingerprint(text[:window_size]),
    )

    # Slide. We roll one position at a time to keep the recurrence valid, but
    # only emit every ``stride`` positions.
    for i in range(1, n - window_size + 1):
        hasher.roll(cps[i - 1], cps[i + window_size - 1])
        if i % stride == 0:
            yield WindowHash(
                offset=i,
                length=window_size,
                rolling_hash=hasher.value,
                fingerprint=sha256_fingerprint(text[i : i + window_size]),
            )
