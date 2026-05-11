"""High-level fingerprinting: normalize text, then slide a window across it.

This module ties together :mod:`provenex.core.normalizer` and
:mod:`provenex.core.hasher` to expose the single operation that ingestion and
verification both perform: take some text, get back a deterministic list of
fingerprints.

Same input + same configuration = same fingerprints. Always. This determinism
is what makes the provenance receipt independently verifiable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List

from .hasher import WindowHash, iter_window_hashes
from .normalizer import NormalizationOptions, TextNormalizer


@dataclass(frozen=True)
class FingerprinterConfig:
    """Configuration for the fingerprinter.

    Attributes:
        window_size: Sliding window length in codepoints. Larger windows mean
            fewer fingerprints per document and lower false-positive match
            rates, but coarser retrieval-time verification. 128 is a balanced
            default for prose; 64 or 32 is appropriate for short text /
            structured data.
        stride: Step size between consecutive windows. Set ``stride <
            window_size`` for overlapping windows (recommended). A stride of
            ``window_size // 2`` is a reasonable default.
        normalization: Normalization options to apply before windowing.
    """

    window_size: int = 128
    stride: int = 64
    normalization: NormalizationOptions = field(default_factory=NormalizationOptions)


@dataclass(frozen=True)
class Fingerprint:
    """A single fingerprint plus the metadata needed to verify it later.

    Attributes:
        fingerprint: The SHA-256 fingerprint string (``"sha256:<hex>"``).
        offset: Character offset within the normalized text.
        length: Window length in characters.
        normalization_applied: Ordered list of normalization step identifiers
            that were applied to produce this fingerprint. Recorded so the
            provenance receipt can document exactly how the chunk was
            processed.
    """

    fingerprint: str
    offset: int
    length: int
    normalization_applied: List[str]


@dataclass(frozen=True)
class FingerprintingResult:
    """All fingerprints for a chunk of text plus the document version hash.

    Attributes:
        fingerprints: The list of fingerprints in left-to-right order.
        document_version: A SHA-256 over the full normalized text, used as the
            document version hash on the provenance receipt. Two documents
            with identical normalized content share a version hash.
        normalization_applied: The normalization pipeline that was applied
            (same as on each fingerprint, hoisted here for convenience).
    """

    fingerprints: List[Fingerprint]
    document_version: str
    normalization_applied: List[str]


class Fingerprinter:
    """Top-level fingerprinting entry point used by both ingestion and verification.

    Construct one Fingerprinter per configuration. Reuse it across documents —
    it is stateless beyond its configuration.

    Example:
        >>> fp = Fingerprinter()
        >>> result = fp.fingerprint("The quick brown fox jumps over the lazy dog.")
        >>> all(f.fingerprint.startswith("sha256:") for f in result.fingerprints)
        True

    Determinism guarantee:
        Two calls to :meth:`fingerprint` with the same text and the same
        :class:`FingerprinterConfig` will always produce identical
        :class:`FingerprintingResult` objects, including the document_version
        hash.
    """

    def __init__(self, config: FingerprinterConfig | None = None) -> None:
        """Initialize the fingerprinter.

        Args:
            config: Fingerprinter configuration. If ``None``, defaults are
                used (window_size=128, stride=64, default normalization).
        """
        self._config = config or FingerprinterConfig()
        self._normalizer = TextNormalizer(options=self._config.normalization)

    @property
    def config(self) -> FingerprinterConfig:
        """The configuration in effect for this fingerprinter."""
        return self._config

    def fingerprint(self, text: str) -> FingerprintingResult:
        """Normalize ``text`` and return its sliding-window fingerprints.

        Args:
            text: The raw input text. Will be normalized before windowing.

        Returns:
            A :class:`FingerprintingResult` containing one fingerprint per
            sliding window, plus the document version hash over the full
            normalized text.
        """
        norm = self._normalizer.normalize(text)
        windows: List[WindowHash] = list(
            iter_window_hashes(
                text=norm.text,
                window_size=self._config.window_size,
                stride=self._config.stride,
            )
        )
        fingerprints = [
            Fingerprint(
                fingerprint=w.fingerprint,
                offset=w.offset,
                length=w.length,
                normalization_applied=list(norm.applied),
            )
            for w in windows
        ]
        document_version = (
            f"sha256:{hashlib.sha256(norm.text.encode('utf-8')).hexdigest()}"
        )
        return FingerprintingResult(
            fingerprints=fingerprints,
            document_version=document_version,
            normalization_applied=list(norm.applied),
        )

    def fingerprint_chunk(self, text: str) -> str:
        """Compute a single fingerprint over a chunk of text (no windowing).

        Used at verification time when a retriever returns an already-chunked
        document and we want to check whether the chunk as a whole appears in
        the provenance index.

        Args:
            text: The chunk text. Will be normalized before hashing.

        Returns:
            The SHA-256 fingerprint string (``"sha256:<hex>"``).
        """
        norm = self._normalizer.normalize(text)
        return f"sha256:{hashlib.sha256(norm.text.encode('utf-8')).hexdigest()}"
