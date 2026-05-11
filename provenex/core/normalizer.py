"""Text normalization pipeline for deterministic fingerprinting.

Normalization is applied to text BEFORE the rolling hash is computed, so that
semantically identical content produces identical fingerprints regardless of
incidental encoding differences (Unicode form, whitespace, etc.).

The applied normalizations are recorded on the provenance receipt so that
verifiers can reproduce the pipeline byte-for-byte. This module has no external
dependencies — pure stdlib only — so the algorithm is auditable end to end.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List


# Compiled at import time. Matches any run of Unicode whitespace.
_WHITESPACE_RUN = re.compile(r"\s+", re.UNICODE)


@dataclass(frozen=True)
class NormalizationOptions:
    """Configuration for the text normalization pipeline.

    Attributes:
        unicode_nfc: Apply Unicode Normalization Form C. Recommended default.
            Ensures canonical equivalence (e.g. precomposed vs. decomposed
            characters) produces identical fingerprints.
        whitespace_collapse: Collapse runs of whitespace to a single space and
            strip leading/trailing whitespace. Recommended default.
        case_fold: Apply Unicode case folding (more aggressive than .lower()).
            OFF by default because compliance use cases generally require
            preserving case (legal/regulatory text is case-sensitive).
        strip_zero_width: Remove zero-width characters (ZWJ, ZWNJ, BOM, etc.)
            that can be used to evade fingerprint matching.
    """

    unicode_nfc: bool = True
    whitespace_collapse: bool = True
    case_fold: bool = False
    strip_zero_width: bool = True


# Zero-width and BOM-class characters that should be stripped when
# strip_zero_width is enabled. Listed explicitly so the audit trail is clear.
_ZERO_WIDTH_CHARS = frozenset(
    [
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\u2060",  # WORD JOINER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
    ]
)


@dataclass(frozen=True)
class NormalizationResult:
    """The result of running the normalization pipeline.

    Attributes:
        text: The normalized text.
        applied: Ordered list of normalization step identifiers that were
            applied. Used in the provenance receipt under
            ``sources[].normalization_applied``.
    """

    text: str
    applied: List[str] = field(default_factory=list)


class TextNormalizer:
    """Applies a configurable pipeline of normalizations to text.

    The normalizer is stateless and thread-safe. Construct one per
    configuration and reuse it across documents.

    Example:
        >>> normalizer = TextNormalizer()
        >>> result = normalizer.normalize("Hello   world\u200b!")
        >>> result.text
        'Hello world!'
        >>> result.applied
        ['unicode_nfc', 'strip_zero_width', 'whitespace_collapse']
    """

    def __init__(self, options: NormalizationOptions | None = None) -> None:
        """Initialize the normalizer.

        Args:
            options: Normalization configuration. If ``None``, defaults are
                used (NFC + whitespace collapse + strip zero-width, no case
                folding).
        """
        self._options = options or NormalizationOptions()

    @property
    def options(self) -> NormalizationOptions:
        """The normalization options in effect for this normalizer."""
        return self._options

    def normalize(self, text: str) -> NormalizationResult:
        """Apply the configured normalization pipeline to ``text``.

        Steps are applied in a fixed order so that the output is deterministic
        given the same options. The order is:

            1. Unicode NFC
            2. Strip zero-width characters
            3. Case folding
            4. Whitespace collapse

        Args:
            text: The input text.

        Returns:
            A :class:`NormalizationResult` containing the normalized text and
            an ordered list of step identifiers that were applied.
        """
        applied: List[str] = []
        out = text

        if self._options.unicode_nfc:
            out = unicodedata.normalize("NFC", out)
            applied.append("unicode_nfc")

        if self._options.strip_zero_width:
            if any(ch in _ZERO_WIDTH_CHARS for ch in out):
                out = "".join(ch for ch in out if ch not in _ZERO_WIDTH_CHARS)
            applied.append("strip_zero_width")

        if self._options.case_fold:
            out = out.casefold()
            applied.append("case_fold")

        if self._options.whitespace_collapse:
            out = _WHITESPACE_RUN.sub(" ", out).strip()
            applied.append("whitespace_collapse")

        return NormalizationResult(text=out, applied=applied)
