"""Verification policy engine.

The policy translates per-chunk :class:`VerificationOutcome` values into
concrete decisions: should this chunk be blocked from reaching the LLM
context? Should the receipt be flagged as overall PASS / PARTIAL / FAIL?

Each enterprise sets its own policy. Examples:

    * A bank doing customer-facing answers: ``block_unauthorized=True``,
      ``block_stale=True``, ``block_unverified=True``. Refuse to answer
      unless every chunk is current, authorized, and Provenex-ingested.

    * A legal team doing research: ``block_unauthorized=True`` but
      ``block_stale=False`` because they explicitly want to see older
      precedent.

    * An internal Q&A bot in development: everything ``False`` —
      tolerate the loose ends but still emit the receipt so the team can
      see what would be blocked in production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from ..index.base import VerificationOutcome


@dataclass(frozen=True)
class VerificationPolicy:
    """Per-outcome blocking and flagging configuration.

    Attributes:
        block_stale: If True, STALE chunks are removed from the retrieval set
            before reaching the LLM.
        block_unauthorized: If True, UNAUTHORIZED chunks are removed.
        block_unverified: If True, UNVERIFIED chunks (those not ingested via
            Provenex at all) are removed. Set ``True`` for strict pipelines
            where every chunk MUST be Provenex-tracked.
        block_tampered: If True, TAMPERED chunks are removed. Almost always
            True — tampering is an alarm condition.
        flag_stale: If True, STALE chunks are noted on the receipt summary
            even when not blocked.
        flag_unauthorized: If True, flag UNAUTHORIZED on the receipt summary.
        flag_unverified: If True, flag UNVERIFIED on the receipt summary.
        flag_tampered: If True, flag TAMPERED on the receipt summary. Almost
            always True.
    """

    block_stale: bool = False
    block_unauthorized: bool = True
    block_unverified: bool = False
    block_tampered: bool = True
    flag_stale: bool = True
    flag_unauthorized: bool = True
    flag_unverified: bool = True
    flag_tampered: bool = True

    def should_block(self, outcome: VerificationOutcome) -> bool:
        """Return True if a chunk with this outcome should be blocked.

        Args:
            outcome: The chunk's verification outcome.

        Returns:
            True if the chunk should be removed before reaching the LLM.
        """
        return {
            VerificationOutcome.VERIFIED: False,
            VerificationOutcome.STALE: self.block_stale,
            VerificationOutcome.UNAUTHORIZED: self.block_unauthorized,
            VerificationOutcome.UNVERIFIED: self.block_unverified,
            VerificationOutcome.TAMPERED: self.block_tampered,
        }[outcome]

    def should_flag(self, outcome: VerificationOutcome) -> bool:
        """Return True if a chunk with this outcome should be flagged on the receipt.

        Args:
            outcome: The chunk's verification outcome.

        Returns:
            True if the chunk should be noted in the receipt summary.
        """
        return {
            VerificationOutcome.VERIFIED: False,
            VerificationOutcome.STALE: self.flag_stale,
            VerificationOutcome.UNAUTHORIZED: self.flag_unauthorized,
            VerificationOutcome.UNVERIFIED: self.flag_unverified,
            VerificationOutcome.TAMPERED: self.flag_tampered,
        }[outcome]


def overall_status(
    outcomes: List[VerificationOutcome],
    policy: VerificationPolicy,
) -> str:
    """Compute the overall receipt status from per-chunk outcomes.

    Args:
        outcomes: The per-chunk outcomes.
        policy: The policy in effect.

    Returns:
        One of:
            * ``"PASS"`` — every chunk verified and no flagged outcomes.
            * ``"PARTIAL"`` — at least one non-VERIFIED outcome, but no
              blocked chunks under this policy.
            * ``"FAIL"`` — at least one chunk would be blocked under policy.
    """
    if not outcomes:
        return "PASS"
    has_block = any(policy.should_block(o) for o in outcomes)
    has_non_verified = any(o != VerificationOutcome.VERIFIED for o in outcomes)
    if has_block:
        return "FAIL"
    if has_non_verified:
        return "PARTIAL"
    return "PASS"
