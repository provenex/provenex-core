"""Tests for the verification policy engine."""

from __future__ import annotations

from provenex.index.base import VerificationOutcome
from provenex.policy.policy import VerificationPolicy, overall_status


def test_default_policy_blocks_unauthorized_and_tampered():
    p = VerificationPolicy()
    assert p.should_block(VerificationOutcome.UNAUTHORIZED) is True
    assert p.should_block(VerificationOutcome.TAMPERED) is True
    assert p.should_block(VerificationOutcome.VERIFIED) is False
    assert p.should_block(VerificationOutcome.STALE) is False  # default off


def test_strict_policy_blocks_everything_non_verified():
    p = VerificationPolicy(
        block_stale=True,
        block_unauthorized=True,
        block_unverified=True,
        block_tampered=True,
    )
    for o in [
        VerificationOutcome.STALE,
        VerificationOutcome.UNAUTHORIZED,
        VerificationOutcome.UNVERIFIED,
        VerificationOutcome.TAMPERED,
    ]:
        assert p.should_block(o) is True
    assert p.should_block(VerificationOutcome.VERIFIED) is False


def test_overall_status_pass():
    p = VerificationPolicy()
    assert (
        overall_status(
            [VerificationOutcome.VERIFIED, VerificationOutcome.VERIFIED], p
        )
        == "PASS"
    )


def test_overall_status_partial():
    p = VerificationPolicy(block_stale=False)
    assert (
        overall_status(
            [VerificationOutcome.VERIFIED, VerificationOutcome.STALE], p
        )
        == "PARTIAL"
    )


def test_overall_status_fail():
    p = VerificationPolicy(block_unauthorized=True)
    assert (
        overall_status(
            [VerificationOutcome.VERIFIED, VerificationOutcome.UNAUTHORIZED], p
        )
        == "FAIL"
    )


def test_overall_status_empty():
    p = VerificationPolicy()
    assert overall_status([], p) == "PASS"


def test_default_flagging():
    p = VerificationPolicy()
    # Default flags everything non-verified.
    assert p.should_flag(VerificationOutcome.STALE) is True
    assert p.should_flag(VerificationOutcome.UNAUTHORIZED) is True
    assert p.should_flag(VerificationOutcome.UNVERIFIED) is True
    assert p.should_flag(VerificationOutcome.TAMPERED) is True
    assert p.should_flag(VerificationOutcome.VERIFIED) is False
