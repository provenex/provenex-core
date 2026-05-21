"""Tests for IndexAvailabilityPolicy validation and the verify path's
block / degrade behavior when the index errors."""

from __future__ import annotations

import asyncio
from typing import List, Optional, Sequence, Tuple

import pytest

from provenex import (
    CircuitBreaker,
    HmacSha256Signer,
    IndexAvailabilityPolicy,
    IndexEntry,
    IndexUnavailable,
    Policy,
    VerificationOutcome,
    VerificationPolicy,
    verify_chunks,
    verify_chunks_async,
    verify_receipt_signature,
)
from provenex.policy.availability import ON_ERROR_BLOCK, ON_ERROR_DEGRADE


SECRET = b"a" * 32
SIGNER = HmacSha256Signer(secret=SECRET)


# --------------------------------------------------------------------------- #
# Stub indexes                                                                #
# --------------------------------------------------------------------------- #


class _AlwaysAllVerified:
    """Sync index that returns VERIFIED entries for every fingerprint."""

    def __init__(self) -> None:
        self.calls = 0

    def verify_batch(
        self, fingerprints: Sequence[str]
    ) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
        self.calls += 1
        return [
            (VerificationOutcome.VERIFIED, _entry(fp)) for fp in fingerprints
        ]


def _entry(fingerprint: str) -> IndexEntry:
    return IndexEntry(
        fingerprint=fingerprint,
        document_id="doc-1",
        document_version="sha256:" + "0" * 64,
        ingested_at="2026-05-21T00:00:00.000Z",
        chunk_offset=0,
        chunk_length=10,
        authorized=True,
        superseded=False,
        signature="ok",
    )


class _SyncFailingIndex:
    """Sync index whose ``verify_batch`` always raises."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def verify_batch(self, fingerprints):
        raise self.exc


class _AsyncFailingIndex:
    """Async index whose ``verify_batch_async`` raises or sleeps."""

    def __init__(
        self,
        *,
        exc: Optional[Exception] = None,
        sleep_seconds: float = 0.0,
    ) -> None:
        self.exc = exc
        self.sleep_seconds = sleep_seconds

    async def verify_batch_async(self, fingerprints):
        if self.sleep_seconds:
            await asyncio.sleep(self.sleep_seconds)
        if self.exc is not None:
            raise self.exc
        return [
            (VerificationOutcome.VERIFIED, _entry(fp)) for fp in fingerprints
        ]


# --------------------------------------------------------------------------- #
# IndexAvailabilityPolicy validation                                          #
# --------------------------------------------------------------------------- #


def test_availability_defaults():
    a = IndexAvailabilityPolicy()
    assert a.on_index_error == ON_ERROR_BLOCK
    assert a.timeout_seconds == pytest.approx(2.0)
    assert a.breaker_threshold == 5


def test_availability_rejects_bad_mode():
    with pytest.raises(ValueError):
        IndexAvailabilityPolicy(on_index_error="bogus")


def test_availability_rejects_bad_timeout():
    with pytest.raises(ValueError):
        IndexAvailabilityPolicy(timeout_seconds=0)
    with pytest.raises(ValueError):
        IndexAvailabilityPolicy(timeout_seconds=-5)


def test_availability_accepts_none_timeout():
    a = IndexAvailabilityPolicy(timeout_seconds=None)
    assert a.timeout_seconds is None


# --------------------------------------------------------------------------- #
# Sync verify_chunks: block mode raises IndexUnavailable                      #
# --------------------------------------------------------------------------- #


def test_sync_block_mode_raises_on_index_error():
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_BLOCK),
    )
    idx = _SyncFailingIndex(ConnectionRefusedError("boom"))
    with pytest.raises(IndexUnavailable) as info:
        verify_chunks(
            chunks=["hello world"],
            index=idx,
            signer=SIGNER,
            policy=policy,
        )
    # ConnectionRefusedError has "Connection" in name -> "connection"
    assert info.value.error_class == "connection"


def test_sync_degrade_mode_returns_signed_receipt_with_index_status():
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_DEGRADE),
    )
    idx = _SyncFailingIndex(ConnectionRefusedError("boom"))
    result = verify_chunks(
        chunks=["alpha", "beta"],
        index=idx,
        signer=SIGNER,
        policy=policy,
    )
    # All chunks degrade to UNVERIFIED.
    for s in result.receipt.sources:
        assert s.verification_outcome == VerificationOutcome.UNVERIFIED
    # The index_status block is set and signed.
    assert result.receipt.index_status == {
        "available": False,
        "error_class": "connection",
    }
    d = result.receipt.to_dict()
    assert d["index_status"]["available"] is False
    assert d["index_status"]["error_class"] == "connection"
    # The receipt's signature still verifies over the new field.
    assert verify_receipt_signature(d, SIGNER) is True


def test_sync_no_index_status_on_healthy_call():
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_DEGRADE),
    )
    result = verify_chunks(
        chunks=["alpha"],
        index=_AlwaysAllVerified(),
        signer=SIGNER,
        policy=policy,
    )
    assert result.receipt.index_status is None
    # And the dict-form drops the optional block entirely.
    assert "index_status" not in result.receipt.to_dict()


# --------------------------------------------------------------------------- #
# Async verify_chunks_async                                                   #
# --------------------------------------------------------------------------- #


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_async_block_mode_raises_on_timeout():
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(
            on_index_error=ON_ERROR_BLOCK, timeout_seconds=0.05
        ),
    )
    idx = _AsyncFailingIndex(sleep_seconds=1.0)
    with pytest.raises(IndexUnavailable) as info:
        _run(
            verify_chunks_async(
                chunks=["x"],
                index=idx,
                signer=SIGNER,
                policy=policy,
            )
        )
    assert info.value.error_class == "timeout"


def test_async_degrade_mode_on_timeout_emits_index_status():
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(
            on_index_error=ON_ERROR_DEGRADE, timeout_seconds=0.05
        ),
    )
    idx = _AsyncFailingIndex(sleep_seconds=1.0)
    result = _run(
        verify_chunks_async(
            chunks=["x", "y"],
            index=idx,
            signer=SIGNER,
            policy=policy,
        )
    )
    assert result.receipt.index_status == {
        "available": False,
        "error_class": "timeout",
    }
    for s in result.receipt.sources:
        assert s.verification_outcome == VerificationOutcome.UNVERIFIED


def test_breaker_open_short_circuits_to_index_unavailable():
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_BLOCK),
    )
    idx = _AlwaysAllVerified()
    breaker = CircuitBreaker(threshold=1, window_seconds=10.0, cooldown_seconds=10.0)
    breaker.record_failure()  # trips OPEN
    assert breaker.state == "open"

    with pytest.raises(IndexUnavailable) as info:
        verify_chunks(
            chunks=["a"],
            index=idx,
            signer=SIGNER,
            policy=policy,
            breaker=breaker,
        )
    assert info.value.error_class == "breaker_open"
    # And the breaker did not call into the index for the short-circuited request.
    assert idx.calls == 0


def test_breaker_degrade_mode_emits_breaker_open_index_status():
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_DEGRADE),
    )
    breaker = CircuitBreaker(threshold=1, window_seconds=10.0, cooldown_seconds=10.0)
    breaker.record_failure()
    result = verify_chunks(
        chunks=["a"],
        index=_AlwaysAllVerified(),
        signer=SIGNER,
        policy=policy,
        breaker=breaker,
    )
    assert result.receipt.index_status == {
        "available": False,
        "error_class": "breaker_open",
    }


def test_breaker_records_failure_on_index_error():
    """After threshold-many failed verify calls, the breaker is OPEN."""
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_DEGRADE),
    )
    breaker = CircuitBreaker(threshold=2, window_seconds=60.0, cooldown_seconds=10.0)
    idx = _SyncFailingIndex(ConnectionRefusedError("boom"))
    for _ in range(2):
        verify_chunks(
            chunks=["a"],
            index=idx,
            signer=SIGNER,
            policy=policy,
            breaker=breaker,
        )
    assert breaker.state == "open"


def test_breaker_records_success_on_healthy_call():
    """A successful call inside HALF_OPEN closes the breaker."""
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_BLOCK),
    )
    breaker = CircuitBreaker(threshold=1, window_seconds=60.0, cooldown_seconds=0.001)
    breaker.record_failure()  # OPEN
    import time as _t
    _t.sleep(0.01)  # let cooldown elapse
    # HALF_OPEN now; one probe gets through and succeeds.
    result = verify_chunks(
        chunks=["x"],
        index=_AlwaysAllVerified(),
        signer=SIGNER,
        policy=policy,
        breaker=breaker,
    )
    assert breaker.state == "closed"
    assert result.receipt.index_status is None


# --------------------------------------------------------------------------- #
# YAML parsing                                                                #
# --------------------------------------------------------------------------- #


def test_yaml_availability_block_parses():
    text = """
version: 1
availability:
  on_index_error: degrade
  timeout_seconds: 5.0
  breaker_threshold: 10
"""
    policy = Policy.from_text(text)
    assert policy.availability.on_index_error == ON_ERROR_DEGRADE
    assert policy.availability.timeout_seconds == pytest.approx(5.0)
    assert policy.availability.breaker_threshold == 10


def test_yaml_availability_block_rejects_unknown_key():
    from provenex.policy.evaluator import PolicyParseError

    text = """
version: 1
availability:
  on_index_errors: degrade  # typo
"""
    with pytest.raises(PolicyParseError):
        Policy.from_text(text)


def test_yaml_no_availability_block_uses_defaults():
    policy = Policy.from_text("version: 1\n")
    assert policy.availability == IndexAvailabilityPolicy()


def test_yaml_availability_block_round_trips_every_knob():
    """Every documented availability key parses with the exact value, so
    we catch a future drift where one knob silently falls back to its
    dataclass default."""
    text = """
version: 1
availability:
  on_index_error: degrade
  timeout_seconds: 7.5
  breaker_threshold: 12
  breaker_window_seconds: 45.0
  breaker_cooldown_seconds: 90.0
"""
    policy = Policy.from_text(text)
    a = policy.availability
    assert a.on_index_error == ON_ERROR_DEGRADE
    assert a.timeout_seconds == pytest.approx(7.5)
    assert a.breaker_threshold == 12
    assert a.breaker_window_seconds == pytest.approx(45.0)
    assert a.breaker_cooldown_seconds == pytest.approx(90.0)


def test_yaml_availability_block_rejects_negative_timeout():
    """Numeric validation in IndexAvailabilityPolicy.__post_init__ must
    surface as a PolicyParseError, not a bare ValueError, so the operator
    sees the same parse-error path as any other bad YAML key."""
    from provenex.policy.evaluator import PolicyParseError

    text = """
version: 1
availability:
  timeout_seconds: -1.0
"""
    with pytest.raises(PolicyParseError):
        Policy.from_text(text)


# --------------------------------------------------------------------------- #
# Offline audit of a degraded receipt                                         #
# --------------------------------------------------------------------------- #


def test_degraded_receipt_signature_survives_json_round_trip():
    """A degraded receipt must remain offline-verifiable after a
    JSON serialize / deserialize round-trip, which is the auditor's
    actual path (the receipt was streamed to a sink, read back later,
    verified with the public material)."""
    import json as _json

    from provenex import verify_receipt_signature

    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_DEGRADE),
    )
    idx = _SyncFailingIndex(ConnectionRefusedError("boom"))
    result = verify_chunks(
        chunks=["alpha"], index=idx, signer=SIGNER, policy=policy
    )

    # Round-trip through JSON, then verify with a freshly-constructed
    # signer holding the same secret (the auditor's posture).
    payload = _json.dumps(result.receipt.to_dict())
    parsed = _json.loads(payload)
    assert parsed["index_status"]["available"] is False
    assert parsed["index_status"]["error_class"] == "connection"

    fresh_signer = HmacSha256Signer(secret=SECRET)
    assert verify_receipt_signature(parsed, fresh_signer) is True


def test_index_status_is_covered_by_signature():
    """If a degraded receipt is rewritten to claim availability without
    re-signing, the signature must NOT verify. This is the property
    that distinguishes a signed annotation from a hint."""
    import json as _json

    from provenex import verify_receipt_signature

    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error=ON_ERROR_DEGRADE),
    )
    idx = _SyncFailingIndex(ConnectionRefusedError("boom"))
    result = verify_chunks(
        chunks=["alpha"], index=idx, signer=SIGNER, policy=policy
    )
    d = result.receipt.to_dict()
    # Tamper: drop the index_status block while leaving the signature.
    d_tampered = dict(d)
    d_tampered.pop("index_status")
    assert verify_receipt_signature(d_tampered, HmacSha256Signer(secret=SECRET)) is False

    # And: rewriting error_class also breaks the signature.
    d_rewritten = _json.loads(_json.dumps(d))
    d_rewritten["index_status"]["error_class"] = "other"
    assert verify_receipt_signature(d_rewritten, HmacSha256Signer(secret=SECRET)) is False
