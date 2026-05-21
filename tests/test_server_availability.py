"""HTTP integration tests for the availability surface on the server.

Covers:
    * `/healthz` is unconditionally 200 once the process is up.
    * `/readyz` is 200 when the index is reachable AND the breaker is
      closed; 503 when the breaker is OPEN or the sentinel index probe
      raises.
    * `/v1/verify` maps `IndexUnavailable` to a structured 503 body
      with the right `error_class`.
    * `/v1/verify` in degrade mode returns a 200 with a signed receipt
      whose `index_status.available` is false.

Does NOT require a live Postgres. Stubs the async index, signer, and
lifespan so the test exercises route logic + state plumbing without
standing up a backend.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import List, Optional, Sequence, Tuple

import pytest

starlette = pytest.importorskip("starlette")  # noqa: F841 - import guard
fastapi = pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

import provenex.server.app as server_app  # noqa: E402
from provenex import (  # noqa: E402
    CircuitBreaker,
    HmacSha256Signer,
    IndexAvailabilityPolicy,
    IndexEntry,
    Policy,
    VerificationOutcome,
    VerificationPolicy,
)
from provenex.server.metrics import Metrics  # noqa: E402


SECRET = b"x" * 32


class _StubAsyncIndex:
    """Async index stub. Configurable to raise on lookup or to return
    the known-good outcome list."""

    def __init__(
        self,
        *,
        verify_exc: Optional[Exception] = None,
        batch_exc: Optional[Exception] = None,
    ) -> None:
        self.verify_exc = verify_exc
        self.batch_exc = batch_exc

    async def verify_async(self, fingerprint: str) -> VerificationOutcome:
        if self.verify_exc is not None:
            raise self.verify_exc
        return VerificationOutcome.UNVERIFIED

    async def verify_batch_async(
        self, fingerprints: Sequence[str]
    ) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
        if self.batch_exc is not None:
            raise self.batch_exc
        return [(VerificationOutcome.UNVERIFIED, None) for _ in fingerprints]


def _build_app(
    monkeypatch,
    *,
    index: Optional[_StubAsyncIndex] = None,
    breaker: Optional[CircuitBreaker] = None,
    policy: Optional[Policy] = None,
):
    """Construct a FastAPI app with a stub lifespan that does no I/O."""
    idx = index or _StubAsyncIndex()
    breaker_obj = breaker or CircuitBreaker(
        threshold=5, window_seconds=30, cooldown_seconds=30
    )
    signer = HmacSha256Signer(secret=SECRET)
    metrics = Metrics()
    eff_policy = policy or Policy(
        verification=VerificationPolicy(block_unverified=False)
    )

    @asynccontextmanager
    async def stub_lifespan(app):
        app.state.index = idx
        app.state.signer = signer
        app.state.tenant_registry = None
        app.state.policy = eff_policy
        app.state.metrics = metrics
        app.state.drift_detector = None
        app.state.breaker = breaker_obj
        app.state.started_at = 0.0
        yield

    monkeypatch.setattr(server_app, "_lifespan", stub_lifespan)
    return server_app.create_app()


# --------------------------------------------------------------------------- #
# /healthz                                                                    #
# --------------------------------------------------------------------------- #


def test_healthz_is_live_unconditionally(monkeypatch):
    """Even if the index is broken, /healthz remains 200 (liveness, not readiness)."""
    idx = _StubAsyncIndex(verify_exc=ConnectionRefusedError("dead"))
    app = _build_app(monkeypatch, index=idx)
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# --------------------------------------------------------------------------- #
# /readyz                                                                     #
# --------------------------------------------------------------------------- #


def test_readyz_returns_200_when_breaker_closed_and_index_reachable(monkeypatch):
    app = _build_app(monkeypatch)
    with TestClient(app) as client:
        resp = client.get("/readyz")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ready"
        assert body["breaker_state"] == "closed"


def test_readyz_returns_503_when_breaker_is_open(monkeypatch):
    breaker = CircuitBreaker(threshold=1, window_seconds=30, cooldown_seconds=30)
    breaker.record_failure()  # OPEN
    app = _build_app(monkeypatch, breaker=breaker)
    with TestClient(app) as client:
        resp = client.get("/readyz")
        assert resp.status_code == 503
        body = resp.json()
        assert body["detail"]["error"] == "breaker_open"


def test_readyz_returns_503_when_index_sentinel_probe_fails(monkeypatch):
    idx = _StubAsyncIndex(verify_exc=ConnectionRefusedError("no pool"))
    app = _build_app(monkeypatch, index=idx)
    with TestClient(app) as client:
        resp = client.get("/readyz")
        assert resp.status_code == 503
        body = resp.json()
        assert body["detail"]["error"] == "index_unreachable"


# --------------------------------------------------------------------------- #
# /v1/verify with index unavailable                                           #
# --------------------------------------------------------------------------- #


def test_verify_returns_503_with_structured_body_in_block_mode(monkeypatch):
    """A verify call against a failing index in `block` mode (default)
    must return 503 with a structured error body."""
    idx = _StubAsyncIndex(batch_exc=ConnectionRefusedError("boom"))
    app = _build_app(monkeypatch, index=idx)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/verify",
            json={"chunks": ["hello world"]},
        )
        assert resp.status_code == 503
        body = resp.json()
        assert body["detail"]["error"] == "index_unavailable"
        assert body["detail"]["error_class"] == "connection"


def test_verify_returns_200_with_index_status_in_degrade_mode(monkeypatch):
    """A verify call against a failing index in `degrade` mode returns
    200 with a signed receipt carrying `index_status.available=false`."""
    idx = _StubAsyncIndex(batch_exc=ConnectionRefusedError("boom"))
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error="degrade"),
    )
    app = _build_app(monkeypatch, index=idx, policy=policy)
    with TestClient(app) as client:
        resp = client.post(
            "/v1/verify",
            json={"chunks": ["alpha", "beta"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        receipt = body["receipt"]
        assert receipt["index_status"] == {
            "available": False,
            "error_class": "connection",
        }
        # Every source got UNVERIFIED.
        for source in receipt["sources"]:
            assert source["verification_outcome"] == "UNVERIFIED"


def test_verify_metrics_count_index_error_and_degraded(monkeypatch):
    """Both `provenex_index_error_total` and `provenex_verify_degraded_total`
    should be visible on /metrics after a degraded verify call."""
    idx = _StubAsyncIndex(batch_exc=TimeoutError("slow query"))
    policy = Policy(
        verification=VerificationPolicy(block_unverified=False),
        availability=IndexAvailabilityPolicy(on_index_error="degrade"),
    )
    app = _build_app(monkeypatch, index=idx, policy=policy)
    with TestClient(app) as client:
        # Trigger one degraded verify.
        r1 = client.post("/v1/verify", json={"chunks": ["x"]})
        assert r1.status_code == 200
        body = client.get("/metrics").text
        assert 'provenex_verify_degraded_total{error_class="timeout"}' in body


def test_verify_metrics_count_index_error_in_block_mode(monkeypatch):
    """When the deployment is in block mode, `provenex_index_error_total`
    is incremented and `provenex_verify_degraded_total` is not."""
    idx = _StubAsyncIndex(batch_exc=ConnectionRefusedError("boom"))
    app = _build_app(monkeypatch, index=idx)  # default policy = block
    with TestClient(app) as client:
        r1 = client.post("/v1/verify", json={"chunks": ["x"]})
        assert r1.status_code == 503
        body = client.get("/metrics").text
        assert 'provenex_index_error_total{error_class="connection"}' in body
        assert "provenex_verify_degraded_total" not in body
