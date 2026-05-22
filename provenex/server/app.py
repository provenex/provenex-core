"""FastAPI app factory + dependency wiring for the Provenex HTTP server.

The server is a thin wrapper over the OSS core. Each route delegates to
the relevant in-process function (`verify_chunks_async`,
`admission_check`, `admit_memory_write`, `admit_model_inference`, or
the async index's `add_async`); the receipt format on the wire is the
same one the SDK emits in-process.

State is held on ``app.state``:

    * ``app.state.index``  - the AsyncPostgresProvenanceIndex.
    * ``app.state.signer`` - the receipt signer (HMAC or Ed25519).
    * ``app.state.policy`` - the optionally-loaded unified policy.
    * ``app.state.metrics`` - the in-process metrics store.

The async index pool is opened on startup and closed on shutdown; the
policy file (if any) is read once at startup.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

_logger = logging.getLogger("provenex.server")

from ..core.receipt import ProvenanceReceipt, ReceiptSigner
from ..core.signer_registry import SignerRegistry, TenantNotFound
from ..index.circuit import STATE_OPEN, CircuitBreaker
from ..policy.availability import IndexAvailabilityPolicy, IndexUnavailable
from .keys import load_index_secret, load_receipt_signer
from .metrics import Metrics
from .models import (
    AdmissionResponse,
    AdmitMemoryWriteRequest,
    AdmitModelInferenceRequest,
    AdmitToolRequest,
    IngestRequest,
    IngestResponse,
    VerifyRequest,
    VerifyResponse,
)


def _receipt_to_jsonable(receipt: ProvenanceReceipt) -> Dict[str, Any]:
    """Serialize a receipt to a plain JSON-friendly dict.

    ``ProvenanceReceipt`` exposes ``.to_dict()`` (the canonical wire
    shape). Clients verify the receipt offline with
    :func:`provenex.verify_receipt_signature`, which takes the dict
    directly; no special deserializer is required.
    """
    return receipt.to_dict()


def _build_request_context(body) -> Any:
    """Wire ``RequestContextBody`` into a :class:`RequestContext`."""
    from ..policy.evaluator import RequestContext

    return RequestContext(
        caller=dict(body.caller or {}),
        jurisdiction=body.jurisdiction,
        purpose=body.purpose,
        timestamp=body.timestamp,
        session_id=body.session_id,
    )


def _load_policy() -> Optional[Any]:
    """Load the optional unified policy from ``PROVENEX_POLICY_FILE``."""
    path = os.environ.get("PROVENEX_POLICY_FILE")
    if not path:
        return None
    from ..policy.unified import Policy

    return Policy.from_yaml(path)


def _load_tenant_registry() -> Optional[SignerRegistry]:
    """Load the multi-tenant signer registry from PROVENEX_TENANTS_FILE.

    File format (YAML)::

        tenants:
          tenant-a:
            type: hmac
            secret: aaaaaaaaaa
          tenant-b:
            type: ed25519
            private_key_pem: |
              -----BEGIN PRIVATE KEY-----
              ...
              -----END PRIVATE KEY-----

    KMS-backed signers are not constructed by this loader because they
    need credentials / clients the file does not carry. Production
    multi-tenant deployments wire the registry up in code at server
    startup; this loader covers the simpler shared-secret and Ed25519
    paths.
    """
    path = os.environ.get("PROVENEX_TENANTS_FILE")
    if not path:
        return None
    import yaml

    from ..core.signer_registry import default_signer_factory, from_config_dict

    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    tenants = cfg.get("tenants") or {}
    return from_config_dict(tenants, default_signer_factory)


def _load_drift_detector():
    """Build an IndexDriftDetector from env, or None if disabled."""
    url = os.environ.get("PROVENEX_DRIFT_WEBHOOK_URL")
    if not url:
        return None
    from ..drift import IndexDriftDetector

    window = float(os.environ.get("PROVENEX_DRIFT_WINDOW_SECONDS", "300"))
    threshold = int(os.environ.get("PROVENEX_DRIFT_MIN_DISTINCT", "1"))
    return IndexDriftDetector(
        webhook_url=url,
        window_seconds=window,
        min_distinct_before_fire=threshold,
    )


def _resolve_signer(request: Request) -> ReceiptSigner:
    """Pick the signer for this request — tenant-aware when registry present.

    Lookup order:
        1. If the ``X-Provenex-Tenant`` header is set and a registry
           was loaded, look the tenant up there.
        2. Otherwise fall back to the process-wide signer (``app.state.signer``).

    Raises:
        HTTPException 400 if the header is set but the registry is
            not loaded (configuration mismatch).
        HTTPException 404 if the tenant is set but not registered.
        HTTPException 503 if neither a registry nor a default signer
            is configured (server misconfiguration).
    """
    tenant = request.headers.get("X-Provenex-Tenant")
    registry: Optional[SignerRegistry] = request.app.state.tenant_registry
    if tenant:
        if registry is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "X-Provenex-Tenant header set but PROVENEX_TENANTS_FILE "
                    "is not configured on this server."
                ),
            )
        try:
            return registry.get(tenant)
        except TenantNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    fallback: Optional[ReceiptSigner] = request.app.state.signer
    if fallback is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Multi-tenant mode requires X-Provenex-Tenant on every request; "
                "no default signer is configured."
            ),
        )
    return fallback


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    from ..index.async_postgres_index import AsyncPostgresProvenanceIndex

    dsn = os.environ.get("PROVENEX_DATABASE_DSN")
    if not dsn:
        raise RuntimeError(
            "Provenex server: set PROVENEX_DATABASE_DSN to a Postgres DSN."
        )

    index_secret = load_index_secret()
    signer = load_receipt_signer()
    tenant_registry = _load_tenant_registry()
    if signer is None and tenant_registry is None:
        raise RuntimeError(
            "Provenex server: set PROVENEX_RECEIPT_PRIVATE_KEY_FILE "
            "(Ed25519 PEM), PROVENEX_RECEIPT_SECRET (HMAC bytes), or "
            "PROVENEX_TENANTS_FILE (multi-tenant registry). The server "
            "refuses to emit unsigned receipts."
        )

    policy = _load_policy()
    metrics = Metrics()
    index = AsyncPostgresProvenanceIndex(
        dsn=dsn,
        signing_secret=index_secret,
        min_size=int(os.environ.get("PROVENEX_POOL_MIN", "1")),
        max_size=int(os.environ.get("PROVENEX_POOL_MAX", "10")),
    )
    await index.open_async()

    # One process-wide circuit breaker guards the verify hot path
    # against the provenance index. Threshold / window / cooldown are
    # taken from the loaded policy's availability block when present,
    # or from the IndexAvailabilityPolicy defaults otherwise. Per
    # replica: a breaker that learned one replica's pool was sick
    # should not also freeze a healthy replica.
    availability = (
        policy.availability
        if policy is not None
        else IndexAvailabilityPolicy()
    )
    breaker = CircuitBreaker(
        threshold=availability.breaker_threshold,
        window_seconds=availability.breaker_window_seconds,
        cooldown_seconds=availability.breaker_cooldown_seconds,
    )

    app.state.index = index
    app.state.signer = signer
    app.state.tenant_registry = tenant_registry
    app.state.policy = policy
    app.state.metrics = metrics
    app.state.drift_detector = _load_drift_detector()
    app.state.breaker = breaker
    app.state.started_at = time.time()
    try:
        yield
    finally:
        await index.close_async()


def create_app() -> FastAPI:
    """FastAPI app factory.

    Run with::

        uvicorn provenex.server.app:create_app --factory
    """
    app = FastAPI(
        title="Provenex",
        version=__import__("provenex").__version__,
        description=(
            "Provenex HTTP API. Returns signed provenance receipts for "
            "retrieval, tool-call admission, memory writes, and model "
            "inference admission. Any language with SHA-256 + HMAC or "
            "Ed25519 can verify the receipts offline using only the "
            "public key (or shared HMAC secret)."
        ),
        lifespan=_lifespan,
    )

    # ----------------------------------------------------------------- verify

    @app.post(
        "/v1/verify",
        response_model=VerifyResponse,
        tags=["verify"],
        summary="Verify retrieved chunks; emit a signed receipt.",
        responses={
            503: {
                "description": (
                    "Provenance index unavailable and the operator chose "
                    "`on_index_error=block`. The response body carries "
                    "`{error: 'index_unavailable', error_class: "
                    "'timeout'|'connection'|'breaker_open'|'other', "
                    "message: '...'}`."
                ),
            },
        },
    )
    async def verify(body: VerifyRequest, request: Request) -> VerifyResponse:
        from ..core.verify import verify_chunks_async

        idx = request.app.state.index
        signer = _resolve_signer(request)
        policy = request.app.state.policy
        metrics: Metrics = request.app.state.metrics
        breaker: CircuitBreaker = request.app.state.breaker

        request_context = (
            _build_request_context(body.request) if body.request is not None else None
        )

        t0 = time.perf_counter()
        try:
            result = await verify_chunks_async(
                chunks=body.chunks,
                index=idx,
                signer=signer,
                policy=policy,
                request_text=body.request_text,
                request_context=request_context,
                output_text=body.output_text,
                breaker=breaker,
            )
        except IndexUnavailable as exc:
            metrics.incr(
                "provenex_index_error_total",
                {"error_class": exc.error_class},
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "index_unavailable",
                    "error_class": exc.error_class,
                    "message": str(exc),
                },
            ) from exc
        finally:
            metrics.observe_verify_latency(time.perf_counter() - t0)
        metrics.incr("provenex_verify_total")
        # Degraded-receipt counter: the verify call ran in
        # ``degrade`` mode and the index was actually unavailable.
        # Distinguish from the all-UNVERIFIED happy-path case where
        # the chunks were genuinely not in the index.
        if result.receipt.index_status is not None:
            metrics.incr(
                "provenex_verify_degraded_total",
                {
                    "error_class": result.receipt.index_status.get(
                        "error_class", "other"
                    )
                },
            )
        drift = request.app.state.drift_detector
        for s in result.receipt.sources:
            metrics.incr(
                "provenex_verify_source_total",
                {"outcome": s.verification_outcome},
            )
            if drift is not None and s.verification_outcome == "UNVERIFIED":
                drift.record(s.fingerprint)
        return VerifyResponse(
            kept=result.kept,
            blocked=result.blocked,
            receipt=_receipt_to_jsonable(result.receipt),
        )

    # ------------------------------------------------------------- admit/tool

    @app.post(
        "/v1/admit/tool",
        response_model=AdmissionResponse,
        tags=["admit"],
        summary="Admission-check a tool call; emit a signed receipt.",
    )
    async def admit_tool(
        body: AdmitToolRequest, request: Request
    ) -> AdmissionResponse:
        from ..tool_call import (
            ToolCallContext,
            admission_check,
        )

        tool = ToolCallContext(
            name=body.tool.name,
            operation=body.tool.operation,
            parameters=dict(body.tool.parameters),
            target_system=body.tool.target_system,
            invocation_id=body.tool.invocation_id,
        )
        rc = _build_request_context(body.request)
        signer = _resolve_signer(request)
        policy = request.app.state.policy
        metrics: Metrics = request.app.state.metrics

        # admission_check is synchronous and CPU-bound (no I/O); fine to
        # call directly from the async handler. If it ever grows
        # blocking deps we'll wrap in asyncio.to_thread.
        result = admission_check(
            tool=tool, request=rc, policy=policy, signer=signer,
            redact_parameters=body.redact_parameters,
            redact_inputs=body.redact_inputs,
        )
        metrics.incr(
            "provenex_admit_total",
            {"kind": "tool", "decision": result.decision},
        )
        return AdmissionResponse(
            decision=result.decision,
            rules_fired=list(result.rules_fired),
            receipt=_receipt_to_jsonable(result.receipt),
        )

    # ----------------------------------------------------- admit/memory_write

    @app.post(
        "/v1/admit/memory_write",
        response_model=AdmissionResponse,
        tags=["admit"],
        summary="Admission-check a memory write; emit a signed receipt.",
    )
    async def admit_memory_write(
        body: AdmitMemoryWriteRequest, request: Request
    ) -> AdmissionResponse:
        from ..tool_call import admit_memory_write as core_admit_memory_write

        rc = _build_request_context(body.request)
        signer = _resolve_signer(request)
        policy = request.app.state.policy
        metrics: Metrics = request.app.state.metrics

        result = core_admit_memory_write(
            memory_key=body.memory_key,
            value=body.value,
            request=rc,
            store_id=body.store_id,
            policy=policy,
            signer=signer,
        )
        metrics.incr(
            "provenex_admit_total",
            {"kind": "memory_write", "decision": result.decision},
        )
        return AdmissionResponse(
            decision=result.decision,
            rules_fired=list(result.rules_fired),
            receipt=_receipt_to_jsonable(result.receipt),
        )

    # ------------------------------------------------- admit/model_inference

    @app.post(
        "/v1/admit/model_inference",
        response_model=AdmissionResponse,
        tags=["admit"],
        summary="Admission-check a model inference call.",
    )
    async def admit_model_inference(
        body: AdmitModelInferenceRequest, request: Request
    ) -> AdmissionResponse:
        from ..tool_call import admit_model_inference as core_admit_model_inference

        rc = _build_request_context(body.request)
        signer = _resolve_signer(request)
        policy = request.app.state.policy
        metrics: Metrics = request.app.state.metrics

        result = core_admit_model_inference(
            model_name=body.model_name,
            prompt=body.prompt,
            request=rc,
            target_provider=body.target_provider,
            policy=policy,
            signer=signer,
        )
        metrics.incr(
            "provenex_admit_total",
            {"kind": "model_inference", "decision": result.decision},
        )
        return AdmissionResponse(
            decision=result.decision,
            rules_fired=list(result.rules_fired),
            receipt=_receipt_to_jsonable(result.receipt),
        )

    # ----------------------------------------------------------------- ingest

    @app.post(
        "/v1/ingest",
        response_model=IngestResponse,
        tags=["ingest"],
        summary="Bulk-ingest fingerprints into the Postgres index.",
    )
    async def ingest(body: IngestRequest, request: Request) -> IngestResponse:
        idx = request.app.state.index
        metrics: Metrics = request.app.state.metrics
        for entry in body.entries:
            await idx.add_async(
                fingerprint=entry.fingerprint,
                document_id=entry.document_id,
                document_version=entry.document_version,
                chunk_offset=entry.chunk_offset,
                chunk_length=entry.chunk_length,
                authorized=entry.authorized,
                entry_kind=entry.entry_kind,
            )
            metrics.incr("provenex_ingest_total")
        return IngestResponse(ingested=len(body.entries))

    # ----------------------------------------------------------------- health

    @app.get("/healthz", tags=["health"], summary="Liveness probe.")
    async def healthz() -> JSONResponse:
        """Liveness: the process is up and running.

        Does NOT consult the index. Use ``/readyz`` to check whether
        this replica can currently issue VERIFIED receipts.
        """
        return JSONResponse({"status": "ok"})

    @app.get(
        "/readyz",
        tags=["health"],
        summary="Readiness probe: can this replica issue VERIFIED receipts now?",
        responses={
            503: {
                "description": (
                    "Not ready. Response body carries "
                    "`{error: 'breaker_open'|'index_unreachable', "
                    "message: '...'}`."
                ),
            },
        },
    )
    async def readyz(request: Request) -> JSONResponse:
        """Readiness: the index is reachable AND the circuit breaker
        is closed.

        A replica that returns 200 here is ready to serve a verify
        request whose receipt may carry a VERIFIED outcome. A replica
        whose breaker is OPEN is still alive (``/healthz`` returns
        200) and may still serve verify requests in
        ``on_index_error=degrade`` mode, but every receipt it issues
        right now will be degraded. The distinction matters to a
        load balancer or k8s controller that wants to route traffic
        away from a replica that can't see the index.

        Returns 503 with a structured detail when not ready.
        """
        idx = request.app.state.index
        breaker: CircuitBreaker = request.app.state.breaker
        if breaker.state == STATE_OPEN:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "breaker_open",
                    "message": (
                        "circuit breaker is OPEN; this replica cannot "
                        "issue VERIFIED receipts until the cooldown elapses"
                    ),
                },
            )
        try:
            # Sentinel verify: lookup a known-absent fingerprint to
            # confirm the Postgres pool can serve a query.
            await idx.verify_async(
                "sha256:" + "0" * 64
            )
        except Exception as exc:  # pragma: no cover - probe error path
            # Log the underlying exception (the operator needs the
            # detail to diagnose) but do not leak driver-level text
            # (DSN fragments, host:port, SQL state) into the HTTP
            # response, which is scraped by probers and proxied through
            # load balancers.
            _logger.warning(
                "readyz: index probe failed (exc_type=%s)",
                type(exc).__name__,
                exc_info=True,
            )
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "index_unreachable",
                    "message": (
                        "index probe failed; see server logs for "
                        "exception detail"
                    ),
                },
            )
        return JSONResponse(
            {"status": "ready", "breaker_state": breaker.state}
        )

    @app.get("/metrics", tags=["health"], summary="Prometheus metrics.")
    async def metrics(request: Request) -> Response:
        body = request.app.state.metrics.render()
        return PlainTextResponse(
            body, media_type="text/plain; version=0.0.4; charset=utf-8"
        )

    return app
