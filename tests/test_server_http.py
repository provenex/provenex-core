"""End-to-end tests for the Provenex HTTP server.

Stands up the FastAPI app with a real ``AsyncPostgresProvenanceIndex``
behind it and exercises every public route via ``httpx``. Skipped
unless ``PROVENEX_TEST_POSTGRES_DSN`` is set AND ``fastapi`` is
installed (it's in the ``server`` extra).

Receipts emitted by the server are verified offline within the test
using only the public artefact (HMAC secret here for portability;
the Go example under ``examples/go_client/`` covers the Ed25519
public-key path).
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
import pytest_asyncio

DSN = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")

pytestmark = [
    pytest.mark.skipif(
        not DSN, reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping server tests"
    ),
    pytest.mark.asyncio,
]

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


RECEIPT_SECRET = "server-test-receipt-secret"
INDEX_SECRET = "server-test-index-secret"


def _fp(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _doc_version(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


@pytest_asyncio.fixture
async def server_client(monkeypatch):
    """Stand up the FastAPI app + ASGI httpx client + fresh pg schema."""
    import httpx
    import psycopg

    schema = f"provenex_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DSN, autocommit=True) as setup:
        with setup.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in DSN else "?"
    test_dsn = f"{DSN}{sep}options=-csearch_path%3D{schema}"

    monkeypatch.setenv("PROVENEX_DATABASE_DSN", test_dsn)
    monkeypatch.setenv("PROVENEX_SIGNING_SECRET", INDEX_SECRET)
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", RECEIPT_SECRET)
    # Make sure no Ed25519 key file is configured for the test.
    monkeypatch.delenv("PROVENEX_RECEIPT_PRIVATE_KEY_FILE", raising=False)
    monkeypatch.delenv("PROVENEX_POLICY_FILE", raising=False)

    from provenex.server.app import create_app

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        # Trigger lifespan startup explicitly: ASGITransport doesn't run
        # the lifespan protocol unless we ask for it. The simplest hook
        # is to use the lifespan context manager directly.
        async with app.router.lifespan_context(app):
            yield app, client, schema

    with psycopg.connect(DSN, autocommit=True) as teardown:
        with teardown.cursor() as cur:
            cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


# --------------------------------------------------------------------------- #
# /healthz, /readyz, /metrics                                                 #
# --------------------------------------------------------------------------- #


async def test_healthz(server_client):
    _, client, _ = server_client
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_readyz_against_open_pool(server_client):
    _, client, _ = server_client
    r = await client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


async def test_metrics_text_format(server_client):
    _, client, _ = server_client
    r = await client.get("/metrics")
    assert r.status_code == 200
    body = r.text
    assert "provenex_build_info" in body
    assert "provenex_uptime_seconds" in body
    assert "provenex_verify_latency_seconds_bucket" in body


# --------------------------------------------------------------------------- #
# /v1/ingest + /v1/verify (round-trip)                                        #
# --------------------------------------------------------------------------- #


async def test_ingest_then_verify_returns_signed_receipt(server_client):
    from provenex import HmacSha256Signer, verify_receipt_signature

    _, client, _ = server_client

    text = "hello provenex server"
    payload = {
        "entries": [
            {
                "fingerprint": _fp(text),
                "document_id": "doc-1",
                "document_version": _doc_version("doc-1"),
                "chunk_offset": 0,
                "chunk_length": len(text),
            }
        ]
    }
    r = await client.post("/v1/ingest", json=payload)
    assert r.status_code == 200, r.text
    assert r.json() == {"ingested": 1}

    r = await client.post(
        "/v1/verify",
        json={"chunks": [text], "request_text": "what is provenex?"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kept"] == [text]
    assert body["blocked"] == []

    # The receipt verifies offline with only the HMAC secret.
    signer = HmacSha256Signer(secret=RECEIPT_SECRET.encode("utf-8"))
    assert verify_receipt_signature(body["receipt"], signer) is True


async def test_verify_unverified_path(server_client):
    _, client, _ = server_client
    r = await client.post(
        "/v1/verify", json={"chunks": ["never indexed"]}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # Default verification policy keeps UNVERIFIED chunks (only blocks
    # UNAUTHORIZED + TAMPERED), but the outcome on the receipt is
    # still UNVERIFIED.
    outcomes = [s["verification_outcome"] for s in body["receipt"]["sources"]]
    assert outcomes == ["UNVERIFIED"]


# --------------------------------------------------------------------------- #
# /v1/admit/tool                                                              #
# --------------------------------------------------------------------------- #


async def test_admit_tool_default_allow(server_client):
    _, client, _ = server_client
    r = await client.post(
        "/v1/admit/tool",
        json={
            "tool": {
                "name": "search.web",
                "operation": "query",
                "parameters": {"q": "test"},
            },
            "request": {"caller": {"id": "user-1", "role": "analyst"}},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    # No tool_call_control policy configured; default allow.
    assert body["decision"] == "allow"
    assert "receipt" in body
    assert "actions" in body["receipt"]
    assert len(body["receipt"]["actions"]) == 1
    assert body["receipt"]["actions"][0]["name"] == "search.web"


# --------------------------------------------------------------------------- #
# /v1/admit/memory_write                                                      #
# --------------------------------------------------------------------------- #


async def test_admit_memory_write(server_client):
    _, client, _ = server_client
    r = await client.post(
        "/v1/admit/memory_write",
        json={
            "memory_key": "user_profile",
            "value": {"name": "Alice"},
            "store_id": "session-cache",
            "request": {"caller": {"id": "user-1"}},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "allow"
    assert body["receipt"]["actions"][0]["name"] == "memory.write"
    assert body["receipt"]["actions"][0]["operation"] == "user_profile"


# --------------------------------------------------------------------------- #
# /v1/admit/model_inference                                                   #
# --------------------------------------------------------------------------- #


async def test_admit_model_inference(server_client):
    _, client, _ = server_client
    r = await client.post(
        "/v1/admit/model_inference",
        json={
            "model_name": "claude-opus-4-7",
            "prompt": "Summarise this document.",
            "target_provider": "anthropic",
            "request": {"caller": {"id": "user-1"}},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "allow"
    assert body["receipt"]["actions"][0]["name"] == "claude-opus-4-7"
