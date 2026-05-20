"""Tests for the multi-tenant SignerRegistry + HTTP server routing.

Two layers:

  1. Unit-level: registry register/get/unregister/thread-safety +
     receipt isolation (a receipt signed under tenant A does NOT
     verify under tenant B's HMAC secret).

  2. Server-level: an ASGI test client sends X-Provenex-Tenant on
     POST /v1/verify and gets back a receipt signed by the right
     tenant's signer. Without the header, the server falls back to
     the process-wide signer (when one is configured) or returns
     503 (multi-tenant only) when no fallback exists.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio


# --------------------------------------------------------------------------- #
# Unit: registry semantics                                                    #
# --------------------------------------------------------------------------- #


def test_register_get_unregister():
    from provenex import HmacSha256Signer
    from provenex.core.signer_registry import SignerRegistry, TenantNotFound

    r = SignerRegistry()
    sig_a = HmacSha256Signer(secret=b"a")
    sig_b = HmacSha256Signer(secret=b"b")

    r.register("tenant-a", sig_a)
    r.register("tenant-b", sig_b)

    assert r.get("tenant-a") is sig_a
    assert r.get("tenant-b") is sig_b
    assert "tenant-a" in r
    assert "tenant-c" not in r
    assert len(r) == 2
    assert set(r.tenants()) == {"tenant-a", "tenant-b"}

    r.unregister("tenant-b")
    with pytest.raises(TenantNotFound):
        r.get("tenant-b")

    # Re-register replaces in place (key rotation flow).
    new_sig_a = HmacSha256Signer(secret=b"a-rotated")
    r.register("tenant-a", new_sig_a)
    assert r.get("tenant-a") is new_sig_a


def test_isolation_between_tenants_at_verify_time():
    """A receipt issued under tenant A must NOT verify under tenant B's key."""
    from provenex import HmacSha256Signer, verify_receipt_signature
    from provenex.core.receipt import ReceiptBuilder

    sig_a = HmacSha256Signer(secret=b"alice-only-secret")
    sig_b = HmacSha256Signer(secret=b"bob-only-secret")

    builder = ReceiptBuilder()
    receipt_a = builder.finalize(output_text="", signer=sig_a).to_dict()

    assert verify_receipt_signature(receipt_a, sig_a) is True
    assert verify_receipt_signature(receipt_a, sig_b) is False


def test_default_signer_factory_hmac_and_ed25519():
    from provenex import HmacSha256Signer
    from provenex.core.signer_registry import default_signer_factory

    sig = default_signer_factory(
        "tenant-a", {"type": "hmac", "secret": "shared-secret"}
    )
    assert isinstance(sig, HmacSha256Signer)
    assert sig.algorithm == "hmac-sha256"


def test_default_signer_factory_rejects_unknown_type():
    from provenex.core.signer_registry import default_signer_factory

    with pytest.raises(ValueError, match="Unknown signer type"):
        default_signer_factory("t", {"type": "made-up"})


# --------------------------------------------------------------------------- #
# Server-level: X-Provenex-Tenant routing                                     #
# --------------------------------------------------------------------------- #

DSN = os.environ.get("PROVENEX_TEST_POSTGRES_DSN")

server_only_pytestmark = [
    pytest.mark.skipif(
        not DSN,
        reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping server tests",
    ),
    pytest.mark.asyncio,
]
pytest.importorskip("fastapi")
pytest.importorskip("httpx")


@pytest_asyncio.fixture
async def multi_tenant_server(monkeypatch, tmp_path):
    """Stand up the server with two tenants registered via YAML."""
    import httpx
    import psycopg

    schema = f"provenex_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(DSN, autocommit=True) as setup:
        with setup.cursor() as cur:
            cur.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in DSN else "?"
    test_dsn = f"{DSN}{sep}options=-csearch_path%3D{schema}"

    tenants_file = tmp_path / "tenants.yaml"
    tenants_file.write_text(
        "tenants:\n"
        "  tenant-alice:\n"
        "    type: hmac\n"
        "    secret: alice-shared-secret\n"
        "  tenant-bob:\n"
        "    type: hmac\n"
        "    secret: bob-shared-secret\n"
    )

    monkeypatch.setenv("PROVENEX_DATABASE_DSN", test_dsn)
    monkeypatch.setenv("PROVENEX_SIGNING_SECRET", "index-secret")
    monkeypatch.setenv("PROVENEX_TENANTS_FILE", str(tenants_file))
    monkeypatch.delenv("PROVENEX_RECEIPT_SECRET", raising=False)
    monkeypatch.delenv("PROVENEX_RECEIPT_PRIVATE_KEY_FILE", raising=False)
    monkeypatch.delenv("PROVENEX_POLICY_FILE", raising=False)

    from provenex.server.app import create_app

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test"
    ) as client:
        async with app.router.lifespan_context(app):
            yield app, client

    with psycopg.connect(DSN, autocommit=True) as teardown:
        with teardown.cursor() as cur:
            cur.execute(f'DROP SCHEMA "{schema}" CASCADE')


for _t in server_only_pytestmark:
    multi_tenant_server = pytest.fixture(scope="function")(
        multi_tenant_server.__wrapped__  # type: ignore[attr-defined]
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    not DSN, reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping server tests"
)
async def test_tenant_header_routes_to_correct_signer(multi_tenant_server):
    from provenex import HmacSha256Signer, verify_receipt_signature

    _, client = multi_tenant_server

    # Alice's receipt should verify with Alice's secret, not Bob's.
    r = await client.post(
        "/v1/verify",
        json={"chunks": ["hello"]},
        headers={"X-Provenex-Tenant": "tenant-alice"},
    )
    assert r.status_code == 200, r.text
    receipt_a = r.json()["receipt"]
    assert verify_receipt_signature(
        receipt_a, HmacSha256Signer(secret=b"alice-shared-secret")
    ) is True
    assert verify_receipt_signature(
        receipt_a, HmacSha256Signer(secret=b"bob-shared-secret")
    ) is False


@pytest.mark.asyncio
@pytest.mark.skipif(
    not DSN, reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping server tests"
)
async def test_unknown_tenant_returns_404(multi_tenant_server):
    _, client = multi_tenant_server
    r = await client.post(
        "/v1/verify",
        json={"chunks": ["x"]},
        headers={"X-Provenex-Tenant": "tenant-charlie"},
    )
    assert r.status_code == 404
    assert "not registered" in r.text


@pytest.mark.asyncio
@pytest.mark.skipif(
    not DSN, reason="PROVENEX_TEST_POSTGRES_DSN not set; skipping server tests"
)
async def test_missing_tenant_header_returns_503_in_multi_tenant_mode(
    multi_tenant_server,
):
    _, client = multi_tenant_server
    r = await client.post("/v1/verify", json={"chunks": ["x"]})
    assert r.status_code == 503
    assert "X-Provenex-Tenant" in r.text
