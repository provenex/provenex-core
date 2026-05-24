"""HTTP server for Provenex (optional ``[server]`` extra).

A thin FastAPI wrapper around the OSS core. Exposes the verify,
admission, and ingest entry points behind ``/v1/...`` JSON routes
plus ``/healthz``, ``/readyz``, and ``/metrics`` for ops. The signing
key is loaded from environment variables; the server never embeds
secrets.

The server is the foundation of the sidecar-per-pod (Pattern B) and
centralized verify-service (Pattern C) deployment shapes documented
in ``docs/deployment_patterns.md``. Any non-Python client can hit
the HTTP API, get back a signed receipt, and verify it offline using
only the public key plus a SHA-256 + Ed25519 / HMAC implementation.

Install
-------
``pip install "provenex-core[server]"``

Run
---
::

    export PROVENEX_DATABASE_DSN="postgresql://..."
    export PROVENEX_SIGNING_SECRET="..."          # index HMAC
    export PROVENEX_RECEIPT_SECRET="..."          # receipt HMAC
    # or:
    # export PROVENEX_RECEIPT_PRIVATE_KEY_FILE=/run/secrets/ed25519.key
    export PROVENEX_POLICY_FILE=/etc/provenex/policy.yaml  # optional

    uvicorn provenex.server.app:create_app --factory \\
        --host 0.0.0.0 --port 8080
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .app import create_app

__all__ = ["create_app"]


def __getattr__(name: str) -> Any:
    if name == "create_app":
        from .app import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
