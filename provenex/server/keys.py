"""Load the receipt signer from environment.

Resolution order:

    1. ``PROVENEX_RECEIPT_PRIVATE_KEY_FILE``: file path to a PEM-encoded
       Ed25519 private key. Produces an :class:`Ed25519Signer`. Highest
       priority because asymmetric keys are the production default
       (public key alone can verify; the signing key never leaves the
       host).

    2. ``PROVENEX_RECEIPT_SECRET``: HMAC shared secret (string or
       hex-encoded bytes). Produces an :class:`HmacSha256Signer`.
       Acceptable for single-tenant deployments where the same secret
       is shared between issuer and verifier.

If neither is set, :func:`load_receipt_signer` returns ``None`` and the
server refuses to start (an unsigned receipt is meaningless for the
non-repudiation property).

The server never embeds the secret in code, container images, or its
own state. The env-var indirection means rotation is a process
restart and the key bytes live only in the runtime memory of a
running pod.
"""

from __future__ import annotations

import os
from typing import Optional

from ..core.receipt import HmacSha256Signer, ReceiptSigner


def load_receipt_signer() -> Optional[ReceiptSigner]:
    """Return a :class:`ReceiptSigner` resolved from env, or ``None``."""
    key_file = os.environ.get("PROVENEX_RECEIPT_PRIVATE_KEY_FILE")
    if key_file:
        from ..core.ed25519 import Ed25519Signer

        with open(key_file, "rb") as f:
            pem = f.read()
        return Ed25519Signer.from_private_key_pem(pem)

    secret = os.environ.get("PROVENEX_RECEIPT_SECRET")
    if secret:
        return HmacSha256Signer(secret=secret.encode("utf-8"))

    return None


def load_index_secret() -> Optional[bytes]:
    """Return the index HMAC secret from env, or ``None`` if unset.

    ``PROVENEX_SIGNING_SECRET`` (the same env var the sync backend uses)
    is the canonical name. The async index will fall back to this var
    too if ``signing_secret=`` isn't passed.
    """
    raw = os.environ.get("PROVENEX_SIGNING_SECRET")
    if raw is None:
        return None
    return raw.encode("utf-8")
