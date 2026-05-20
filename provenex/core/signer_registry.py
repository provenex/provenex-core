"""Multi-tenant signer registry.

A :class:`SignerRegistry` maps a ``tenant_id`` to its
:class:`ReceiptSigner`. The HTTP server consults the registry on
each request via the ``X-Provenex-Tenant`` header and signs with the
matching signer. A receipt issued under tenant A does NOT verify under
tenant B's public key — that's the isolation guarantee.

The registry is intentionally tiny: just a thread-safe dict with
``register`` / ``unregister`` / ``get``. Construction from a config
file (YAML or JSON) lives in :func:`from_config_dict`; production
deployments typically build the registry once at server startup from
an external secret-management system.

The OSS core has no opinion on how tenant identity is established
(JWT claim, header, mTLS subject, etc.); the registry's only job is
the ``tenant_id`` → ``signer`` lookup.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Iterable, Optional

from .receipt import ReceiptSigner


class TenantNotFound(KeyError):
    """Raised when a tenant_id is not registered."""


class SignerRegistry:
    """Thread-safe ``tenant_id -> ReceiptSigner`` registry.

    The registry does NOT own the signer's key material; signers are
    constructed externally (HMAC, Ed25519, AwsKmsSigner, etc.) and
    registered here. Removing a tenant via :meth:`unregister` does
    not call any cleanup on the signer.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._signers: Dict[str, ReceiptSigner] = {}

    def register(self, tenant_id: str, signer: ReceiptSigner) -> None:
        """Add or replace the signer for ``tenant_id``.

        Re-registering the same tenant_id replaces the existing signer
        (key rotation flow: build the new signer, register it under
        the same tenant_id, the next request signs with the new key).
        """
        if not tenant_id:
            raise ValueError("tenant_id must be a non-empty string")
        with self._lock:
            self._signers[tenant_id] = signer

    def unregister(self, tenant_id: str) -> None:
        """Remove ``tenant_id``. Idempotent: a missing tenant is a no-op."""
        with self._lock:
            self._signers.pop(tenant_id, None)

    def get(self, tenant_id: str) -> ReceiptSigner:
        """Look up the signer for ``tenant_id``.

        Raises:
            TenantNotFound: If ``tenant_id`` is not registered.
        """
        with self._lock:
            try:
                return self._signers[tenant_id]
            except KeyError:
                raise TenantNotFound(
                    f"Tenant {tenant_id!r} is not registered."
                )

    def tenants(self) -> Iterable[str]:
        """Return a snapshot of registered tenant IDs."""
        with self._lock:
            return tuple(self._signers.keys())

    def __contains__(self, tenant_id: object) -> bool:
        with self._lock:
            return tenant_id in self._signers

    def __len__(self) -> int:
        with self._lock:
            return len(self._signers)


def from_config_dict(
    config: Dict[str, Dict[str, Any]],
    signer_factory: Callable[[str, Dict[str, Any]], ReceiptSigner],
) -> SignerRegistry:
    """Build a registry from a ``{tenant_id: signer_config}`` mapping.

    Args:
        config: Mapping where each value is a signer config dict. The
            shape of the dict is opaque to the registry; the factory
            interprets it.
        signer_factory: Callable ``(tenant_id, signer_config) -> ReceiptSigner``.
            Typical implementations switch on ``signer_config["type"]``
            (``"hmac"``, ``"ed25519"``, ``"aws-kms"``, ...).

    Returns:
        A populated :class:`SignerRegistry`.
    """
    registry = SignerRegistry()
    for tenant_id, signer_config in config.items():
        registry.register(tenant_id, signer_factory(tenant_id, signer_config))
    return registry


def default_signer_factory(
    tenant_id: str, signer_config: Dict[str, Any]
) -> ReceiptSigner:
    """Built-in factory covering the OSS signer types.

    Recognised ``signer_config["type"]`` values:

        * ``"hmac"``: requires ``secret`` (str). Builds an
          :class:`HmacSha256Signer`.
        * ``"ed25519"``: requires ``private_key_pem`` (str, the PEM
          bytes as text). Builds an :class:`Ed25519Signer`.

    KMS-backed signers are constructed by the deployment-side factory
    because they need credentials / boto3 clients that aren't
    universally available; this default covers the simplest two cases.
    """
    from .receipt import HmacSha256Signer

    kind = signer_config.get("type")
    if kind == "hmac":
        secret = signer_config["secret"]
        return HmacSha256Signer(secret=secret.encode("utf-8") if isinstance(secret, str) else secret)
    if kind == "ed25519":
        from .ed25519 import Ed25519Signer

        pem = signer_config["private_key_pem"]
        if isinstance(pem, str):
            pem = pem.encode("utf-8")
        return Ed25519Signer.from_private_key_pem(pem)
    raise ValueError(
        f"Unknown signer type {kind!r} for tenant {tenant_id!r}; "
        "supported: 'hmac', 'ed25519'."
    )
