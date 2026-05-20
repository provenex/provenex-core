"""Azure Key Vault adapter for the Provenex receipt signer.

Azure Key Vault has not GA'd Ed25519 as of the matrix in
``provenex/kms/__init__.py``. RSASSA-PSS-SHA256 over an RSA key is the
production-grade path; the adapter uses that.

Install
-------
``pip install "provenex-core[kms-azure]"``

Usage
-----

    from provenex.kms.azure import AzureKeyVaultSigner

    signer = AzureKeyVaultSigner(
        vault_url="https://my-vault.vault.azure.net/",
        key_name="provenex-receipt-key",
    )

Algorithm choice
----------------

* RSA key, signing algorithm ``PS256`` → recorded as
  ``"rsa-pss-sha256"`` on the receipt.
* EC key, ``ES256`` → not currently supported by the Provenex receipt
  verifier (raises ``KMSConfigurationError``); future work.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Optional

from ..core.receipt import ReceiptSigner
from .common import (
    ALGORITHM_RSA_PSS_SHA256,
    KMSConfigurationError,
)


def _require_azure():
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401
        from azure.keyvault.keys import KeyClient  # noqa: F401
        from azure.keyvault.keys.crypto import (  # noqa: F401
            CryptographyClient,
            SignatureAlgorithm,
        )
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "AzureKeyVaultSigner requires the 'kms-azure' extra. "
            'Install with: pip install "provenex-core[kms-azure]"'
        ) from exc


class AzureKeyVaultSigner(ReceiptSigner):
    """Receipt signer backed by an Azure Key Vault RSA key (PS256).

    Args:
        vault_url: HTTPS URL of the vault, e.g.
            ``"https://my-vault.vault.azure.net/"``.
        key_name: Name of the key inside the vault.
        key_version: Optional explicit version; defaults to the
            current version.
        credential: Optional Azure credential. Defaults to
            ``DefaultAzureCredential()`` (Workload Identity, Managed
            Identity, env vars, Azure CLI, etc.).
    """

    def __init__(
        self,
        vault_url: str,
        key_name: str,
        *,
        key_version: Optional[str] = None,
        credential=None,
    ) -> None:
        _require_azure()
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.keys.crypto import (
            CryptographyClient,
            SignatureAlgorithm,
        )

        cred = credential if credential is not None else DefaultAzureCredential()
        kc = KeyClient(vault_url=vault_url, credential=cred)
        if key_version is None:
            key = kc.get_key(key_name)
        else:
            key = kc.get_key(key_name, version=key_version)

        if key.key_type not in ("RSA", "RSA-HSM"):
            raise KMSConfigurationError(
                f"Azure Key Vault key {key_name!r} is type {key.key_type}; "
                "only RSA / RSA-HSM keys are supported today."
            )

        self._crypto = CryptographyClient(key, credential=cred)
        self._sig_algo = SignatureAlgorithm.ps256
        self._receipt_algorithm = ALGORITHM_RSA_PSS_SHA256
        # Public key DER for verify(). Build SubjectPublicKeyInfo from
        # the JWK n/e the SDK returned.
        self._jwk = key.key

    @property
    def algorithm(self) -> str:
        return self._receipt_algorithm

    def sign(self, payload: bytes) -> str:
        digest = hashlib.sha256(payload).digest()
        result = self._crypto.sign(self._sig_algo, digest)
        return base64.b64encode(result.signature).decode("ascii")

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            sig_bytes = base64.b64decode(signature.encode("ascii"))
        except Exception:
            return False
        digest = hashlib.sha256(payload).digest()
        try:
            result = self._crypto.verify(self._sig_algo, digest, sig_bytes)
            return bool(result.is_valid)
        except Exception:
            return False
