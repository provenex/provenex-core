"""Google Cloud KMS adapter for the Provenex receipt signer.

GCP KMS supports Ed25519 asymmetric keys natively (key algorithm
``EC_SIGN_ED25519``) plus a range of RSA signing algorithms. The
adapter wraps ``projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.asymmetricSign``
so the private key never leaves GCP KMS.

Install
-------
``pip install "provenex-core[kms-gcp]"``

Usage
-----

    from provenex.kms.gcp import GcpKmsSigner

    signer = GcpKmsSigner(
        key_version="projects/X/locations/global/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1",
    )

Algorithm choice
----------------

The adapter inspects the CryptoKeyVersion's ``algorithm`` field and
picks the matching shape:

* ``EC_SIGN_ED25519`` → ``signature.algorithm = "ed25519"``
* ``RSA_SIGN_PSS_2048_SHA256`` / ``RSA_SIGN_PSS_3072_SHA256`` /
  ``RSA_SIGN_PSS_4096_SHA256`` → ``signature.algorithm = "rsa-pss-sha256"``
* Anything else → ``KMSConfigurationError`` (unsupported by the
  Provenex receipt verifier today).
"""

from __future__ import annotations

import base64
import hashlib
from typing import Optional

from ..core.receipt import ReceiptSigner
from .common import (
    ALGORITHM_ED25519,
    ALGORITHM_RSA_PSS_SHA256,
    KMSConfigurationError,
)


def _require_gcp():
    try:
        from google.cloud import kms  # noqa: F401
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "GcpKmsSigner requires the 'kms-gcp' extra. "
            'Install with: pip install "provenex-core[kms-gcp]"'
        ) from exc


class GcpKmsSigner(ReceiptSigner):
    """Receipt signer backed by a GCP KMS asymmetric CryptoKeyVersion.

    Args:
        key_version: Full resource name of the CryptoKeyVersion.
        client: Optional pre-built ``kms_v1.KeyManagementServiceClient``.

    Raises:
        KMSConfigurationError: If the key version's algorithm is not
            one the Provenex receipt verifier supports.
    """

    def __init__(
        self,
        key_version: str,
        *,
        client=None,
    ) -> None:
        _require_gcp()
        from google.cloud import kms

        self._key_version = key_version
        self._client = client if client is not None else kms.KeyManagementServiceClient()

        version = self._client.get_crypto_key_version(name=key_version)
        algo = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm(version.algorithm)
        self._gcp_algorithm = algo

        if algo == kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519:
            self._receipt_algorithm = ALGORITHM_ED25519
        elif algo in (
            kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256,
            kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256,
            kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256,
        ):
            self._receipt_algorithm = ALGORITHM_RSA_PSS_SHA256
        else:
            raise KMSConfigurationError(
                f"GCP KMS key version algorithm {algo!r} is not supported. "
                "Use EC_SIGN_ED25519 (preferred) or RSA_SIGN_PSS_*_SHA256."
            )

        # Cache the public key PEM (auditor-friendly format).
        pub = self._client.get_public_key(name=key_version)
        self._public_key_pem = pub.pem.encode("ascii")

    @property
    def algorithm(self) -> str:
        return self._receipt_algorithm

    def public_key_pem(self) -> bytes:
        return self._public_key_pem

    def sign(self, payload: bytes) -> str:
        from google.cloud import kms

        # For RSA PSS, GCP KMS requires a pre-computed digest; for
        # Ed25519 the API takes the raw message.
        if self._receipt_algorithm == ALGORITHM_ED25519:
            request = {"name": self._key_version, "data": payload}
        else:
            digest = hashlib.sha256(payload).digest()
            request = {
                "name": self._key_version,
                "digest": {"sha256": digest},
            }
        resp = self._client.asymmetric_sign(request=request)
        return base64.b64encode(resp.signature).decode("ascii")

    def verify(self, payload: bytes, signature: str) -> bool:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519, padding
        except ImportError as exc:  # pragma: no cover - import guard
            raise ImportError(
                "GcpKmsSigner.verify requires the 'cryptography' package."
            ) from exc

        try:
            sig_bytes = base64.b64decode(signature.encode("ascii"))
        except Exception:
            return False
        pub = serialization.load_pem_public_key(self._public_key_pem)
        try:
            if self._receipt_algorithm == ALGORITHM_ED25519:
                if not isinstance(pub, ed25519.Ed25519PublicKey):
                    return False
                pub.verify(sig_bytes, payload)
                return True
            else:
                pub.verify(
                    sig_bytes,
                    payload,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True
        except Exception:
            return False
