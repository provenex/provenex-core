"""AWS KMS adapter for the Provenex receipt signer.

Wraps ``kms:Sign`` so the signing key never leaves AWS KMS. The public
key is fetched once at construction and used for verify; the signing
key spec on the AWS side determines which algorithm is recorded on the
receipt.

Install
-------
``pip install "provenex-core[kms-aws]"``

Usage
-----

    from provenex.kms.aws import AwsKmsSigner

    signer = AwsKmsSigner(
        key_id="arn:aws:kms:us-east-1:111111111111:key/abc...",
        # Optional: explicit boto3 client; defaults to the ambient one.
    )

    receipt = builder.finalize(..., signer=signer)

Algorithm choice
----------------

The adapter today ships RSASSA-PSS-SHA256 only, because RSA-PSS is the
algorithm the Provenex offline receipt verifier covers end-to-end and
the one moto's KMS mock exercises in CI. The behaviour:

* Key spec ``RSA_*`` (RSA_3072 / RSA_4096 recommended for the 7-year
  retention horizon) → uses ``RSASSA_PSS_SHA_256`` and stamps
  ``signature.algorithm = "rsa-pss-sha256"`` on the receipt.
* Any other key spec → :class:`KMSConfigurationError`. Pass
  ``signing_algorithm=`` explicitly if you have a verifier path for
  another algorithm; the receipt will record whatever string the
  override produces.

Check the current AWS KMS asymmetric-key-spec docs for any Ed25519
support in your region; if AWS adds it, set ``signing_algorithm=`` and
extend :meth:`verify` to dispatch on the new algorithm.
"""

from __future__ import annotations

import base64
from typing import Optional

from ..core.receipt import ReceiptSigner
from .common import (
    ALGORITHM_RSA_PSS_SHA256,
    KMSConfigurationError,
)


def _require_boto3():
    try:
        import boto3  # noqa: F401
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "AwsKmsSigner requires the 'kms-aws' extra. "
            'Install with: pip install "provenex-core[kms-aws]"'
        ) from exc


class AwsKmsSigner(ReceiptSigner):
    """Receipt signer backed by an AWS KMS asymmetric key.

    Args:
        key_id: AWS KMS key ID / ARN / alias. The IAM role this process
            runs under must have ``kms:Sign`` and ``kms:GetPublicKey``
            on this key.
        client: Optional boto3 ``kms`` client. Falls back to
            ``boto3.client("kms")`` with the default credential chain.
        signing_algorithm: Optional override. By default the adapter
            chooses based on ``KeySpec``: RSA → ``RSASSA_PSS_SHA_256``.
            If your key spec doesn't map to a supported algorithm the
            adapter raises ``KMSConfigurationError``.

    Raises:
        KMSConfigurationError: If the KMS key's spec is not one the
            Provenex receipt verifier knows how to verify offline.
    """

    def __init__(
        self,
        key_id: str,
        *,
        client=None,
        signing_algorithm: Optional[str] = None,
    ) -> None:
        _require_boto3()
        import boto3

        self._key_id = key_id
        self._client = client if client is not None else boto3.client("kms")

        meta = self._client.describe_key(KeyId=key_id)["KeyMetadata"]
        key_spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")
        if key_spec is None:
            raise KMSConfigurationError(
                f"AWS KMS key {key_id!r} has no KeySpec; is it a symmetric key?"
            )
        usage = meta.get("KeyUsage")
        if usage != "SIGN_VERIFY":
            raise KMSConfigurationError(
                f"AWS KMS key {key_id!r} KeyUsage is {usage!r}; expected SIGN_VERIFY."
            )

        if signing_algorithm is not None:
            chosen = signing_algorithm
        elif key_spec.startswith("RSA_"):
            chosen = "RSASSA_PSS_SHA_256"
        else:
            raise KMSConfigurationError(
                f"AWS KMS key spec {key_spec!r} is not supported by the "
                "Provenex receipt verifier today. Use an RSA_3072 or "
                "RSA_4096 key (RSASSA-PSS-SHA256), or pass "
                "signing_algorithm= explicitly if you know the verifier "
                "supports your choice."
            )
        self._signing_algorithm = chosen

        if chosen == "RSASSA_PSS_SHA_256":
            self._receipt_algorithm = ALGORITHM_RSA_PSS_SHA256
        else:
            self._receipt_algorithm = chosen.lower().replace("_", "-")

        # Cache the public key so verify() doesn't fan out to KMS.
        pub = self._client.get_public_key(KeyId=key_id)
        self._public_key_der = pub["PublicKey"]  # SubjectPublicKeyInfo DER

    @property
    def algorithm(self) -> str:
        return self._receipt_algorithm

    @property
    def public_key_der(self) -> bytes:
        """Return the PEM-derived SPKI DER for the verifier."""
        return self._public_key_der

    def public_key_pem(self) -> bytes:
        """Return the PEM-encoded public key (auditor-friendly format)."""
        b64 = base64.encodebytes(self._public_key_der).decode("ascii")
        return (
            b"-----BEGIN PUBLIC KEY-----\n"
            + b64.encode("ascii")
            + b"-----END PUBLIC KEY-----\n"
        )

    def sign(self, payload: bytes) -> str:
        resp = self._client.sign(
            KeyId=self._key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm=self._signing_algorithm,
        )
        return base64.b64encode(resp["Signature"]).decode("ascii")

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify using the cached public key, no KMS round-trip.

        Verification happens entirely off the KMS hot path so auditors
        and the verify pods don't pay an AWS API call per receipt.
        """
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError as exc:  # pragma: no cover - import guard
            raise ImportError(
                "AwsKmsSigner.verify requires the 'cryptography' package "
                '(installed as a transitive dep of kms-aws extras).'
            ) from exc

        try:
            sig_bytes = base64.b64decode(signature.encode("ascii"))
        except Exception:
            return False
        pub = serialization.load_der_public_key(self._public_key_der)
        try:
            if self._signing_algorithm == "RSASSA_PSS_SHA_256":
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
            return False
        except Exception:
            return False
