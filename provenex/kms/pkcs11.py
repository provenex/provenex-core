"""PKCS#11 adapter for the Provenex receipt signer.

Wraps a customer-owned HSM (Thales Luna, AWS CloudHSM, YubiHSM, SoftHSM,
etc.) via ``python-pkcs11``. The private key never leaves the token;
the adapter does ``C_Sign`` on the receipt payload and returns the
signature bytes.

Install
-------
``pip install "provenex-core[pkcs11]"``

Algorithm support
-----------------

The adapter expects the token to expose one of:

* RSA key with ``Mechanism.SHA256_RSA_PKCS_PSS`` → recorded as
  ``"rsa-pss-sha256"`` on the receipt (universally supported by HSMs).

Ed25519 PKCS#11 support is patchy across vendors as of the matrix in
``provenex/kms/__init__.py``; the adapter does not surface it yet but
can be extended trivially once your HSM's token supports
``Mechanism.EDDSA``.

Usage
-----

    from provenex.kms.pkcs11 import PKCS11Signer

    signer = PKCS11Signer(
        module_path="/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
        token_label="provenex",
        pin="...",
        key_label="provenex-receipt-key",
    )
"""

from __future__ import annotations

import base64
import hashlib
from typing import Optional

from ..core.receipt import ReceiptSigner
from .common import ALGORITHM_RSA_PSS_SHA256, KMSConfigurationError


def _require_pkcs11():
    try:
        import pkcs11  # noqa: F401
    except ImportError as exc:  # pragma: no cover - import guard
        raise ImportError(
            "PKCS11Signer requires the 'pkcs11' extra. "
            'Install with: pip install "provenex-core[pkcs11]"'
        ) from exc


class PKCS11Signer(ReceiptSigner):
    """Receipt signer backed by a PKCS#11 HSM key.

    Args:
        module_path: Path to the vendor PKCS#11 module ``.so`` / ``.dll``.
        token_label: Label of the token to log in to.
        pin: User PIN for the token. Pass via env or secret manager.
        key_label: Label of the signing key on the token.
        public_key_pem: Optional pre-extracted public-key PEM for the
            verify() path. If absent, the adapter extracts the public
            key from the token at construction.
    """

    def __init__(
        self,
        module_path: str,
        token_label: str,
        pin: str,
        key_label: str,
        *,
        public_key_pem: Optional[bytes] = None,
    ) -> None:
        _require_pkcs11()
        import pkcs11
        from pkcs11 import KeyType, ObjectClass

        lib = pkcs11.lib(module_path)
        try:
            token = lib.get_token(token_label=token_label)
        except pkcs11.exceptions.NoSuchToken as exc:
            raise KMSConfigurationError(
                f"PKCS#11 token {token_label!r} not found in {module_path!r}."
            ) from exc

        self._session = token.open(user_pin=pin)
        try:
            self._priv = self._session.get_key(
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=KeyType.RSA,
                label=key_label,
            )
        except pkcs11.exceptions.NoSuchKey as exc:
            raise KMSConfigurationError(
                f"PKCS#11 key {key_label!r} not found on token "
                f"{token_label!r}; only RSA keys are supported today."
            ) from exc

        if public_key_pem is not None:
            self._public_key_pem = public_key_pem
        else:
            pub = self._session.get_key(
                object_class=ObjectClass.PUBLIC_KEY,
                key_type=KeyType.RSA,
                label=key_label,
            )
            self._public_key_pem = self._pkcs11_pub_to_pem(pub)

    def _pkcs11_pub_to_pem(self, pub) -> bytes:
        """Convert a PKCS#11 RSA public key handle to PEM via cryptography."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from pkcs11 import Attribute

        n = int.from_bytes(pub[Attribute.MODULUS], "big")
        e = int.from_bytes(pub[Attribute.PUBLIC_EXPONENT], "big")
        rsa_pub = rsa.RSAPublicNumbers(e, n).public_key()
        return rsa_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @property
    def algorithm(self) -> str:
        return ALGORITHM_RSA_PSS_SHA256

    def public_key_pem(self) -> bytes:
        return self._public_key_pem

    def sign(self, payload: bytes) -> str:
        from pkcs11 import Mechanism, MGF

        digest = hashlib.sha256(payload).digest()
        sig = self._priv.sign(
            digest,
            mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
            mechanism_param=(Mechanism.SHA256, MGF.SHA256, len(digest)),
        )
        return base64.b64encode(sig).decode("ascii")

    def verify(self, payload: bytes, signature: str) -> bool:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            sig_bytes = base64.b64decode(signature.encode("ascii"))
        except Exception:
            return False
        pub = serialization.load_pem_public_key(self._public_key_pem)
        try:
            pub.verify(
                sig_bytes,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256.digest_size,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False
