"""Ed25519 asymmetric signer for provenance receipts.

The default HMAC signer is symmetric: anyone who can verify a receipt can
also forge one. That's fine for in-house compliance teams who hold the
key, but it doesn't work for external auditors, regulators, or
cross-organisation provenance. Ed25519 closes that gap.

Producer side:
    signer = Ed25519Signer.generate()
    receipt = builder.finalize(signer=signer, ...)
    # Distribute signer.public_key_pem() out-of-band. Keep
    # signer.private_key_pem() in a secrets manager.

Auditor side:
    verifier = Ed25519Signer.from_public_key_pem(pem_bytes)
    ok = verify_receipt_signature(receipt_dict, verifier)
    # No private key in scope. No way for the auditor to forge a receipt.

Optional dependency. Install with::

    pip install provenex-core[ed25519]

The ``cryptography`` package (PyCA) provides the underlying primitive. We
keep it optional so the rest of provenex-core stays pure-stdlib.
"""

from __future__ import annotations

from typing import Optional

from .receipt import ReceiptSigner

# Lazy import of cryptography, with a clear error if the extra wasn't installed.
try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTOGRAPHY = False


_ALGORITHM = "ed25519"


def _require_cryptography() -> None:
    if not _HAVE_CRYPTOGRAPHY:
        raise RuntimeError(
            "Ed25519Signer requires the `cryptography` package. Install with "
            "`pip install provenex-core[ed25519]`."
        )


class Ed25519Signer(ReceiptSigner):
    """Ed25519 receipt signer. Asymmetric, fast, small signatures (64 bytes).

    Operates in two modes:

        * **Signer mode**: constructed with a private key. Can sign and
          verify. This is what the receipt producer uses.
        * **Verifier-only mode**: constructed with only a public key. Can
          verify but not sign. Calling ``sign()`` raises ``RuntimeError``.
          This is what an external auditor uses.

    Args:
        private_key: ``Ed25519PrivateKey`` from ``cryptography``. If
            provided, the signer can both sign and verify.
        public_key: ``Ed25519PublicKey`` from ``cryptography``. If only
            this is provided, the signer is verify-only.

    Raises:
        RuntimeError: If the ``cryptography`` extra is not installed.
        ValueError: If neither private_key nor public_key is provided.
    """

    def __init__(
        self,
        private_key: Optional["Ed25519PrivateKey"] = None,
        public_key: Optional["Ed25519PublicKey"] = None,
    ) -> None:
        _require_cryptography()
        if private_key is None and public_key is None:
            raise ValueError(
                "Ed25519Signer requires either a private_key (for signing) "
                "or a public_key (for verification)."
            )
        self._private_key = private_key
        # If a private key is provided, derive the public key from it so
        # verify() works without the caller having to pass both.
        if public_key is not None:
            self._public_key = public_key
        else:
            assert private_key is not None  # narrowed by guard above
            self._public_key = private_key.public_key()

    # -------------------------------------------------------------- factories

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        """Generate a fresh keypair and return a signer holding both halves."""
        _require_cryptography()
        return cls(private_key=Ed25519PrivateKey.generate())

    @classmethod
    def from_private_key_pem(
        cls, pem: bytes, password: Optional[bytes] = None
    ) -> "Ed25519Signer":
        """Load a signer (signer + verifier) from a PEM-encoded private key."""
        _require_cryptography()
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(
                "PEM does not contain an Ed25519 private key "
                f"(got {type(key).__name__})"
            )
        return cls(private_key=key)

    @classmethod
    def from_public_key_pem(cls, pem: bytes) -> "Ed25519Signer":
        """Load a verifier-only signer from a PEM-encoded public key.

        This is the auditor's entry point. The returned signer can call
        :meth:`verify` but ``sign`` will raise.
        """
        _require_cryptography()
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(
                "PEM does not contain an Ed25519 public key "
                f"(got {type(key).__name__})"
            )
        return cls(public_key=key)

    # -------------------------------------------------------------- exports

    def private_key_pem(self, password: Optional[bytes] = None) -> bytes:
        """Serialize the private key to PKCS8 PEM (optionally password-protected)."""
        if self._private_key is None:
            raise RuntimeError("This signer has no private key (verify-only mode).")
        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

    def public_key_pem(self) -> bytes:
        """Serialize the public key to SubjectPublicKeyInfo PEM."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # -------------------------------------------------------------- signer api

    @property
    def algorithm(self) -> str:
        return _ALGORITHM

    def sign(self, payload: bytes) -> str:
        """Sign ``payload`` and return the 64-byte signature as 128 hex chars.

        Raises:
            RuntimeError: If this signer was constructed without a private
                key (verifier-only mode).
        """
        if self._private_key is None:
            raise RuntimeError(
                "Cannot sign: this Ed25519Signer is verify-only (no private key)."
            )
        return self._private_key.sign(payload).hex()

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify ``signature`` against ``payload`` using the public key.

        Constant-time at the primitive level (cryptography uses libsodium /
        OpenSSL). Returns False on any failure: bad hex, wrong length,
        signature mismatch, key type mismatch.
        """
        try:
            sig_bytes = bytes.fromhex(signature)
        except ValueError:
            return False
        try:
            self._public_key.verify(sig_bytes, payload)
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Defensive: cryptography raises various TypeErrors / ValueErrors
            # if the signature bytes are wrong length etc. Treat as "invalid".
            return False
