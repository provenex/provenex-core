"""Shared bits across KMS / HSM adapters: errors + algorithm constants."""

from __future__ import annotations


class KMSConfigurationError(RuntimeError):
    """Raised when an adapter is misconfigured (missing creds, key, etc.)."""


# Receipt-side signature.algorithm strings. The verifier reads these to
# know how to check; the producer writes them when emitting receipts.
ALGORITHM_ED25519 = "ed25519"
ALGORITHM_RSA_PSS_SHA256 = "rsa-pss-sha256"
