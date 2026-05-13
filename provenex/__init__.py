"""Provenex — cryptographic provenance verification for enterprise RAG.

This is the open source core: fingerprinting, local SQLite index, receipt
generation, and LangChain/LlamaIndex integration. The algorithm is open so
enterprises can audit it. Hosted infrastructure, Bloom-filter acceleration,
compliance-grade exports, and cross-enterprise provenance graphs are
available separately — see https://provenex.ai.
"""

from .core.fingerprinter import Fingerprinter, FingerprinterConfig, Fingerprint
from .core.hasher import sha256_fingerprint
from .core.normalizer import NormalizationOptions, TextNormalizer
from .core.receipt import (
    HmacSha256Signer,
    ProvenanceReceipt,
    ReceiptBuilder,
    ReceiptSigner,
    verify_receipt_signature,
)
from .index.base import IndexEntry, ProvenanceIndex, VerificationOutcome
from .index.sqlite_index import SQLiteProvenanceIndex
from .policy.policy import VerificationPolicy, overall_status

__version__ = "0.2.0"

__all__ = [
    # Core
    "Fingerprinter",
    "FingerprinterConfig",
    "Fingerprint",
    "NormalizationOptions",
    "TextNormalizer",
    "sha256_fingerprint",
    # Index
    "IndexEntry",
    "ProvenanceIndex",
    "SQLiteProvenanceIndex",
    "VerificationOutcome",
    # Policy
    "VerificationPolicy",
    "overall_status",
    # Receipt
    "ProvenanceReceipt",
    "ReceiptBuilder",
    "ReceiptSigner",
    "HmacSha256Signer",
    "verify_receipt_signature",
    "__version__",
]
