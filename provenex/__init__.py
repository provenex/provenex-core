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
    CONTENT_SOURCE_COMPILED_ARTIFACT,
    CONTENT_SOURCE_INDEXED_CORPUS,
    CONTENT_SOURCE_LIVE_TOOL_OUTPUT,
    CONTENT_SOURCE_MEMORY_STORE,
    Claim,
    HmacSha256Signer,
    ProvenanceReceipt,
    ReceiptBuilder,
    ReceiptSigner,
    verify_receipt_signature,
)
from .core.trajectory import (
    TrajectoryAuditResult,
    TrajectoryCheck,
    TrajectoryContext,
    audit_trajectory_dag,
    start_trajectory,
)
from .core.verify import VerifiedChunks, verify_chunks
from .index.base import IndexEntry, ProvenanceIndex, VerificationOutcome
from .index.sqlite_index import SQLiteProvenanceIndex
from .policy.policy import VerificationPolicy, overall_status

__version__ = "0.3.0"

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
    "Claim",
    "CONTENT_SOURCE_INDEXED_CORPUS",
    "CONTENT_SOURCE_LIVE_TOOL_OUTPUT",
    "CONTENT_SOURCE_MEMORY_STORE",
    "CONTENT_SOURCE_COMPILED_ARTIFACT",
    # Trajectory (RFC-0003)
    "TrajectoryContext",
    "TrajectoryAuditResult",
    "TrajectoryCheck",
    "audit_trajectory_dag",
    "start_trajectory",
    # Framework-agnostic verification
    "VerifiedChunks",
    "verify_chunks",
    "__version__",
]
