"""Provenex — policy enforcement for AI data access, with cryptographic proof.

This is the open source core: fingerprinting, local SQLite index, the
native YAML data-access policy DSL (schema 1.5.0), receipt generation,
and integrations for LangChain / LangGraph / LlamaIndex / CrewAI. The
algorithm is open so enterprises can audit it. Hosted infrastructure,
the Rego adapter, the OPA service adapter, Bloom-filter acceleration,
compliance-grade exports, and cross-enterprise provenance graphs are
available separately — see https://provenex.ai.
"""

from .core.fingerprinter import Fingerprint, Fingerprinter, FingerprinterConfig
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
    compute_caller_hash,
    compute_request_binding,
    compute_value_hash,
    verify_receipt_signature,
)
from .core.witness import WitnessLog, WitnessRecord
# Ed25519Signer is exported at the top level for symmetry with
# HmacSha256Signer. The class itself only fails (with a clear
# "install provenex-core[ed25519]" error) when instantiated; bare
# import works in any environment so the top-level provenex import
# stays pure-stdlib.
from .core.ed25519 import Ed25519Signer
from .core.trajectory import (
    TrajectoryAuditResult,
    TrajectoryCheck,
    TrajectoryContext,
    audit_trajectory_dag,
    start_trajectory,
)
from .core.signer_registry import (
    SignerRegistry,
    TenantNotFound,
    default_signer_factory,
    from_config_dict as signer_registry_from_config,
)
from .drift import DriftEvent, IndexDriftDetector
from .core.verify import VerifiedChunks, verify_chunks, verify_chunks_async, verify_memory
from .export import (
    FileJSONLSink,
    MultiSink,
    OCSFAdapter,
    ReceiptSink,
    RetryQueueSink,
    SinkClosedError,
    StdoutJSONLSink,
    receipt_to_ocsf,
)
from .index.base import (
    ENTRY_KIND_WHOLE_CHUNK,
    ENTRY_KIND_WINDOW,
    OUTCOME_PRECEDENCE,
    AsyncProvenanceIndex,
    IndexEntry,
    ProvenanceIndex,
    VerificationOutcome,
    reduce_outcomes,
)
from .index.bloom import BloomAcceleratedIndex, BloomFilterIndex, NoopBloomFilter
from .index.async_postgres_index import AsyncPostgresProvenanceIndex
from .index.postgres_index import PostgresProvenanceIndex
from .index.sqlite_index import SQLiteProvenanceIndex
from .policy.evaluator import (
    DECISION_ALLOW,
    DECISION_DENY,
    EVALUATOR_CUSTOM,
    EVALUATOR_NATIVE_YAML,
    EVALUATOR_NONE,
    EVALUATOR_OPA_SERVICE,
    EVALUATOR_REGO,
    ChunkContext,
    NullPolicyEvaluator,
    PolicyDecision,
    PolicyError,
    PolicyEvaluator,
    PolicyParseError,
    RequestContext,
    UnsupportedPolicyFeature,
    compute_inputs_hash,
    compute_policy_version_hash,
)
from .policy.availability import IndexAvailabilityPolicy, IndexUnavailable
from .policy.policy import VerificationPolicy, overall_status
from .policy.unified import Policy
from .policy.yaml_evaluator import NativeYamlEvaluator, validate_policy_file
from .index.circuit import CircuitBreaker
from .tool_call import (
    AdmissionResult,
    NativeYamlToolCallEvaluator,
    NullToolCallPolicyEvaluator,
    ToolCallContext,
    ToolCallDenied,
    ToolCallPolicyEvaluator,
    admission_check,
    admit_memory_write,
    admit_model_inference,
    enforce_admission,
)

__version__ = "0.10.0"

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
    "AsyncProvenanceIndex",
    "SQLiteProvenanceIndex",
    "PostgresProvenanceIndex",
    "AsyncPostgresProvenanceIndex",
    "VerificationOutcome",
    "OUTCOME_PRECEDENCE",
    "reduce_outcomes",
    "ENTRY_KIND_WHOLE_CHUNK",
    "ENTRY_KIND_WINDOW",
    # Bloom acceleration interface (stub in OSS; real impl is commercial)
    "BloomFilterIndex",
    "NoopBloomFilter",
    "BloomAcceleratedIndex",
    # Unified policy (schema 2.0.0)
    "Policy",
    # Verification policy (the five-outcome half, since v0.1)
    "VerificationPolicy",
    "overall_status",
    # Index-availability policy (block/degrade on index error)
    "IndexAvailabilityPolicy",
    "IndexUnavailable",
    "CircuitBreaker",
    # Data-access policy framework (schema 2.0.0)
    "ChunkContext",
    "RequestContext",
    "PolicyDecision",
    "PolicyEvaluator",
    "PolicyError",
    "PolicyParseError",
    "UnsupportedPolicyFeature",
    "NullPolicyEvaluator",
    "NativeYamlEvaluator",
    "validate_policy_file",
    "compute_policy_version_hash",
    "compute_inputs_hash",
    "DECISION_ALLOW",
    "DECISION_DENY",
    "EVALUATOR_NATIVE_YAML",
    "EVALUATOR_REGO",
    "EVALUATOR_OPA_SERVICE",
    "EVALUATOR_CUSTOM",
    "EVALUATOR_NONE",
    # Receipt
    "ProvenanceReceipt",
    "ReceiptBuilder",
    "ReceiptSigner",
    "HmacSha256Signer",
    "Ed25519Signer",
    "verify_receipt_signature",
    "compute_caller_hash",
    "compute_value_hash",
    "compute_request_binding",
    "Claim",
    # Multi-tenant signer registry
    "SignerRegistry",
    "TenantNotFound",
    "default_signer_factory",
    "signer_registry_from_config",
    # Index drift detector
    "DriftEvent",
    "IndexDriftDetector",
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
    # Witness / checkpoint log (v0.8.0+)
    "WitnessLog",
    "WitnessRecord",
    # Framework-agnostic verification
    "VerifiedChunks",
    "verify_chunks",
    "verify_chunks_async",
    "verify_memory",
    # Streaming export sinks (0.6.6+)
    "ReceiptSink",
    "StdoutJSONLSink",
    "FileJSONLSink",
    "MultiSink",
    "RetryQueueSink",
    "SinkClosedError",
    # OCSF export (0.6.7+)
    "OCSFAdapter",
    "receipt_to_ocsf",
    # Tool-call admission
    "ToolCallContext",
    "ToolCallPolicyEvaluator",
    "NullToolCallPolicyEvaluator",
    "NativeYamlToolCallEvaluator",
    "AdmissionResult",
    "ToolCallDenied",
    "admission_check",
    "admit_memory_write",
    "admit_model_inference",
    "enforce_admission",
    "__version__",
]
