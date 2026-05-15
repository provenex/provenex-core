"""Data-access policy evaluator interface (schema 1.5.0).

The data-access policy is a separate concern from the existing
:class:`provenex.policy.policy.VerificationPolicy`. The verification policy
gates chunks on the five outcomes (VERIFIED / STALE / UNAUTHORIZED /
UNVERIFIED / TAMPERED). The data-access policy gates chunks on the
operator's own rules — origin, freshness, access, jurisdiction, PII tags,
classification — using a pluggable evaluator backend.

A chunk reaches the LLM only if it passes BOTH gates. The receipt records
both: ``sources[i].verification_outcome`` and
``access_policy.decisions[i].decision``. Auditors can reason about them
independently.

This module defines the evaluator-agnostic surface: the
:class:`PolicyEvaluator` protocol, the input/output dataclasses, the
hashing helpers, and the :class:`NullPolicyEvaluator` stub used when no
policy is configured.

The native YAML evaluator lives in :mod:`provenex.policy.yaml_evaluator`.
The Rego adapter and OPA-service adapter are deliberately out of scope for
v0.4; the schema reserves the enum values.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

# Evaluator backend enum values recorded on receipts under
# ``access_policy.evaluator``. Only ``native_yaml`` and ``none`` are
# implemented in v0.4; the others are reserved for forward compatibility
# and will raise NotImplementedError if anyone tries to load them.
EVALUATOR_NATIVE_YAML = "native_yaml"
EVALUATOR_REGO = "rego"
EVALUATOR_OPA_SERVICE = "opa_service"
EVALUATOR_CUSTOM = "custom"
EVALUATOR_NONE = "none"

# Decision enum values.
DECISION_ALLOW = "allow"
DECISION_DENY = "deny"

# The policy_id recorded when no evaluator is configured. Chosen so an
# auditor reading a receipt can tell at a glance that the operator opted
# out, rather than having to infer from the absence of the block.
NO_POLICY_ID = "none"

# Metadata-binding values (schema 2.1.0). Each decision input records
# how the value the evaluator looked at was bound to trust:
#
#   "at_ingest"   — the value lives in the signed Provenex index row;
#                   covered by the row HMAC and (with the Merkle log)
#                   by the published tree head. An attacker cannot
#                   flip the value without invalidating the signature.
#                   This is the strong case.
#
#   "at_evaluate" — the value was looked up from an external system at
#                   decision time (IAM, classification sidecar, feature
#                   flag service, etc.) or supplied freshly by the
#                   caller. The receipt records what we read, but the
#                   decision is only as trustworthy as that external
#                   system was at that moment.
BINDING_AT_INGEST = "at_ingest"
BINDING_AT_EVALUATE = "at_evaluate"


# --------------------------------------------------------------------------- #
# Exceptions                                                                  #
# --------------------------------------------------------------------------- #


class PolicyError(Exception):
    """Base class for all policy-evaluation errors."""


class PolicyParseError(PolicyError):
    """Raised when a policy file fails to parse or is structurally invalid.

    The message should always carry enough context (file path, key, and
    where possible a line number) for the operator to fix the policy
    without a debugger.
    """


class UnsupportedPolicyFeature(PolicyError):
    """Raised when a policy file uses a feature not implemented in v0.4.

    Reserved features include boolean composition (``any_of`` / ``all_of``),
    negation, nested rules, custom functions, and external lookups. The
    error names the offending feature so the operator knows what to
    remove (or upgrade to wait for).
    """


# --------------------------------------------------------------------------- #
# Contexts and decision record                                                #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ChunkContext:
    """One retrieved chunk's view as seen by the policy evaluator.

    Attributes:
        fingerprint: SHA-256 fingerprint string (``"sha256:<hex>"``).
        document_id: Stable document identifier.
        document_version: SHA-256 of the normalized document content.
        ingested_at: ISO-8601 UTC timestamp from the index entry.
        metadata: Opaque customer-defined tags. The evaluator reads
            dotted paths like ``chunk.metadata.residency`` against this
            dict. Values may be any JSON-serializable type.
        content_source: One of the ``CONTENT_SOURCE_*`` constants
            (introduced in schema 1.4.0). May be ``None`` when the chunk
            was not in the index.
    """

    fingerprint: str
    document_id: Optional[str]
    document_version: Optional[str]
    ingested_at: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    content_source: Optional[str] = None


@dataclass(frozen=True)
class RequestContext:
    """The caller's view as seen by the policy evaluator.

    For v0.4 the caller constructs this explicitly; identity-provider
    integration is future work. Document this when you wire it up.

    Attributes:
        caller: Opaque caller identity. A dict so rules can read paths
            like ``request.caller.role`` or ``request.caller.id``. Do not
            put PII in here that you wouldn't want appearing in receipt
            ``inputs`` blocks (you can always redact, but defaults
            record).
        jurisdiction: Optional ISO/region code (``"EU"``, ``"US"``,
            ``"APAC"``). Read by rules like
            ``when: request.jurisdiction: EU``.
        purpose: Optional free-form purpose string (``"customer_support"``,
            ``"internal_research"``). Read by rules that gate on intent.
        timestamp: ISO-8601 UTC timestamp of the request. This is the
            "now" used for freshness comparisons (``not_older_than``).
            Sourcing freshness from the request timestamp (not wall
            clock) keeps decisions deterministic and auditable.
        session_id: Optional caller-chosen opaque multi-trajectory
            correlation key (schema 2.3.0+). NOT a policy input — never
            resolves under ``request.*`` in a rule's ``when`` or
            ``require`` clause, and is excluded from ``inputs_hash`` by
            design (two requests differing only in ``session_id``
            produce identical decisions and identical input hashes).
            The wiring layer (:func:`provenex.core.verify.verify_chunks`,
            :func:`provenex.tool_call.admission_check`) reads this and
            stamps it onto the emitted receipt's ``trajectory.session_id``
            field for downstream correlation. When passed on a request
            without a trajectory in scope, the value is silently dropped
            (single-shot calls aren't sessions).
    """

    caller: Dict[str, Any]
    jurisdiction: Optional[str]
    purpose: Optional[str]
    timestamp: str
    session_id: Optional[str] = None


@dataclass(frozen=True)
class PolicyDecision:
    """The evaluator's verdict on a single chunk.

    Attributes:
        decision: One of :data:`DECISION_ALLOW` or :data:`DECISION_DENY`.
        rules_fired: Names of the rules whose ``when`` clause matched.
            This is the trace of rules that participated in the decision
            (regardless of whether each one passed or failed its
            ``require`` clause). The list is in policy-file order.
        inputs_hash: SHA-256 of the canonicalized ``inputs`` object. Always
            present, even when ``inputs`` is redacted, so an auditor with
            the original inputs can independently verify the hash.
        inputs: The canonical inputs dict the evaluator looked at, or
            ``None`` if the operator chose to redact it from the receipt.
        metadata_binding: Schema 2.1.0+. A dict marking each section of
            ``inputs`` as :data:`BINDING_AT_INGEST` (signed by the index
            row) or :data:`BINDING_AT_EVALUATE` (looked up at decision
            time). ``request_context`` is always ``at_evaluate``;
            ``chunk_metadata`` is operator-declared. Lets an auditor see
            the trust class of each input at a glance.
    """

    decision: str
    rules_fired: List[str]
    inputs_hash: str
    inputs: Optional[Dict[str, Any]]
    metadata_binding: Optional[Dict[str, str]] = None

    def to_dict(self, chunk_fingerprint: str) -> Dict[str, Any]:
        """Serialize for the ``policy.access_control.decisions[]`` entry on a receipt."""
        d: Dict[str, Any] = {
            "chunk_fingerprint": chunk_fingerprint,
            "decision": self.decision,
            "rules_fired": list(self.rules_fired),
            "inputs_hash": self.inputs_hash,
            "inputs": (
                dict(self.inputs) if self.inputs is not None else None
            ),
        }
        if self.metadata_binding is not None:
            d["metadata_binding"] = dict(self.metadata_binding)
        return d


# --------------------------------------------------------------------------- #
# Evaluator protocol                                                          #
# --------------------------------------------------------------------------- #


@runtime_checkable
class PolicyEvaluator(Protocol):
    """The interface every data-access policy backend implements.

    A backend is responsible for (a) loading a policy bundle, (b)
    producing the bundle's stable :attr:`policy_version_hash`, and (c)
    evaluating per-(chunk, request) decisions. Backends MUST be
    deterministic: the same inputs and same bundle MUST always produce the
    same decision.

    Backends MUST also be side-effect-free per evaluation. Any logging,
    metrics, or audit emission should be done by the caller using the
    returned :class:`PolicyDecision`, not by the evaluator itself.
    """

    @property
    def evaluator_name(self) -> str:
        """The backend name recorded on the receipt (``"native_yaml"`` etc.).

        See the ``EVALUATOR_*`` module constants. Custom backends should
        use :data:`EVALUATOR_CUSTOM`.
        """
        ...

    @property
    def policy_id(self) -> str:
        """The ``policy_id`` from the loaded bundle (or ``"none"``)."""
        ...

    @property
    def policy_version_hash(self) -> str:
        """``"sha256:<hex>"`` over the canonicalized policy bundle.

        Two policies that differ only in formatting (key order, whitespace)
        MUST hash to the same value. This is the field that would be
        published to a transparency log.
        """
        ...

    def evaluate(
        self,
        chunk: ChunkContext,
        request: RequestContext,
    ) -> PolicyDecision:
        """Return the decision for one ``(chunk, request)`` pair."""
        ...


# --------------------------------------------------------------------------- #
# Null evaluator                                                              #
# --------------------------------------------------------------------------- #


class NullPolicyEvaluator:
    """Allow-all evaluator used when no policy is configured.

    Recording an explicit "no policy" evaluator on the receipt is more
    honest than omitting the block — an auditor can tell the difference
    between "operator opted out" and "older schema". That said, when this
    evaluator is in use, the wiring layer SHOULD omit the
    ``access_policy`` block from the receipt entirely (and leave
    ``schema_version`` at 1.4.0) for full backward compatibility with
    pre-v0.4 consumers.

    Use this class explicitly when you want a decisions[] trace anyway —
    e.g. during a migration where you're enabling the policy plumbing
    before authoring real rules.
    """

    @property
    def evaluator_name(self) -> str:
        return EVALUATOR_NONE

    @property
    def policy_id(self) -> str:
        return NO_POLICY_ID

    @property
    def policy_version_hash(self) -> str:
        # Hash of an empty canonical bundle. Stable across releases.
        return compute_policy_version_hash({})

    def evaluate(
        self,
        chunk: ChunkContext,
        request: RequestContext,
    ) -> PolicyDecision:
        inputs = _build_inputs(chunk, request)
        return PolicyDecision(
            decision=DECISION_ALLOW,
            rules_fired=[],
            inputs_hash=compute_inputs_hash(inputs),
            inputs=inputs,
        )


# --------------------------------------------------------------------------- #
# Canonicalization and hashing                                                #
# --------------------------------------------------------------------------- #


def _canonical_bytes(obj: Any) -> bytes:
    """Return the canonical byte serialization of ``obj`` for hashing.

    The canonicalization rules are:

    * JSON serialization with ``sort_keys=True``. This means dict key order
      in the input has no effect on the output.
    * Tight separators (``","`` and ``":"``) so insignificant whitespace
      cannot perturb the hash.
    * ``ensure_ascii=False`` so non-ASCII characters survive without
      escape-form jitter. (Smart quotes survive; see CLAUDE.md.)
    * UTF-8 encoding of the resulting string.

    Both the policy bundle and the per-decision ``inputs`` object share
    this canonicalization, so the two hash functions below are trivial
    wrappers.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_policy_version_hash(policy_bundle: Any) -> str:
    """SHA-256 over the canonicalized policy bundle.

    Two policies that parse to equal Python structures produce the same
    hash. This is true regardless of: YAML key order, surrounding
    whitespace, comments, or YAML vs. equivalent JSON form. It is NOT
    invariant to actual structural differences (rename a rule, change a
    value — hash changes).

    Args:
        policy_bundle: Any JSON-serializable structure. For the native
            YAML backend this is the dict returned by ``yaml.safe_load``.

    Returns:
        ``"sha256:<hex>"`` string suitable for direct insertion into the
        receipt's ``access_policy.policy_version_hash`` field.
    """
    return "sha256:" + hashlib.sha256(_canonical_bytes(policy_bundle)).hexdigest()


def compute_inputs_hash(inputs: Dict[str, Any]) -> str:
    """SHA-256 over the canonicalized per-decision inputs object.

    Same canonicalization as :func:`compute_policy_version_hash`. The hash
    is recorded on the receipt even when the ``inputs`` field itself is
    redacted, so an auditor who holds the original inputs (e.g. from
    request-side logging) can independently verify them.
    """
    return "sha256:" + hashlib.sha256(_canonical_bytes(inputs)).hexdigest()


def _build_inputs(
    chunk: ChunkContext,
    request: RequestContext,
) -> Dict[str, Any]:
    """Build the canonical ``inputs`` dict for a decision record.

    The shape mirrors what appears under ``access_policy.decisions[i].inputs``
    on the receipt. ``chunk_metadata`` is the chunk's opaque tag dict plus
    its ``ingested_at`` and ``content_source``. ``request_context`` is the
    request fields the evaluator could have read.
    """
    chunk_meta: Dict[str, Any] = dict(chunk.metadata)
    if chunk.ingested_at is not None:
        chunk_meta.setdefault("ingested_at", chunk.ingested_at)
    if chunk.content_source is not None:
        chunk_meta.setdefault("content_source", chunk.content_source)
    request_ctx: Dict[str, Any] = {
        "caller": dict(request.caller),
        "jurisdiction": request.jurisdiction,
        "purpose": request.purpose,
        "timestamp": request.timestamp,
    }
    return {
        "chunk_metadata": chunk_meta,
        "request_context": request_ctx,
    }
