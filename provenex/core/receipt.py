"""Provenance receipt model, JSON serialization, and signing.

The provenance receipt is the most important public API surface of Provenex.
It is the artifact a compliance team holds onto, the artifact an auditor
verifies independently, and the artifact downstream systems consume to decide
whether to trust an AI output.

Schema design properties (intentional):

    1. **Self-describing.** ``schema_version`` is at the top. ``issuer``
       identifies the software that produced the receipt. Field names match
       what a human would expect.
    2. **Independently verifiable.** Everything needed to verify the receipt
       without contacting the issuer is in the receipt: the output hash, the
       per-source fingerprints, the policy, the signature algorithm.
    3. **Stable.** The schema version exists precisely so this schema can
       evolve without breaking older receipts.
    4. **Privacy-preserving.** No document content. No PII. Fingerprints
       only.

The signing layer is pluggable. The open source core ships an HMAC-SHA256
signer (symmetric, stdlib only). Production deployments can plug in an
asymmetric signer (e.g. Ed25519) without changing the receipt structure or
the rest of the pipeline.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..index.base import VerificationOutcome
from ..policy.policy import VerificationPolicy, overall_status
from .trajectory import TrajectoryContext


# Schema version history:
#   1.0.0 — original receipt
#   1.1.0 — transparency_log block + per-source leaf_index/inclusion_proof
#   1.2.0 — RESERVED for RFC-0001 (coverage block; not yet shipped)
#   1.3.0 — trajectory block (RFC-0003)
#   1.4.0 — per-source claims[] (self-attribution) + content_source field
#   1.5.0 — (skipped) interim shape that placed access_policy as a separate
#           top-level block; was never released. See the v0.4 release notes
#           for the migration story.
#   2.0.0 — unified ``policy`` block with ``verification`` and
#           ``access_control`` subsections. Breaking: the old top-level
#           ``policy`` field (which previously held only the
#           VerificationPolicy config) now wraps both halves.
#   2.1.0 — per-decision ``metadata_binding`` field recording whether
#           ``chunk_metadata`` and ``request_context`` were tag-at-ingest
#           (signed by the index) or tag-at-evaluate (looked up at
#           decision time). Additive: receipts without the field remain
#           valid 2.0.0 subsets.
#   2.2.0 — Phase 2: optional top-level ``actions[]`` array (tool-call
#           records, parallel to ``sources[]``); optional
#           ``policy.tool_call_control`` subsection (admission decision
#           record, parallel to ``policy.access_control``); ``summary``
#           gains ``total_actions`` / ``actions_allowed`` /
#           ``actions_denied`` when actions are present. Additive: a
#           2.1.0 receipt with no actions is a valid 2.2.0 receipt.
# Minor-version bumps are additive: receipts at a lower revision remain
# valid subsets of higher revisions. Major bumps may break the top-level
# shape — 2.0.0 did.
SCHEMA_VERSION = "2.2.0"
ISSUER = "provenex-core/0.6.0"


# --------------------------------------------------------------------------- #
# Signer interface                                                            #
# --------------------------------------------------------------------------- #


class ReceiptSigner(ABC):
    """Abstract signer interface.

    Implement this to plug in alternative signing algorithms. The receipt
    layer doesn't care whether the signature is symmetric or asymmetric. It
    only cares that ``algorithm``, ``sign``, and ``verify`` are consistent.
    """

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """A short identifier recorded on the receipt (e.g. ``"hmac-sha256"``)."""

    @abstractmethod
    def sign(self, payload: bytes) -> str:
        """Sign ``payload`` and return the signature as a hex/base64 string."""

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify that ``signature`` was produced over ``payload`` by this signer.

        Default implementation: re-sign and compare in constant time. This
        works correctly for any symmetric signer (HMAC, AES-CMAC, etc.).

        Asymmetric signers MUST override this. For Ed25519 etc. the verify
        path uses the public key, while ``sign`` requires the private key,
        so the default sign-and-compare strategy would either fail (no
        private key on hand for the auditor) or be wrong.
        """
        try:
            actual = self.sign(payload)
        except Exception:
            return False
        return hmac.compare_digest(actual, signature)


class HmacSha256Signer(ReceiptSigner):
    """HMAC-SHA256 signer (symmetric).

    The default signer for the open source core. Pure stdlib.

    Args:
        secret: Bytes used as the HMAC key. If ``None``, the value of the
            ``PROVENEX_SIGNING_SECRET`` environment variable is used.

    Raises:
        RuntimeError: If no secret is provided and no environment variable is
            set.
    """

    def __init__(self, secret: Optional[bytes] = None) -> None:
        if secret is None:
            env_secret = os.environ.get("PROVENEX_SIGNING_SECRET")
            if not env_secret:
                raise RuntimeError(
                    "HmacSha256Signer requires a secret or the "
                    "PROVENEX_SIGNING_SECRET environment variable."
                )
            secret = env_secret.encode("utf-8")
        self._secret = secret

    @property
    def algorithm(self) -> str:
        return "hmac-sha256"

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._secret, payload, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Receipt models                                                              #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Claim:
    """A self-attribution claim about a source chunk (schema 1.4.0+).

    Agents — especially Self-RAG-style models that emit reflective tokens
    ([Relevant], [Supported], [No Support]) — produce assertions *about*
    retrieved chunks: "I used this", "this supports the answer", "this is
    relevant to the query". Those assertions are valuable signal, but they
    are the agent's word, not a property Provenex can independently verify.

    A ``Claim`` is the cryptographically-bound record of that assertion.
    The signature on the receipt covers every claim verbatim, so an agent
    cannot deny what it said. Provenex does **not** verify the claim's
    correctness — that is the agent operator's compliance burden.

    Provenex-defined ``type`` strings (callers can use any string for
    forward compatibility):

        * ``"model_used_in_answer"`` — the model asserts it used this chunk.
        * ``"supports_answer"`` — the model asserts the chunk grounds the output.
        * ``"relevant"`` — the model asserts the chunk is relevant to the query.

    Attributes:
        type: Free-form classifier (see above for Provenex-defined values).
        asserted_by: Who emitted the claim. Typically an agent_id, model
            name, or operator identifier. Opaque; do not encode PII.
        value: Optional value the assertion carries. Booleans, strings
            (e.g. ``"partial"``), or ``None``.
        reason: Optional short rationale string supplied by the agent.
    """

    type: str
    asserted_by: str
    value: Optional[Any] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type, "asserted_by": self.asserted_by}
        if self.value is not None:
            d["value"] = self.value
        if self.reason is not None:
            d["reason"] = self.reason
        return d


# Provenex-recognised ``content_source`` values. These describe the
# *origin* of a chunk's bytes — useful for an auditor reading a receipt
# that contains an UNVERIFIED outcome. Unknown values are valid for
# forward compatibility.
CONTENT_SOURCE_INDEXED_CORPUS = "indexed_corpus"
CONTENT_SOURCE_LIVE_TOOL_OUTPUT = "live_tool_output"
CONTENT_SOURCE_MEMORY_STORE = "memory_store"
CONTENT_SOURCE_COMPILED_ARTIFACT = "compiled_artifact"


@dataclass
class SourceRecord:
    """A single source chunk's entry on the receipt.

    Attributes match the ``sources[]`` schema in the project spec.

    The transparency-log fields (``leaf_index``, ``inclusion_proof``) are
    optional and present only when the receipt was produced against an
    index that maintains an RFC 6962 transparency log (added in schema
    version 1.1.0). When present, ``inclusion_proof`` can be verified
    offline against the receipt's ``transparency_log.tree_root``.

    Schema 1.4.0 added two optional fields:

        * ``claims`` — list of self-attribution :class:`Claim`s (item 5).
        * ``content_source`` — origin classifier, e.g.
          ``"live_tool_output"`` (item 6). Absent means
          ``"indexed_corpus"`` implicitly.
    """

    chunk_index: int
    fingerprint: str
    document_id: Optional[str]
    document_version: Optional[str]
    ingested_at: Optional[str]
    chunk_offset: Optional[int]
    chunk_length: Optional[int]
    authorized: Optional[bool]
    verification_outcome: VerificationOutcome
    normalization_applied: List[str] = field(default_factory=list)
    leaf_index: Optional[int] = None
    inclusion_proof: Optional[List[str]] = None
    claims: Optional[List[Claim]] = None
    content_source: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this source record to a plain dict (JSON-ready)."""
        d: Dict[str, Any] = {
            "chunk_index": self.chunk_index,
            "fingerprint": self.fingerprint,
            "document_id": self.document_id,
            "document_version": self.document_version,
            "ingested_at": self.ingested_at,
            "chunk_offset": self.chunk_offset,
            "chunk_length": self.chunk_length,
            "authorized": self.authorized,
            "verification_outcome": self.verification_outcome.value,
            "normalization_applied": list(self.normalization_applied),
        }
        if self.leaf_index is not None:
            d["leaf_index"] = self.leaf_index
        if self.inclusion_proof is not None:
            d["inclusion_proof"] = list(self.inclusion_proof)
        if self.claims:
            d["claims"] = [c.to_dict() for c in self.claims]
        if self.content_source is not None:
            d["content_source"] = self.content_source
        return d


@dataclass
class ActionRecord:
    """A single tool-call attempt's entry on the receipt (schema 2.2.0).

    Phase 2 parallel of :class:`SourceRecord`: ``sources[]`` records what
    was retrieved, ``actions[]`` records what tool calls were attempted.
    A receipt may carry one or both arrays. The per-action policy
    decision lives under ``policy.tool_call_control.decisions[]`` and
    references each action by ``action_index``, the same way
    ``policy.access_control.decisions[].chunk_fingerprint`` references a
    source.

    Attributes:
        action_index: 0-based position in ``actions[]``. The
            ``tool_call_control.decisions[i].action_index`` field
            references this back.
        name: Tool identifier. For MCP, the server-and-tool path
            (``"jira/issues"``). Read from
            :attr:`provenex.tool_call.ToolCallContext.name`.
        operation: The specific operation (``"create_issue"``,
            ``"query"``).
        parameters_hash: SHA-256 over the canonicalised verbatim
            parameter dict. Always present, regardless of whether
            :attr:`parameters` itself is recorded — an auditor with the
            original parameters can independently re-derive the hash.
        parameters: The verbatim parameters the caller passed, or
            ``None`` if the operator opted in to redaction at admission
            time. Default: recorded. Operators with PII concerns set
            ``redact_parameters=True`` on
            :func:`provenex.tool_call.admission_check`.
        target_system: Optional logical target system. Same convention
            as the source-record optional fields — omitted from JSON
            when ``None``.
        invocation_id: Optional caller-chosen ID for correlation.
    """

    action_index: int
    name: str
    operation: str
    parameters_hash: str
    parameters: Optional[Dict[str, Any]] = None
    target_system: Optional[str] = None
    invocation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize this action record to a plain dict (JSON-ready)."""
        d: Dict[str, Any] = {
            "action_index": self.action_index,
            "name": self.name,
            "operation": self.operation,
            "parameters_hash": self.parameters_hash,
        }
        # parameters: emit verbatim dict, or null when redacted, so the
        # caller's redaction choice is visible to the auditor reading
        # the JSON. Absence would be ambiguous; null is explicit.
        d["parameters"] = (
            dict(self.parameters) if self.parameters is not None else None
        )
        if self.target_system is not None:
            d["target_system"] = self.target_system
        if self.invocation_id is not None:
            d["invocation_id"] = self.invocation_id
        return d


@dataclass
class ProvenanceReceipt:
    """A complete provenance receipt for one LLM inference event.

    Do not construct this directly; use :class:`ReceiptBuilder`.

    The receipt is immutable in practice once :meth:`finalize` has been
    called. Mutating fields afterward will invalidate the signature.
    """

    receipt_id: str
    issued_at: str
    output_hash: str
    sources: List[SourceRecord]
    policy: VerificationPolicy
    summary: Dict[str, Any]
    signature_algorithm: Optional[str] = None
    signature_value: Optional[str] = None
    schema_version: str = SCHEMA_VERSION
    issuer: str = ISSUER
    transparency_log: Optional[Dict[str, Any]] = None
    trajectory: Optional[Dict[str, Any]] = None
    # Schema 2.0.0: optional ``access_control`` payload nested under the
    # unified top-level ``policy`` block. Absent on receipts produced
    # without a configured PolicyEvaluator. Carries evaluator identity,
    # the canonical policy version hash, and the per-chunk decision
    # records.
    access_control: Optional[Dict[str, Any]] = None
    # Schema 2.2.0 (Phase 2): optional tool-call action records and the
    # parallel ``policy.tool_call_control`` decision payload. Either or
    # both of these are present on receipts produced by the tool-call
    # admission pipeline. Pure-retrieval receipts leave both empty/None.
    actions: List[ActionRecord] = field(default_factory=list)
    tool_call_control: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the receipt to a plain dict in canonical schema order."""
        policy_block: Dict[str, Any] = {
            "verification": {
                "block_stale": self.policy.block_stale,
                "block_unauthorized": self.policy.block_unauthorized,
                "block_unverified": self.policy.block_unverified,
                "block_tampered": self.policy.block_tampered,
                "flag_stale": self.policy.flag_stale,
                "flag_unauthorized": self.policy.flag_unauthorized,
                "flag_unverified": self.policy.flag_unverified,
                "flag_tampered": self.policy.flag_tampered,
            }
        }
        if self.access_control is not None:
            policy_block["access_control"] = dict(self.access_control)
        if self.tool_call_control is not None:
            policy_block["tool_call_control"] = dict(self.tool_call_control)
        d: Dict[str, Any] = {
            "receipt_id": self.receipt_id,
            "schema_version": self.schema_version,
            "issued_at": self.issued_at,
            "issuer": self.issuer,
            "output": {
                "hash": self.output_hash,
                "hash_algorithm": "sha256",
            },
            "sources": [s.to_dict() for s in self.sources],
            "policy": policy_block,
            "summary": dict(self.summary),
        }
        # Schema 2.2.0: actions[] is emitted only when the receipt
        # actually carries tool-call records. An empty actions[] on a
        # pure-retrieval receipt would be a noisy addition to the JSON
        # and would gratuitously change the canonical signing payload
        # for receipts that were valid 2.1.0 receipts.
        if self.actions:
            d["actions"] = [a.to_dict() for a in self.actions]
        if self.transparency_log is not None:
            d["transparency_log"] = dict(self.transparency_log)
        if self.trajectory is not None:
            d["trajectory"] = dict(self.trajectory)
        if self.signature_algorithm is not None:
            d["signature"] = {
                "algorithm": self.signature_algorithm,
                "value": self.signature_value,
            }
        return d

    def to_json(self, indent: int | None = 2) -> str:
        """Serialize the receipt to a JSON string.

        Args:
            indent: JSON indent level. Pass ``None`` for the most compact
                form. The default (2) is human-readable.
        """
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def canonical_payload(self) -> bytes:
        """Build the canonical byte payload that gets signed.

        The payload is the JSON serialization of the receipt with the
        ``signature`` block omitted and keys sorted. Sorting ensures any
        verifier produces the same bytes regardless of dict insertion order.
        """
        d = self.to_dict()
        d.pop("signature", None)
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- #
# Builder                                                                     #
# --------------------------------------------------------------------------- #


def _now_utc_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with millisecond precision."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _new_receipt_id() -> str:
    """Generate a fresh receipt ID. ``prx_`` prefix + 32 hex chars."""
    return "prx_" + secrets.token_hex(16)


def _hash_output(output_text: str) -> str:
    """Compute the SHA-256 hash of an LLM output string."""
    return "sha256:" + hashlib.sha256(output_text.encode("utf-8")).hexdigest()


class ReceiptBuilder:
    """Assemble a :class:`ProvenanceReceipt` from per-chunk verification data.

    Typical usage (called by the LangChain retriever middleware):

        >>> builder = ReceiptBuilder(policy=VerificationPolicy())
        >>> builder.add_source(
        ...     fingerprint="sha256:...",
        ...     outcome=VerificationOutcome.VERIFIED,
        ...     entry=index_entry,
        ...     normalization_applied=["unicode_nfc", "whitespace_collapse"],
        ... )
        >>> receipt = builder.finalize(output_text="The answer is 42.", signer=signer)
    """

    def __init__(self, policy: VerificationPolicy | None = None) -> None:
        self._policy = policy or VerificationPolicy()
        self._sources: List[SourceRecord] = []
        # Schema 2.2.0: tool-call action records, parallel to sources[].
        # Populated via :meth:`add_action`.
        self._actions: List[ActionRecord] = []

    @property
    def policy(self) -> VerificationPolicy:
        """The policy in effect for this receipt."""
        return self._policy

    def add_source(
        self,
        fingerprint: str,
        outcome: VerificationOutcome,
        entry: Any = None,
        normalization_applied: Optional[List[str]] = None,
        leaf_index: Optional[int] = None,
        inclusion_proof: Optional[List[str]] = None,
        claims: Optional[List[Claim]] = None,
        content_source: Optional[str] = None,
    ) -> None:
        """Add one source chunk to the receipt under construction.

        Args:
            fingerprint: The chunk's SHA-256 fingerprint.
            outcome: The verification outcome from the index.
            entry: The :class:`provenex.index.base.IndexEntry` for this
                fingerprint, or ``None`` if the chunk was UNVERIFIED (not in
                the index). When ``None``, document metadata fields on the
                receipt are set to ``None``.
            normalization_applied: The normalization steps that were applied
                to compute the fingerprint.
            leaf_index: Position of this fingerprint in the transparency
                log, if one is in use (schema version 1.1.0+).
            inclusion_proof: RFC 6962 audit path for ``leaf_index`` as a
                list of ``sha256:<hex>`` strings. Verifiable offline against
                the receipt's ``transparency_log.tree_root``.
            claims: Optional list of :class:`Claim` self-attributions
                from the calling agent about this chunk (schema 1.4.0+).
                Claims are cryptographically bound to the receipt but
                NOT verified by Provenex. See :class:`Claim`.
            content_source: Optional origin classifier (schema 1.4.0+).
                One of the ``CONTENT_SOURCE_*`` constants, or any
                forward-compatible string. Absent means the implicit
                default ``"indexed_corpus"`` — set explicitly for
                ``"live_tool_output"``, ``"memory_store"``, etc., so an
                auditor reading an UNVERIFIED outcome knows whether to
                expect the chunk in the index.
        """
        record = SourceRecord(
            chunk_index=len(self._sources),
            fingerprint=fingerprint,
            document_id=getattr(entry, "document_id", None),
            document_version=getattr(entry, "document_version", None),
            ingested_at=getattr(entry, "ingested_at", None),
            chunk_offset=getattr(entry, "chunk_offset", None),
            chunk_length=getattr(entry, "chunk_length", None),
            authorized=getattr(entry, "authorized", None),
            verification_outcome=outcome,
            normalization_applied=list(normalization_applied or []),
            leaf_index=leaf_index,
            inclusion_proof=inclusion_proof,
            claims=list(claims) if claims else None,
            content_source=content_source,
        )
        self._sources.append(record)

    def add_action(
        self,
        name: str,
        operation: str,
        parameters_hash: str,
        parameters: Optional[Dict[str, Any]] = None,
        target_system: Optional[str] = None,
        invocation_id: Optional[str] = None,
    ) -> int:
        """Add one tool-call action to the receipt under construction (schema 2.2.0).

        Args:
            name: Tool identifier. From
                :attr:`provenex.tool_call.ToolCallContext.name`.
            operation: The specific operation on the tool.
            parameters_hash: SHA-256 over the canonical verbatim
                parameter dict. The caller must always pass this — it is
                what an auditor uses to re-derive the binding even when
                the parameters themselves are redacted.
            parameters: Verbatim parameters dict, or ``None`` to redact
                from the receipt. ``parameters_hash`` remains
                independently verifiable either way.
            target_system: Optional logical target.
            invocation_id: Optional caller-chosen correlation ID.

        Returns:
            The 0-based ``action_index`` assigned to this record. The
            tool-call decision later references the action by this
            index in ``tool_call_control.decisions[i].action_index``.
        """
        idx = len(self._actions)
        self._actions.append(
            ActionRecord(
                action_index=idx,
                name=name,
                operation=operation,
                parameters_hash=parameters_hash,
                parameters=dict(parameters) if parameters is not None else None,
                target_system=target_system,
                invocation_id=invocation_id,
            )
        )
        return idx

    def _summary(
        self,
        tool_call_control: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compute the per-receipt summary.

        Combines per-chunk verification outcomes (Phase 1) with per-action
        admission decisions (Phase 2, schema 2.2.0). The fields emitted
        depend on which halves the receipt carries:

            * Sources only — the original Phase 1 summary keys
              (``total_chunks`` + the five-outcome counts) plus
              ``overall_status``.
            * Sources + actions — Phase 1 keys, plus ``total_actions`` /
              ``actions_allowed`` / ``actions_denied``;
              ``overall_status`` considers both halves.
            * Actions only — verification counts are zero;
              ``total_actions`` and action counts present;
              ``overall_status`` reflects the admission outcome.

        ``overall_status``:

            * ``PASS`` — every chunk VERIFIED AND every action allowed.
            * ``FAIL`` — at least one chunk blocked by verification policy
              OR at least one action denied by tool-call policy.
            * ``PARTIAL`` — neither; at least one non-VERIFIED outcome
              with nothing blocked.
        """
        counts: Dict[str, Any] = {
            "total_chunks": len(self._sources),
            "verified": 0,
            "stale": 0,
            "unauthorized": 0,
            "unverified": 0,
            "tampered": 0,
        }
        for s in self._sources:
            counts[s.verification_outcome.value.lower()] += 1

        # Phase 2 action counts. Always emitted when the receipt carries
        # actions; omitted entirely on pure-retrieval receipts to
        # preserve the schema 2.1.0 summary shape exactly. Auditors
        # consuming 2.1.0 receipts under the 2.2.0 verifier see no diff.
        if self._actions:
            counts["total_actions"] = len(self._actions)
            counts["actions_allowed"] = 0
            counts["actions_denied"] = 0
            if tool_call_control is not None:
                for d in tool_call_control.get("decisions", []):
                    if d.get("decision") == "deny":
                        counts["actions_denied"] += 1
                    else:
                        # ``allow`` and the reserved
                        # ``allow_with_conditions`` both count as
                        # admitted for summary purposes; we may want a
                        # third bucket if conditions ever ship.
                        counts["actions_allowed"] += 1
            else:
                # No tool-call policy was configured — actions default
                # to allowed (the wiring layer never builds a
                # tool_call_control block in that case).
                counts["actions_allowed"] = len(self._actions)

        chunk_status = overall_status(
            [s.verification_outcome for s in self._sources], self._policy
        )
        action_status = "PASS"
        if self._actions:
            denied = counts.get("actions_denied", 0)
            action_status = "FAIL" if denied > 0 else "PASS"

        # Combine: FAIL beats PARTIAL beats PASS.
        if chunk_status == "FAIL" or action_status == "FAIL":
            counts["overall_status"] = "FAIL"
        elif chunk_status == "PARTIAL":
            counts["overall_status"] = "PARTIAL"
        else:
            counts["overall_status"] = "PASS"
        return counts

    def finalize(
        self,
        output_text: str,
        signer: Optional[ReceiptSigner] = None,
        transparency_log: Optional[Dict[str, Any]] = None,
        trajectory: Optional[TrajectoryContext] = None,
        access_control: Optional[Dict[str, Any]] = None,
        tool_call_control: Optional[Dict[str, Any]] = None,
    ) -> ProvenanceReceipt:
        """Build, sign, and return the finished receipt.

        Args:
            output_text: The LLM output text. Its SHA-256 is recorded as the
                ``output.hash`` field. Note: the text itself is NOT stored,
                only its hash.
            signer: A :class:`ReceiptSigner` for signing the receipt. If
                ``None``, the receipt is returned unsigned (the ``signature``
                block is omitted from the JSON). Unsigned receipts are useful
                in development; production should always sign.
            transparency_log: Optional dict carrying the log head at
                issuance, typically ``{"tree_size": int, "tree_root":
                "sha256:<hex>"}``. Present when the source records carry
                ``leaf_index`` / ``inclusion_proof`` fields. Recorded under
                the receipt's ``transparency_log`` key and covered by the
                signature.
            trajectory: Optional :class:`TrajectoryContext` linking this
                receipt into a multi-step agentic trajectory. When supplied,
                the trajectory block is emitted on the receipt and covered
                by the signature. See :mod:`provenex.core.trajectory`.
            access_control: Optional schema-2.0.0 ``policy.access_control``
                payload — evaluator identity, policy_id, policy_version_hash,
                policy_in_transparency_log, and the per-chunk decisions[].
                Callers normally do not assemble this by hand: see
                :func:`provenex.core.verify.verify_chunks`, which builds
                it from a configured :class:`Policy`.
            tool_call_control: Optional schema-2.2.0
                ``policy.tool_call_control`` payload — same shape as
                ``access_control`` but with decisions keyed by
                ``action_index`` rather than ``chunk_fingerprint``.
                Callers normally do not assemble this by hand: see
                :func:`provenex.tool_call.admission_check`, which builds
                it from a configured :class:`Policy`.

        Returns:
            The completed :class:`ProvenanceReceipt`.
        """
        receipt = ProvenanceReceipt(
            receipt_id=_new_receipt_id(),
            issued_at=_now_utc_iso(),
            output_hash=_hash_output(output_text),
            sources=list(self._sources),
            policy=self._policy,
            summary=self._summary(tool_call_control=tool_call_control),
            transparency_log=dict(transparency_log) if transparency_log else None,
            trajectory=trajectory.to_dict() if trajectory is not None else None,
            access_control=dict(access_control) if access_control else None,
            actions=list(self._actions),
            tool_call_control=(
                dict(tool_call_control) if tool_call_control else None
            ),
        )
        if signer is not None:
            receipt.signature_algorithm = signer.algorithm
            receipt.signature_value = signer.sign(receipt.canonical_payload())
        return receipt


# --------------------------------------------------------------------------- #
# Verification                                                                #
# --------------------------------------------------------------------------- #


def verify_receipt_signature(
    receipt_dict: Dict[str, Any],
    signer: ReceiptSigner,
) -> bool:
    """Independently verify the signature on a serialized receipt.

    Anyone with the receipt JSON and the signing secret (for HMAC) or public
    key (for asymmetric signers) can call this to confirm the receipt has
    not been tampered with.

    Args:
        receipt_dict: The receipt as a dict (e.g. from ``json.loads``).
        signer: A signer configured with the same key material that was used
            to sign the receipt.

    Returns:
        True if the signature is valid, False otherwise.
    """
    sig = receipt_dict.get("signature")
    if not sig:
        return False
    expected_alg = sig.get("algorithm")
    expected_value = sig.get("value")
    if expected_alg != signer.algorithm:
        return False
    payload_dict = dict(receipt_dict)
    payload_dict.pop("signature", None)
    payload = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return signer.verify(payload, expected_value or "")
