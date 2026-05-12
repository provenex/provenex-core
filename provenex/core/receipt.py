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


SCHEMA_VERSION = "1.1.0"
ISSUER = "provenex-core/0.1.0"


# --------------------------------------------------------------------------- #
# Signer interface                                                            #
# --------------------------------------------------------------------------- #


class ReceiptSigner(ABC):
    """Abstract signer interface.

    Implement this to plug in alternative signing algorithms. The receipt
    layer doesn't care whether the signature is symmetric or asymmetric — it
    only cares that ``algorithm`` and ``sign`` are consistent.
    """

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """A short identifier recorded on the receipt (e.g. ``"hmac-sha256"``)."""

    @abstractmethod
    def sign(self, payload: bytes) -> str:
        """Sign ``payload`` and return the signature as a hex/base64 string."""


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


@dataclass
class SourceRecord:
    """A single source chunk's entry on the receipt.

    Attributes match the ``sources[]`` schema in the project spec.

    The transparency-log fields (``leaf_index``, ``inclusion_proof``) are
    optional and present only when the receipt was produced against an
    index that maintains an RFC 6962 transparency log (added in schema
    version 1.1.0). When present, ``inclusion_proof`` can be verified
    offline against the receipt's ``transparency_log.tree_root``.
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

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the receipt to a plain dict in canonical schema order."""
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
            "policy": {
                "block_stale": self.policy.block_stale,
                "block_unauthorized": self.policy.block_unauthorized,
                "block_unverified": self.policy.block_unverified,
                "block_tampered": self.policy.block_tampered,
                "flag_stale": self.policy.flag_stale,
                "flag_unauthorized": self.policy.flag_unauthorized,
                "flag_unverified": self.policy.flag_unverified,
                "flag_tampered": self.policy.flag_tampered,
            },
            "summary": dict(self.summary),
        }
        if self.transparency_log is not None:
            d["transparency_log"] = dict(self.transparency_log)
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
        )
        self._sources.append(record)

    def _summary(self) -> Dict[str, Any]:
        counts = {
            "total_chunks": len(self._sources),
            "verified": 0,
            "stale": 0,
            "unauthorized": 0,
            "unverified": 0,
            "tampered": 0,
        }
        for s in self._sources:
            counts[s.verification_outcome.value.lower()] += 1
        counts["overall_status"] = overall_status(
            [s.verification_outcome for s in self._sources], self._policy
        )
        return counts

    def finalize(
        self,
        output_text: str,
        signer: Optional[ReceiptSigner] = None,
        transparency_log: Optional[Dict[str, Any]] = None,
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

        Returns:
            The completed :class:`ProvenanceReceipt`.
        """
        receipt = ProvenanceReceipt(
            receipt_id=_new_receipt_id(),
            issued_at=_now_utc_iso(),
            output_hash=_hash_output(output_text),
            sources=list(self._sources),
            policy=self._policy,
            summary=self._summary(),
            transparency_log=dict(transparency_log) if transparency_log else None,
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
    actual = signer.sign(payload)
    return hmac.compare_digest(actual, expected_value or "")
