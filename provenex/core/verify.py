"""Framework-agnostic chunk verification.

This module supplies the *escape hatch* for users who aren't on a supported
framework (LangChain, LangGraph, LlamaIndex, CrewAI) but still want
Provenex receipts on their retrieval pipeline. Pass chunks plus an index;
get back kept/blocked chunks plus a signed receipt, optionally linked to
a trajectory.

The function is what every framework wrapper ultimately delegates to. It
exists at the package top level (``provenex.verify_chunks``) precisely so
"how do I use this without LangChain?" has a one-line answer.

Quick reference
---------------

    import provenex

    # Single retrieval call:
    result = provenex.verify_chunks(
        chunks=["chunk text 1", "chunk text 2"],
        index=index,
        signer=provenex.HmacSha256Signer(),
    )
    for doc in result.kept:
        feed_to_llm(doc)
    save_receipt(result.receipt)

    # Multi-step / agentic flow:
    traj = provenex.start_trajectory(agent_id="my_agent")
    r1 = provenex.verify_chunks(chunks_a, index=index, trajectory=traj)
    r2 = provenex.verify_chunks(chunks_b, index=index, trajectory=r1.next_trajectory)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .fingerprinter import Fingerprinter, FingerprinterConfig
from .receipt import ProvenanceReceipt, ReceiptBuilder, ReceiptSigner
from .trajectory import TrajectoryContext
from ..index.base import IndexEntry, ProvenanceIndex
from ..policy.evaluator import (
    BINDING_AT_EVALUATE,
    BINDING_AT_INGEST,
    DECISION_ALLOW,
    ChunkContext,
    PolicyDecision,
    RequestContext,
)
from ..policy.policy import VerificationPolicy
from ..policy.unified import Policy, build_access_control_metadata, coerce_policy


@dataclass
class VerifiedChunks:
    """Result of a :func:`verify_chunks` call.

    Attributes:
        kept: Chunk texts that passed policy. Safe to pass to the LLM.
        blocked: Chunk texts removed by policy. The receipt still records
            them; this list is surfaced so the caller can log them or
            substitute placeholders.
        receipt: The signed receipt covering both sets.
        next_trajectory: When the caller passed a ``trajectory`` to
            :func:`verify_chunks`, this is the advanced cursor ready to
            be passed to the next call (chains receipts into a DAG).
            ``None`` if no trajectory was supplied.
    """

    kept: List[str]
    blocked: List[str]
    receipt: ProvenanceReceipt
    next_trajectory: Optional[TrajectoryContext] = None


def _coerce_chunks(value: Any) -> List[str]:
    """Normalise any common retrieval-result shape into a list of chunk strings.

    Accepts:
        * A single string — treated as one chunk.
        * A list/tuple of strings — each is one chunk.
        * A list of duck-typed Documents with ``.page_content`` /
          ``.content`` / ``.text``.
        * A list of dicts containing one of those text fields.

    Anything else raises ``TypeError`` — we'd rather fail loudly than
    silently fingerprint the wrong bytes.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        out: List[str] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif hasattr(item, "page_content"):
                out.append(item.page_content)
            elif hasattr(item, "content"):
                out.append(item.content)
            elif hasattr(item, "text"):
                out.append(item.text)
            elif isinstance(item, dict):
                for k in ("page_content", "content", "text"):
                    if k in item and isinstance(item[k], str):
                        out.append(item[k])
                        break
                else:
                    raise TypeError(
                        f"dict chunk missing recognized text field "
                        f"(page_content/content/text): keys={list(item)}"
                    )
            else:
                raise TypeError(
                    f"unrecognised chunk type {type(item).__name__}; "
                    f"expected str, Document-like, or dict"
                )
        return out
    raise TypeError(
        f"chunks must be str or list, got {type(value).__name__}"
    )


def _build_chunk_context(
    *,
    fingerprint: str,
    entry: Optional[IndexEntry],
    metadata: Optional[Dict[str, Any]],
) -> ChunkContext:
    """Assemble a :class:`ChunkContext` for the policy evaluator.

    Pulls document_id / document_version / ingested_at off the index
    entry when available. For UNVERIFIED chunks (no entry), those
    attributes are ``None`` and the policy author can decide how to
    handle them via ``defaults.unknown_metadata``.
    """
    return ChunkContext(
        fingerprint=fingerprint,
        document_id=getattr(entry, "document_id", None),
        document_version=getattr(entry, "document_version", None),
        ingested_at=getattr(entry, "ingested_at", None),
        metadata=dict(metadata) if metadata else {},
        content_source=None,
    )


def verify_chunks(
    chunks: Any,
    index: ProvenanceIndex,
    signer: Optional[ReceiptSigner] = None,
    policy: Any = None,  # Policy | VerificationPolicy | None
    fingerprinter: Optional[Fingerprinter] = None,
    trajectory: Optional[TrajectoryContext] = None,
    step_kind: Optional[str] = None,
    agent_id: Optional[str] = None,
    output_text: str = "",
    request_context: Optional[RequestContext] = None,
    chunk_metadata: Optional[List[Dict[str, Any]]] = None,
    chunk_metadata_binding: str = BINDING_AT_EVALUATE,
) -> VerifiedChunks:
    """Verify a set of chunks against the index and emit a signed receipt.

    This is the framework-agnostic entry point. Each supported framework
    wrapper (LangChain retriever, LangGraph node factory, CrewAI session)
    ultimately calls into the same fingerprint / verify / receipt
    machinery this function exposes directly.

    Args:
        chunks: Retrieval result. Accepts a string, a list of strings,
            a list of duck-typed Documents (``.page_content`` /
            ``.content`` / ``.text``), or a list of dicts with those
            keys. See :func:`_coerce_chunks`.
        index: The :class:`ProvenanceIndex` to verify against.
        signer: Optional :class:`ReceiptSigner`. Production should always
            sign.
        policy: Optional unified :class:`Policy` carrying the verification
            gate config and (optionally) a data-access evaluator. Defaults
            to a Policy with default verification (block UNAUTHORIZED +
            TAMPERED) and no access control. Load a unified YAML config
            with :meth:`Policy.from_yaml`.
        fingerprinter: Optional custom :class:`Fingerprinter`. Must match
            the one used at ingest time, otherwise nothing will verify.
        trajectory: Optional :class:`TrajectoryContext`. When supplied,
            the emitted receipt carries the trajectory block, and the
            returned :class:`VerifiedChunks` includes ``next_trajectory``
            so the caller can chain calls into a DAG.
        step_kind: Optional override for ``trajectory.step_kind`` on the
            emitted receipt. If supplied, replaces the cursor's
            ``step_kind`` for this emission only — the cursor itself is
            not mutated.
        agent_id: Optional override for ``trajectory.agent_id``. Same
            per-emission-only semantics as ``step_kind``.
        output_text: Optional LLM-output text whose hash should appear
            on the receipt. Defaults to empty (the receipt covers the
            chunks but no answer); pass the actual answer on the final
            call in a multi-step flow.
        request_context: Required when ``policy.access_control`` is set.
            The caller / jurisdiction / purpose / timestamp the evaluator
            checks against. For v0.4 the caller constructs this
            explicitly; identity-provider integration is future work.
        chunk_metadata: Optional list, one entry per chunk in retrieval
            order, of opaque metadata dicts surfaced to the policy
            evaluator under ``chunk.metadata.*``. Use this to pass
            tagging set by upstream PII / classification tools. If
            omitted, ``chunk.metadata`` is empty for every chunk.
        chunk_metadata_binding: Schema 2.1.0+. Whether ``chunk_metadata``
            was tag-at-ingest (signed by the index row; defaults to
            ``"at_ingest"`` if the caller declares it) or tag-at-evaluate
            (the default — the caller looked it up at retrieval time).
            ``request_context`` is always ``"at_evaluate"`` and is
            recorded that way on the receipt. The binding is non-load-
            bearing: it does not change the decision, only what an
            auditor reading the receipt knows about the trust class of
            each input. See [docs/threat_model.md] for the trust model.

    Returns:
        A :class:`VerifiedChunks` containing the kept chunks, blocked
        chunks, the signed receipt, and (when a trajectory was passed)
        the advanced cursor.

    Raises:
        TypeError: When ``chunks`` is of an unrecognised shape.
        ValueError: When ``policy.access_control`` is set without a
            ``request_context``, or when ``chunk_metadata`` is provided
            but has a different length than ``chunks``.
    """
    eff_policy: Policy = coerce_policy(policy)
    fp = fingerprinter or Fingerprinter(FingerprinterConfig())

    texts = _coerce_chunks(chunks)

    # Validate the access-control + request-context combination eagerly.
    # The retriever should not silently degrade if the operator forgot
    # the request context — that would emit allow-by-default receipts.
    if eff_policy.access_control is not None and request_context is None:
        raise ValueError(
            "verify_chunks: policy.access_control was set but "
            "request_context is None. Pass a RequestContext."
        )
    if chunk_metadata is not None and len(chunk_metadata) != len(texts):
        raise ValueError(
            f"verify_chunks: chunk_metadata length {len(chunk_metadata)} "
            f"does not match chunks length {len(texts)}"
        )
    if chunk_metadata_binding not in (BINDING_AT_INGEST, BINDING_AT_EVALUATE):
        raise ValueError(
            f"verify_chunks: chunk_metadata_binding must be "
            f"{BINDING_AT_INGEST!r} or {BINDING_AT_EVALUATE!r}, got "
            f"{chunk_metadata_binding!r}"
        )

    builder = ReceiptBuilder(policy=eff_policy.verification)
    kept: List[str] = []
    blocked: List[str] = []
    policy_decisions: List[Dict[str, Any]] = []

    for i, text in enumerate(texts):
        fingerprint = fp.fingerprint_chunk(text)
        outcome = index.verify(fingerprint)
        entry = index.lookup(fingerprint)
        builder.add_source(
            fingerprint=fingerprint,
            outcome=outcome,
            entry=entry,
            normalization_applied=list(
                fp.fingerprint(text).normalization_applied
            ),
        )
        block_by_verification = eff_policy.verification.should_block(outcome)
        block_by_policy = False
        if eff_policy.access_control is not None and request_context is not None:
            chunk_ctx = _build_chunk_context(
                fingerprint=fingerprint,
                entry=entry,
                metadata=chunk_metadata[i] if chunk_metadata else None,
            )
            decision = eff_policy.access_control.evaluate(
                chunk_ctx, request_context
            )
            decision_with_binding = PolicyDecision(
                decision=decision.decision,
                rules_fired=decision.rules_fired,
                inputs_hash=decision.inputs_hash,
                inputs=decision.inputs,
                metadata_binding={
                    "chunk_metadata": chunk_metadata_binding,
                    "request_context": BINDING_AT_EVALUATE,
                },
            )
            policy_decisions.append(
                decision_with_binding.to_dict(chunk_fingerprint=fingerprint)
            )
            block_by_policy = decision.decision != DECISION_ALLOW

        if block_by_verification or block_by_policy:
            blocked.append(text)
        else:
            kept.append(text)

    # If trajectory is provided, allow per-call overrides of step_kind /
    # agent_id without mutating the caller's cursor.
    emit_trajectory: Optional[TrajectoryContext] = trajectory
    if trajectory is not None and (
        step_kind is not None or agent_id is not None
    ):
        emit_trajectory = TrajectoryContext(
            trajectory_id=trajectory.trajectory_id,
            step_index=trajectory.step_index,
            trajectory_started_at=trajectory.trajectory_started_at,
            parent_step_ids=trajectory.parent_step_ids,
            step_kind=step_kind if step_kind is not None else trajectory.step_kind,
            agent_id=agent_id if agent_id is not None else trajectory.agent_id,
        )

    access_control_block: Optional[Dict[str, Any]] = None
    if eff_policy.access_control is not None:
        access_control_block = build_access_control_metadata(
            eff_policy.access_control, policy_decisions
        )

    receipt = builder.finalize(
        output_text=output_text,
        signer=signer,
        trajectory=emit_trajectory,
        access_control=access_control_block,
    )

    next_trajectory: Optional[TrajectoryContext] = None
    if trajectory is not None:
        next_trajectory = trajectory.next_step(
            parent_receipts=[receipt],
            agent_id=agent_id if agent_id is not None else trajectory.agent_id,
        )

    return VerifiedChunks(
        kept=kept,
        blocked=blocked,
        receipt=receipt,
        next_trajectory=next_trajectory,
    )
