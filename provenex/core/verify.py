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

For ASGI / FastAPI / Starlette callers, use :func:`verify_chunks_async`
with an :class:`AsyncPostgresProvenanceIndex`. The async path is
identical to the sync one except the index round-trip is awaited
instead of blocking the event loop.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .fingerprinter import Fingerprinter, FingerprinterConfig
from .receipt import (
    ProvenanceReceipt,
    ReceiptBuilder,
    ReceiptSigner,
    compute_caller_hash,
    compute_request_binding,
)
from .trajectory import TrajectoryContext
from ..export.streaming import _safe_publish
from ..index.base import AsyncProvenanceIndex, IndexEntry, ProvenanceIndex, VerificationOutcome
from ..index.circuit import CircuitBreaker
from ..policy.availability import (
    ON_ERROR_BLOCK,
    IndexAvailabilityPolicy,
    IndexUnavailable,
)
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
    request_text: Optional[str] = None,
    chunk_metadata: Optional[List[Dict[str, Any]]] = None,
    chunk_metadata_binding: str = BINDING_AT_EVALUATE,
    caller_hash_salt: Optional[bytes] = None,
    content_source: Optional[str] = None,
    sink: Any = None,
    breaker: Optional[CircuitBreaker] = None,
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
        request_text: Optional triggering query / prompt text (v0.8.0+).
            When supplied, the receipt's ``request_binding.query_hash``
            is the SHA-256 of this text; the binding is covered by the
            receipt signature, so a valid receipt cannot be presented as
            evidence for a different query. The text itself is NEVER
            recorded on the receipt, only its hash. Recommended for any
            retrieval where the receipt may be handed to a regulator,
            third-party auditor, or downstream compliance system.
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
    eff_policy, fp, texts, fingerprints = _verify_chunks_prepare(
        chunks=chunks,
        policy=policy,
        fingerprinter=fingerprinter,
        request_context=request_context,
        chunk_metadata=chunk_metadata,
        chunk_metadata_binding=chunk_metadata_binding,
    )

    # Phase 1.1: one ``verify_batch`` round-trip on the index instead of
    # N pairs of ``verify`` + ``lookup`` (which were two lookups per chunk
    # internally). On a 10-chunk retrieval this drops 20 backend hits to
    # 1 on Postgres; on SQLite it folds the in-process I/O similarly.
    # The wrapper enforces the operator's availability policy: timeout
    # bound, circuit-breaker check, and either block-on-error
    # (IndexUnavailable) or degrade-on-error (UNVERIFIED + index_status).
    verifications, index_status = _verify_batch_with_availability(
        index=index,
        fingerprints=fingerprints,
        availability=eff_policy.availability,
        breaker=breaker,
    )

    return _verify_chunks_finalize(
        texts=texts,
        fingerprints=fingerprints,
        verifications=verifications,
        fp=fp,
        eff_policy=eff_policy,
        signer=signer,
        trajectory=trajectory,
        step_kind=step_kind,
        agent_id=agent_id,
        output_text=output_text,
        request_context=request_context,
        request_text=request_text,
        chunk_metadata=chunk_metadata,
        chunk_metadata_binding=chunk_metadata_binding,
        caller_hash_salt=caller_hash_salt,
        content_source=content_source,
        sink=sink,
        index_status=index_status,
    )


# --------------------------------------------------------------------------- #
# Index availability — timeout, circuit breaker, mode handling                #
# --------------------------------------------------------------------------- #
#
# The provenance index is the only network dependency on the verify hot
# path. These helpers wrap the index round-trip so that timeouts,
# connection errors, and pool exhaustion produce the operator-chosen
# response (``block`` — raise :class:`IndexUnavailable` — or ``degrade``
# — return a degraded receipt) instead of crashing the call. The
# circuit breaker, when supplied, short-circuits while the index is
# considered unhealthy so a struggling backend is not pushed harder.


def _classify_index_exception(exc: BaseException) -> str:
    """Bucket an index error into ``"timeout"`` / ``"connection"`` / ``"other"``.

    The core stays stdlib-only, so we cannot import psycopg's exception
    taxonomy to switch on. We approximate by class name: anything named
    ``*Timeout*`` is a timeout; anything mentioning ``Connection`` /
    ``Pool`` / ``OperationalError`` is connection-class; everything else
    is ``other``. The class string is the value of
    ``index_status.error_class`` on a degraded receipt and the label of
    the ``IndexUnavailable.error_class`` attribute when blocking.
    """
    if isinstance(exc, asyncio.TimeoutError) or isinstance(exc, TimeoutError):
        return "timeout"
    name = type(exc).__name__
    if (
        "Timeout" in name
    ):
        return "timeout"
    if (
        "Connection" in name
        or "Pool" in name
        or "Operational" in name
        or "Disconnect" in name
    ):
        return "connection"
    return "other"


def _degraded_outcomes(
    fingerprints: Sequence[str],
) -> List[Tuple[VerificationOutcome, Optional[IndexEntry]]]:
    """Return the all-UNVERIFIED outcome list used in ``degrade`` mode.

    When the index is unreachable, the caller cannot know whether a
    given chunk would have verified, been stale, or been blocked.
    Every chunk's outcome collapses to ``UNVERIFIED`` and the
    receipt carries ``index_status.available=false`` so an auditor
    distinguishes this case from a genuine "no entry in the index"
    miss.
    """
    return [(VerificationOutcome.UNVERIFIED, None) for _ in fingerprints]


def _resolve_index_failure(
    *,
    fingerprints: Sequence[str],
    availability: IndexAvailabilityPolicy,
    error_class: str,
    exc: Optional[BaseException] = None,
) -> Tuple[
    List[Tuple[VerificationOutcome, Optional[IndexEntry]]],
    Optional[Dict[str, Any]],
]:
    """Apply the operator-chosen mode to an index failure.

    ``block`` raises :class:`IndexUnavailable`; ``degrade`` returns the
    all-UNVERIFIED outcome list plus an ``index_status`` dict for the
    receipt.
    """
    if availability.on_index_error == ON_ERROR_BLOCK:
        message = f"provenance index unavailable ({error_class})"
        if exc is not None:
            message = f"{message}: {exc}"
        raise IndexUnavailable(message, error_class=error_class)
    return (
        _degraded_outcomes(fingerprints),
        {"available": False, "error_class": error_class},
    )


def _verify_batch_with_availability(
    *,
    index: ProvenanceIndex,
    fingerprints: Sequence[str],
    availability: IndexAvailabilityPolicy,
    breaker: Optional[CircuitBreaker],
) -> Tuple[
    List[Tuple[VerificationOutcome, Optional[IndexEntry]]],
    Optional[Dict[str, Any]],
]:
    """Sync index call wrapped in breaker + mode handling.

    The sync path does not impose a wall-clock timeout — production
    sync callers should set their database driver's
    ``statement_timeout``. Library users on SQLite are bounded by
    file I/O and do not need one.
    """
    if breaker is not None and not breaker.allow():
        return _resolve_index_failure(
            fingerprints=fingerprints,
            availability=availability,
            error_class="breaker_open",
        )
    try:
        verifications = index.verify_batch(fingerprints)
    except IndexUnavailable:
        if breaker is not None:
            breaker.record_failure()
        raise
    except Exception as exc:
        if breaker is not None:
            breaker.record_failure()
        return _resolve_index_failure(
            fingerprints=fingerprints,
            availability=availability,
            error_class=_classify_index_exception(exc),
            exc=exc,
        )
    if breaker is not None:
        breaker.record_success()
    return verifications, None


async def _verify_batch_async_with_availability(
    *,
    index: AsyncProvenanceIndex,
    fingerprints: Sequence[str],
    availability: IndexAvailabilityPolicy,
    breaker: Optional[CircuitBreaker],
) -> Tuple[
    List[Tuple[VerificationOutcome, Optional[IndexEntry]]],
    Optional[Dict[str, Any]],
]:
    """Async index call wrapped in timeout + breaker + mode handling.

    The wall-clock timeout comes from
    :attr:`IndexAvailabilityPolicy.timeout_seconds`. When ``None``,
    the call is awaited without an outer ``asyncio.wait_for``;
    callers can still bound latency at the connection-pool /
    statement-timeout layers.
    """
    if breaker is not None and not breaker.allow():
        return _resolve_index_failure(
            fingerprints=fingerprints,
            availability=availability,
            error_class="breaker_open",
        )
    timeout = availability.timeout_seconds
    try:
        if timeout is None:
            verifications = await index.verify_batch_async(fingerprints)
        else:
            verifications = await asyncio.wait_for(
                index.verify_batch_async(fingerprints), timeout=timeout
            )
    except IndexUnavailable:
        if breaker is not None:
            breaker.record_failure()
        raise
    except Exception as exc:
        if breaker is not None:
            breaker.record_failure()
        return _resolve_index_failure(
            fingerprints=fingerprints,
            availability=availability,
            error_class=_classify_index_exception(exc),
            exc=exc,
        )
    if breaker is not None:
        breaker.record_success()
    return verifications, None


# --------------------------------------------------------------------------- #
# Shared prepare / finalize stages                                            #
# --------------------------------------------------------------------------- #
#
# verify_chunks and verify_chunks_async share everything except the call into
# the index: one calls ``index.verify_batch(...)``, the other awaits
# ``index.verify_batch_async(...)``. The CPU-bound stages around that I/O
# (input coercion, fingerprinting, receipt assembly, policy evaluation,
# signing, sink publishing) are factored out here so neither path can drift
# from the other on what the wire shape of a receipt looks like.


def _verify_chunks_prepare(
    *,
    chunks: Any,
    policy: Any,
    fingerprinter: Optional[Fingerprinter],
    request_context: Optional[RequestContext],
    chunk_metadata: Optional[List[Dict[str, Any]]],
    chunk_metadata_binding: str,
) -> Tuple[Policy, Fingerprinter, List[str], List[str]]:
    eff_policy: Policy = coerce_policy(policy)
    fp = fingerprinter or Fingerprinter(FingerprinterConfig())
    texts = _coerce_chunks(chunks)

    # Validate the access-control + request-context combination eagerly.
    # The retriever should not silently degrade if the operator forgot
    # the request context, since that would emit allow-by-default receipts.
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

    fingerprints = [fp.fingerprint_chunk(text) for text in texts]
    return eff_policy, fp, texts, fingerprints


def _verify_chunks_finalize(
    *,
    texts: List[str],
    fingerprints: List[str],
    verifications: Sequence[Tuple[VerificationOutcome, Optional[IndexEntry]]],
    fp: Fingerprinter,
    eff_policy: Policy,
    signer: Optional[ReceiptSigner],
    trajectory: Optional[TrajectoryContext],
    step_kind: Optional[str],
    agent_id: Optional[str],
    output_text: str,
    request_context: Optional[RequestContext],
    request_text: Optional[str],
    chunk_metadata: Optional[List[Dict[str, Any]]],
    chunk_metadata_binding: str,
    caller_hash_salt: Optional[bytes],
    content_source: Optional[str],
    sink: Any,
    index_status: Optional[Dict[str, Any]] = None,
) -> VerifiedChunks:
    builder = ReceiptBuilder(policy=eff_policy.verification)
    kept: List[str] = []
    blocked: List[str] = []
    policy_decisions: List[Dict[str, Any]] = []

    for i, text in enumerate(texts):
        fingerprint = fingerprints[i]
        outcome, entry = verifications[i]
        builder.add_source(
            fingerprint=fingerprint,
            outcome=outcome,
            entry=entry,
            normalization_applied=list(
                fp.fingerprint(text).normalization_applied
            ),
            content_source=content_source,
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
    # agent_id / session_id without mutating the caller's cursor. The
    # request-supplied session_id (schema 2.3.0) wins over whatever the
    # cursor carries, then propagates forward via next_step. The request
    # is the source-of-truth per emission; operators who want
    # session immutability across a trajectory should set the session
    # once at start_trajectory and not pass it on subsequent requests.
    request_session_id = (
        request_context.session_id if request_context is not None else None
    )
    emit_trajectory: Optional[TrajectoryContext] = trajectory
    if trajectory is not None and (
        step_kind is not None
        or agent_id is not None
        or request_session_id is not None
    ):
        emit_trajectory = TrajectoryContext(
            trajectory_id=trajectory.trajectory_id,
            step_index=trajectory.step_index,
            trajectory_started_at=trajectory.trajectory_started_at,
            parent_step_ids=trajectory.parent_step_ids,
            step_kind=step_kind if step_kind is not None else trajectory.step_kind,
            agent_id=agent_id if agent_id is not None else trajectory.agent_id,
            session_id=(
                request_session_id
                if request_session_id is not None
                else trajectory.session_id
            ),
        )

    access_control_block: Optional[Dict[str, Any]] = None
    if eff_policy.access_control is not None:
        access_control_block = build_access_control_metadata(
            eff_policy.access_control, policy_decisions
        )

    # Schema 2.3.0: compute caller_hash from the request context's
    # caller dict (when present). Top-level field on the emitted
    # receipt; lets downstream consumers GROUP BY caller without
    # crawling per-decision inputs. When ``caller_hash_salt`` is
    # supplied (0.6.5+), the hash becomes HMAC-SHA256 with the salt
    # as the key (same canonical-JSON payload, two deployments with
    # different salts produce different caller_hash values for the
    # same caller; per-deployment unlinkability).
    emit_caller_hash: Optional[str] = None
    if request_context is not None:
        emit_caller_hash = compute_caller_hash(
            request_context.caller, salt=caller_hash_salt
        )

    # Schema 2.4.0: cryptographic binding between this receipt and the
    # request that produced it. Both halves are optional; absence is
    # recorded explicitly so an auditor sees that the binding is
    # incomplete. When the operator passes neither a request_text nor
    # a request_context, the block is omitted entirely.
    request_binding = compute_request_binding(
        request_text=request_text,
        request_context=request_context,
    )

    receipt = builder.finalize(
        output_text=output_text,
        signer=signer,
        trajectory=emit_trajectory,
        access_control=access_control_block,
        caller_hash=emit_caller_hash,
        request_binding=request_binding,
        index_status=index_status,
    )

    # Schema 2.3.0 / 0.6.6+: ship to downstream sink if supplied.
    # Failures are swallowed (warnings.warn); the agent's hot path
    # is never broken by export degradation.
    _safe_publish(sink, receipt)

    next_trajectory: Optional[TrajectoryContext] = None
    if trajectory is not None:
        next_trajectory = trajectory.next_step(
            parent_receipts=[receipt],
            agent_id=agent_id if agent_id is not None else trajectory.agent_id,
            session_id=(
                request_session_id
                if request_session_id is not None
                else trajectory.session_id
            ),
        )

    return VerifiedChunks(
        kept=kept,
        blocked=blocked,
        receipt=receipt,
        next_trajectory=next_trajectory,
    )


# --------------------------------------------------------------------------- #
# Async entry point                                                           #
# --------------------------------------------------------------------------- #


async def verify_chunks_async(
    chunks: Any,
    index: AsyncProvenanceIndex,
    signer: Optional[ReceiptSigner] = None,
    policy: Any = None,  # Policy | VerificationPolicy | None
    fingerprinter: Optional[Fingerprinter] = None,
    trajectory: Optional[TrajectoryContext] = None,
    step_kind: Optional[str] = None,
    agent_id: Optional[str] = None,
    output_text: str = "",
    request_context: Optional[RequestContext] = None,
    request_text: Optional[str] = None,
    chunk_metadata: Optional[List[Dict[str, Any]]] = None,
    chunk_metadata_binding: str = BINDING_AT_EVALUATE,
    caller_hash_salt: Optional[bytes] = None,
    content_source: Optional[str] = None,
    sink: Any = None,
    breaker: Optional[CircuitBreaker] = None,
) -> VerifiedChunks:
    """Async-safe counterpart of :func:`verify_chunks`.

    Same semantics, same return shape, same receipt wire format. The only
    difference from :func:`verify_chunks` is that the index round-trip is
    awaited (``index.verify_batch_async``) rather than blocking, so a
    FastAPI / Starlette / aiohttp handler can call this directly without
    serializing the event loop.

    Args:
        index: An :class:`AsyncProvenanceIndex` (such as
            :class:`AsyncPostgresProvenanceIndex`). The async counterpart
            of the sync :class:`ProvenanceIndex` interface; only the
            ``verify_batch_async`` method is consulted on this hot path.
        chunks, signer, policy, fingerprinter, trajectory, step_kind,
        agent_id, output_text, request_context, request_text,
        chunk_metadata, chunk_metadata_binding, caller_hash_salt,
        content_source, sink: See :func:`verify_chunks` for full
        semantics; the meanings carry over unchanged.

    Returns:
        :class:`VerifiedChunks`, bit-identical to what
        :func:`verify_chunks` would have returned given the same inputs
        and the same index state.

    Note:
        The sink publishing step (``_safe_publish``) runs synchronously
        inside the coroutine. Built-in sinks (Stdout / File / Multi /
        RetryQueue) are non-blocking enough to be safe; network-bound
        sinks (Kafka, AWS, GCP) may briefly block the event loop. If
        that becomes the bottleneck, wrap the call in
        ``asyncio.to_thread(...)`` or set ``sink=None`` on the hot path
        and forward receipts asynchronously elsewhere.
    """
    eff_policy, fp, texts, fingerprints = _verify_chunks_prepare(
        chunks=chunks,
        policy=policy,
        fingerprinter=fingerprinter,
        request_context=request_context,
        chunk_metadata=chunk_metadata,
        chunk_metadata_binding=chunk_metadata_binding,
    )

    verifications, index_status = await _verify_batch_async_with_availability(
        index=index,
        fingerprints=fingerprints,
        availability=eff_policy.availability,
        breaker=breaker,
    )

    return _verify_chunks_finalize(
        texts=texts,
        fingerprints=fingerprints,
        verifications=verifications,
        fp=fp,
        eff_policy=eff_policy,
        signer=signer,
        trajectory=trajectory,
        step_kind=step_kind,
        agent_id=agent_id,
        output_text=output_text,
        request_context=request_context,
        request_text=request_text,
        chunk_metadata=chunk_metadata,
        chunk_metadata_binding=chunk_metadata_binding,
        caller_hash_salt=caller_hash_salt,
        content_source=content_source,
        sink=sink,
        index_status=index_status,
    )


def verify_memory(
    memory_chunks: Any,
    index: ProvenanceIndex,
    signer: Optional[ReceiptSigner] = None,
    **kwargs: Any,
) -> VerifiedChunks:
    """Convenience: :func:`verify_chunks` with memory-read defaults (schema 2.3.0).

    Thin wrapper that sets the receipt-side classifiers a memory-read step
    SHOULD carry:

        * ``step_kind="memory_read"`` on the trajectory block (if a
          trajectory cursor is passed).
        * ``content_source="memory_store"`` on every emitted source
          record, so an auditor reading an UNVERIFIED outcome knows to
          expect a memory miss rather than alarm.

    Both defaults are overridable — pass ``step_kind=...`` or
    ``content_source=...`` to ``kwargs`` and the explicit value wins.

    Use this when the agent reads from a memory store you've also
    indexed via Provenex (CrewAI memory, LangGraph state, a custom
    store). The memory store SHOULD be a :class:`ProvenanceIndex`; for
    ad-hoc memory not in any index, an ``UNVERIFIED`` outcome with
    ``content_source="memory_store"`` is the right shape — an auditor
    reading the receipt sees a memory miss, not a corpus miss.

    Args:
        memory_chunks: The memory entries to verify. Same shape as
            :func:`verify_chunks`'s ``chunks`` argument.
        index: The :class:`ProvenanceIndex` backing the memory store.
        signer: Optional :class:`ReceiptSigner`.
        **kwargs: Passed through verbatim to :func:`verify_chunks`.

    Returns:
        :class:`VerifiedChunks`. The emitted receipt carries
        ``trajectory.step_kind="memory_read"`` (when a trajectory is
        in scope) and every source has
        ``content_source="memory_store"`` (when not overridden).
    """
    kwargs.setdefault("step_kind", "memory_read")
    kwargs.setdefault("content_source", "memory_store")
    return verify_chunks(memory_chunks, index, signer=signer, **kwargs)
