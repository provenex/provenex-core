"""LangGraph node factory and state helpers.

A LangGraph node is any callable ``(state) -> state_delta``. This module
supplies:

    * :func:`provenex_retrieval_node` — a factory that builds a retrieval
      node which verifies returned chunks, emits a trajectory-linked
      receipt, and threads the trajectory cursor forward in state.
    * :func:`provenex_admission_node` — Phase 2 sibling. A factory that
      builds a tool-call admission node: runs admission against policy,
      emits a signed receipt either way, and writes
      ``tool_admitted`` / ``tool_decision`` / ``tool_rules_fired``
      into state so a conditional edge can route execution. **Decision
      and proof, not execution** — the node never invokes the tool.
      That stays on a downstream node owned by the graph.
    * :func:`start_trajectory_state` — initialise a fresh trajectory inside
      a state dict, plus an empty receipts list.
    * :func:`record_step_receipt` — append a receipt and advance the
      trajectory cursor, for users writing custom nodes.

The factory and helpers are deliberately minimal — they reuse the same
fingerprint / verify / receipt machinery the LangChain wrapper uses, so the
two integrations stay consistent.

State conventions
-----------------

By default, the helpers and the factory read/write these state keys:

    * ``"query"`` — input string for the retriever.
    * ``"documents"`` — list of retrieved (and kept) documents.
    * ``"blocked_documents"`` — list of documents removed by policy.
    * ``"receipts"`` — list of :class:`ProvenanceReceipt` accumulated so far.
    * ``"trajectory"`` — current :class:`TrajectoryContext` cursor.

The admission node adds:

    * ``"tool_parameters"`` — dict of parameters for the pending tool call
      (input; can be remapped or supplied via ``params_extractor``).
    * ``"tool_admitted"`` — bool, True iff the decision was allow.
    * ``"tool_decision"`` — the verbatim decision string
      (``"allow"`` / ``"deny"`` / reserved ``"allow_with_conditions"``).
    * ``"tool_rules_fired"`` — list of rule names that fired.

Any of these can be remapped per-node by passing a ``state_keys`` mapping
to the factory. Keys not present in state are treated as missing rather
than raising; missing ``"trajectory"`` is the trigger to start a fresh
trajectory on the first call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional

from ...core.fingerprinter import Fingerprinter, FingerprinterConfig
from ...core.receipt import ProvenanceReceipt, ReceiptBuilder, ReceiptSigner
from ...core.trajectory import TrajectoryContext, start_trajectory
from ...index.base import ProvenanceIndex
from ...policy.evaluator import RequestContext
from ...policy.policy import VerificationPolicy
from ...policy.unified import Policy
from ...tool_call.admission import admission_check
from ...tool_call.context import ToolCallContext


_DEFAULT_KEYS: Dict[str, str] = {
    "query": "query",
    "documents": "documents",
    "blocked_documents": "blocked_documents",
    "receipts": "receipts",
    "trajectory": "trajectory",
    # Phase 2 admission node keys.
    "tool_parameters": "tool_parameters",
    "tool_admitted": "tool_admitted",
    "tool_decision": "tool_decision",
    "tool_rules_fired": "tool_rules_fired",
}


def _resolve_keys(custom: Optional[Mapping[str, str]]) -> Dict[str, str]:
    if not custom:
        return dict(_DEFAULT_KEYS)
    keys = dict(_DEFAULT_KEYS)
    for k, v in custom.items():
        if k not in _DEFAULT_KEYS:
            raise KeyError(
                f"unknown state_keys override {k!r}; valid keys are "
                f"{sorted(_DEFAULT_KEYS)}"
            )
        keys[k] = v
    return keys


def _document_text(doc: Any) -> str:
    """Extract chunk text from a LangChain Document, a raw string, or a dict
    with a ``"page_content"`` / ``"content"`` field."""
    if hasattr(doc, "page_content"):
        return doc.page_content
    if isinstance(doc, str):
        return doc
    if isinstance(doc, dict):
        for k in ("page_content", "content", "text"):
            if k in doc and isinstance(doc[k], str):
                return doc[k]
    raise TypeError(
        "Cannot extract text from retrieved object: expected a Document "
        "with .page_content, a string, or a dict with page_content/content/text"
    )


def start_trajectory_state(
    agent_id: Optional[str] = None,
    step_kind: Optional[str] = None,
    state_keys: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Build a state delta that initialises a fresh trajectory.

    Use this once at the start of a LangGraph flow to seed the state with
    a trajectory cursor and an empty receipts list. Subsequent nodes that
    emit receipts will advance the cursor and append to the list.

    Args:
        agent_id: Optional agent identifier carried on every step receipt.
        step_kind: Optional default step kind. Per-step kinds usually
            override this in the node implementation.
        state_keys: Optional remapping of state keys (see module docstring).

    Returns:
        A dict suitable for returning from a LangGraph node:
        ``{"trajectory": <ctx>, "receipts": []}`` (with whatever key names
        the caller specified).
    """
    keys = _resolve_keys(state_keys)
    return {
        keys["trajectory"]: start_trajectory(
            agent_id=agent_id, step_kind=step_kind
        ),
        keys["receipts"]: [],
    }


def record_step_receipt(
    state: Mapping[str, Any],
    receipt: ProvenanceReceipt,
    step_kind: Optional[str] = None,
    agent_id: Optional[str] = None,
    state_keys: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Build a state delta appending a receipt and advancing the trajectory.

    Use this in custom LangGraph nodes that produce a Provenex receipt
    without going through :func:`provenex_retrieval_node` (for example, a
    memory-read node or a tool-call node).

    Args:
        state: The current LangGraph state. Read-only; the function does
            not mutate it.
        receipt: The just-produced :class:`ProvenanceReceipt`. Will be
            appended to ``state["receipts"]``.
        step_kind: Optional step kind to record on the *next* trajectory
            cursor (the one that will be used by the following step).
        agent_id: Optional agent override for the next cursor. Defaults to
            inheriting from the current cursor.
        state_keys: Optional state-key remapping.

    Returns:
        A dict suitable for returning from a LangGraph node:
        ``{"receipts": [...append-merged...], "trajectory": <next_ctx>}``.

    Note:
        LangGraph's default state-merge semantics replace list-valued keys
        rather than appending. If you want true append semantics, declare
        the ``receipts`` key on your state with an ``operator.add`` reducer
        (LangGraph supports this via ``Annotated[list, operator.add]``).
        For simple linear flows, returning the full accumulated list (as
        this helper does) works without that wiring.
    """
    keys = _resolve_keys(state_keys)
    current_receipts = list(state.get(keys["receipts"], []))
    current_receipts.append(receipt)
    current_trajectory: Optional[TrajectoryContext] = state.get(keys["trajectory"])
    if current_trajectory is None:
        next_trajectory = start_trajectory(
            agent_id=agent_id, step_kind=step_kind
        ).next_step(parent_step_ids=[receipt.receipt_id], step_kind=step_kind)
    else:
        next_trajectory = current_trajectory.next_step(
            parent_receipts=[receipt],
            step_kind=step_kind,
            agent_id=agent_id,
        )
    return {
        keys["receipts"]: current_receipts,
        keys["trajectory"]: next_trajectory,
    }


def provenex_retrieval_node(
    base_retriever: Any,
    index: ProvenanceIndex,
    policy: Optional[VerificationPolicy] = None,
    signer: Optional[ReceiptSigner] = None,
    fingerprinter: Optional[Fingerprinter] = None,
    step_kind: str = "retrieval",
    agent_id: Optional[str] = None,
    state_keys: Optional[Mapping[str, str]] = None,
    sink: Any = None,
) -> Callable[[Mapping[str, Any]], Dict[str, Any]]:
    """Build a LangGraph retrieval node that emits trajectory-linked receipts.

    The returned callable reads the query from state, invokes the
    underlying retriever, verifies each returned chunk against the
    Provenex index, applies the policy, builds a trajectory-aware signed
    receipt, and returns a state delta with kept documents, blocked
    documents, the receipt appended, and the trajectory cursor advanced.

    Args:
        base_retriever: Any retriever exposing ``invoke(query)`` or
            ``get_relevant_documents(query)``. Same duck-typing as the
            LangChain wrapper.
        index: The :class:`ProvenanceIndex` to verify against.
        policy: Verification policy. Defaults to a sensible production
            policy.
        signer: Optional :class:`ReceiptSigner`. Unsigned in dev; sign in
            production.
        fingerprinter: Optional custom fingerprinter; must match the one
            used at ingest time.
        step_kind: The ``step_kind`` recorded on this node's trajectory
            block. Defaults to ``"retrieval"``.
        agent_id: Optional agent identifier override for this node.
        state_keys: Optional state-key remapping (see module docstring).

    Returns:
        A LangGraph-compatible node function: ``(state) -> state_delta``.

    Example:
        >>> from langgraph.graph import StateGraph  # doctest: +SKIP
        >>> retrieve = provenex_retrieval_node(my_retriever, index=idx)
        >>> graph.add_node("retrieve", retrieve)  # doctest: +SKIP
    """
    keys = _resolve_keys(state_keys)
    pol = policy or VerificationPolicy()
    fp = fingerprinter or Fingerprinter(FingerprinterConfig())

    def _invoke(query: str) -> List[Any]:
        if hasattr(base_retriever, "invoke"):
            try:
                return list(base_retriever.invoke(query))
            except TypeError:
                pass
        if hasattr(base_retriever, "get_relevant_documents"):
            return list(base_retriever.get_relevant_documents(query))
        raise TypeError(
            "base_retriever does not expose a recognized retrieval method "
            "(invoke() or get_relevant_documents())"
        )

    def node(state: Mapping[str, Any]) -> Dict[str, Any]:
        query = state.get(keys["query"])
        if not isinstance(query, str):
            raise TypeError(
                f"state[{keys['query']!r}] must be a string query, got "
                f"{type(query).__name__}"
            )

        # Trajectory: either continue from existing cursor or start fresh.
        trajectory_ctx: Optional[TrajectoryContext] = state.get(keys["trajectory"])
        if trajectory_ctx is None:
            trajectory_ctx = start_trajectory(
                agent_id=agent_id, step_kind=step_kind
            )

        retrieved = _invoke(query)
        builder = ReceiptBuilder(policy=pol)
        kept: List[Any] = []
        blocked: List[Any] = []

        for doc in retrieved:
            text = _document_text(doc)
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
            if pol.should_block(outcome):
                blocked.append(doc)
            else:
                kept.append(doc)

        # Stamp the factory-configured step_kind / agent_id onto the
        # emitted trajectory block. Previously the factory's step_kind
        # parameter only fired on a freshly-created trajectory; if the
        # caller seeded the cursor elsewhere (the common case in
        # multi-node graphs), the emitted receipt's step_kind was
        # whatever was on the cursor — usually None. Per-emission
        # override mirrors what ``verify_chunks(step_kind=...)`` does
        # and is what the factory's API contract has always implied.
        emit_trajectory = TrajectoryContext(
            trajectory_id=trajectory_ctx.trajectory_id,
            step_index=trajectory_ctx.step_index,
            trajectory_started_at=trajectory_ctx.trajectory_started_at,
            parent_step_ids=trajectory_ctx.parent_step_ids,
            step_kind=step_kind,
            agent_id=agent_id if agent_id is not None else trajectory_ctx.agent_id,
        )
        receipt = builder.finalize(
            output_text="",
            signer=signer,
            trajectory=emit_trajectory,
        )

        # 0.6.6+: ship to downstream sink; swallow + log on failure.
        from ...export.streaming import _safe_publish

        _safe_publish(sink, receipt)

        # Advance trajectory cursor for the next step in the graph.
        next_ctx = trajectory_ctx.next_step(
            parent_receipts=[receipt],
            agent_id=agent_id,
        )

        previous_receipts = list(state.get(keys["receipts"], []))
        previous_receipts.append(receipt)

        return {
            keys["documents"]: kept,
            keys["blocked_documents"]: blocked,
            keys["receipts"]: previous_receipts,
            keys["trajectory"]: next_ctx,
        }

    return node


# --------------------------------------------------------------------------- #
# Phase 2: tool-call admission node                                           #
# --------------------------------------------------------------------------- #


# A request factory: turns the LangGraph state into a RequestContext.
# Provenex does not own identity; the host application supplies caller /
# jurisdiction / purpose / timestamp by reading them off whatever state
# field the graph happens to use.
RequestFactory = Callable[[Mapping[str, Any]], RequestContext]


def provenex_admission_node(
    *,
    name: str,
    policy: Any,
    request_factory: RequestFactory,
    operation: str = "invoke",
    target_system: Optional[str] = None,
    params_extractor: Optional[Callable[[Mapping[str, Any]], Dict[str, Any]]] = None,
    signer: Optional[ReceiptSigner] = None,
    step_kind: str = "tool_call",
    agent_id: Optional[str] = None,
    redact_parameters: bool = False,
    state_keys: Optional[Mapping[str, str]] = None,
    sink: Any = None,
) -> Callable[[Mapping[str, Any]], Dict[str, Any]]:
    """Build a LangGraph tool-call admission node.

    The returned callable runs admission against the supplied unified
    :class:`Policy`'s ``tool_call_control`` half, emits a signed
    trajectory-linked receipt regardless of outcome, and writes the
    decision into state so a conditional edge can route execution.

    The node does NOT invoke the underlying tool. That's the load-bearing
    "decision and proof, not execution" line: routing the actual call to
    a downstream "execute" node is the graph's responsibility. The
    conventional shape is::

        graph.add_node("admit_jira", provenex_admission_node(name="jira", ...))
        graph.add_node("execute_jira", _your_actual_jira_node)
        graph.add_node("denied", _audit_log_node)
        graph.add_conditional_edges(
            "admit_jira",
            lambda s: "execute_jira" if s["tool_admitted"] else "denied",
        )

    Args:
        name: Tool identifier evaluated against ``tool.name`` in policy.
        policy: A unified :class:`Policy`. Only the
            ``tool_call_control`` half drives admission; the other
            halves are recorded on the receipt unchanged.
        request_factory: Callable that takes the current state and
            returns a :class:`RequestContext`. The seam where the host
            application injects caller identity from auth / IdP /
            session.
        operation: Default operation string. Overridable per-step by
            placing an ``"__operation__"`` key in state (consumed before
            being passed to admission).
        target_system: Default target system. Overridable per-step by
            placing an ``"__target_system__"`` key in state.
        params_extractor: Optional callable that returns the parameters
            dict from state. Default: read ``state["tool_parameters"]``
            (after the configured state-key remap). Useful when the
            graph's parameter layout doesn't match the default key.
        signer: Optional :class:`ReceiptSigner`.
        step_kind: Trajectory step kind. Default ``"tool_call"``.
        agent_id: Optional default agent identifier.
        redact_parameters: If True, the emitted receipt has
            ``actions[i].parameters = null`` while preserving the
            ``parameters_hash``.
        state_keys: Optional state-key remapping. See module docstring.

    Returns:
        A LangGraph-compatible node function: ``(state) -> state_delta``.

    Example:
        >>> admit = provenex_admission_node(
        ...     name="jira",
        ...     policy=Policy.from_yaml("agent_policy.yaml"),
        ...     signer=HmacSha256Signer(),
        ...     operation="create_issue",
        ...     target_system="acme.atlassian.net",
        ...     request_factory=lambda s: RequestContext(
        ...         caller=s["caller"], jurisdiction=s["jurisdiction"],
        ...         purpose=s["purpose"], timestamp=s["timestamp"],
        ...     ),
        ... )
    """
    keys = _resolve_keys(state_keys)

    def node(state: Mapping[str, Any]) -> Dict[str, Any]:
        # Per-step overrides for operation / target_system / invocation_id.
        # State is a Mapping; we do not mutate it. We read keys with the
        # "__name__" prefix convention from the LangChain wrapper so
        # graphs migrating between wrappers see the same shape.
        op = state.get("__operation__", operation)
        tgt = state.get("__target_system__", target_system)
        inv_id = state.get("__invocation_id__")

        if params_extractor is not None:
            parameters = params_extractor(state)
        else:
            raw_params = state.get(keys["tool_parameters"])
            if raw_params is None:
                parameters = {}
            elif isinstance(raw_params, dict):
                parameters = dict(raw_params)
            else:
                # Single non-dict (e.g. a string from a planning node)
                # is wrapped under "input" so the receipt has a stable
                # key for the policy author to gate on.
                parameters = {"input": raw_params}

        tool_ctx = ToolCallContext(
            name=name,
            operation=op,
            parameters=parameters,
            target_system=tgt,
            invocation_id=inv_id,
        )
        request = request_factory(state)

        # Continue from existing trajectory or start fresh.
        trajectory_ctx: Optional[TrajectoryContext] = state.get(keys["trajectory"])
        if trajectory_ctx is None:
            trajectory_ctx = start_trajectory(
                agent_id=agent_id, step_kind=step_kind
            )

        result = admission_check(
            tool=tool_ctx,
            request=request,
            policy=policy,
            signer=signer,
            trajectory=trajectory_ctx,
            step_kind=step_kind,
            agent_id=agent_id,
            redact_parameters=redact_parameters,
            sink=sink,
        )

        previous_receipts = list(state.get(keys["receipts"], []))
        previous_receipts.append(result.receipt)

        assert result.next_trajectory is not None  # we supplied trajectory
        return {
            keys["tool_admitted"]: result.allowed,
            keys["tool_decision"]: result.decision,
            keys["tool_rules_fired"]: list(result.rules_fired),
            keys["receipts"]: previous_receipts,
            keys["trajectory"]: result.next_trajectory,
        }

    return node
