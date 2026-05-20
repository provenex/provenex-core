"""Policy simulator: replay historic decisions under a proposed new policy.

The Phase 4.1 SR-11-7 / Model Risk workflow primitive. Reads a
directory of previously-issued receipts (each carries the verbatim
``inputs`` block per decision, when not redacted), re-evaluates each
decision against a proposed new policy file, and reports which
decisions flip allow → deny or deny → allow.

Pure local computation. No HTTP, no signer, no index. The receipts'
embedded ``inputs`` is all that's needed; the canonical-payload
``inputs_hash`` makes the inputs independently verifiable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .evaluator import (
    DECISION_ALLOW,
    DECISION_DENY,
    ChunkContext,
    RequestContext,
)
from .unified import Policy


@dataclass
class DecisionFlip:
    """One decision whose verdict changed under the new policy."""

    receipt_id: Optional[str]
    chunk_fingerprint: str
    original_decision: str
    new_decision: str
    original_rules_fired: List[str] = field(default_factory=list)
    new_rules_fired: List[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        if self.original_decision == DECISION_ALLOW and self.new_decision == DECISION_DENY:
            return "allow_to_deny"
        if self.original_decision == DECISION_DENY and self.new_decision == DECISION_ALLOW:
            return "deny_to_allow"
        return "other"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "chunk_fingerprint": self.chunk_fingerprint,
            "original_decision": self.original_decision,
            "new_decision": self.new_decision,
            "original_rules_fired": list(self.original_rules_fired),
            "new_rules_fired": list(self.new_rules_fired),
            "kind": self.kind,
        }


@dataclass
class SimulationReport:
    """Aggregate of one simulation run over a corpus of receipts."""

    receipts_examined: int = 0
    decisions_examined: int = 0
    decisions_skipped_redacted: int = 0
    flips: List[DecisionFlip] = field(default_factory=list)

    @property
    def allow_to_deny(self) -> List[DecisionFlip]:
        return [f for f in self.flips if f.kind == "allow_to_deny"]

    @property
    def deny_to_allow(self) -> List[DecisionFlip]:
        return [f for f in self.flips if f.kind == "deny_to_allow"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipts_examined": self.receipts_examined,
            "decisions_examined": self.decisions_examined,
            "decisions_skipped_redacted": self.decisions_skipped_redacted,
            "flips_total": len(self.flips),
            "flips_allow_to_deny": len(self.allow_to_deny),
            "flips_deny_to_allow": len(self.deny_to_allow),
            "flips": [f.to_dict() for f in self.flips],
        }

    def to_human_diff(self) -> str:
        lines = [
            "## Policy simulation diff",
            f"- receipts examined: {self.receipts_examined}",
            f"- decisions examined: {self.decisions_examined}",
            f"- decisions skipped (inputs redacted): {self.decisions_skipped_redacted}",
            f"- total flips: {len(self.flips)}",
            f"  - allow -> deny: {len(self.allow_to_deny)}",
            f"  - deny -> allow: {len(self.deny_to_allow)}",
            "",
        ]
        for f in self.flips:
            lines.append(
                f"  {f.kind:>14s}  {f.chunk_fingerprint[:20]}... "
                f"({f.original_decision} -> {f.new_decision}; "
                f"new rules: {','.join(f.new_rules_fired) or '-'})"
            )
        return "\n".join(lines) + "\n"


def _iter_receipts(path: Path) -> Iterator[Tuple[Path, Dict[str, Any]]]:
    """Yield ``(file_path, parsed_receipt_json)`` pairs."""
    if path.is_file():
        candidates: List[Path] = [path]
    else:
        candidates = sorted(path.rglob("*.json"))
    for p in candidates:
        try:
            with open(p, "r", encoding="utf-8") as f:
                body = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(body, dict):
            continue
        yield p, body


def _reconstruct_contexts(
    inputs: Dict[str, Any],
    metadata_binding: Optional[Dict[str, str]] = None,
) -> Tuple[ChunkContext, RequestContext]:
    """Rebuild ChunkContext + RequestContext from a serialised inputs block.

    Mirrors :func:`provenex.policy.evaluator._build_inputs` in reverse.
    Anything missing falls back to ``None`` / ``{}``, which the
    evaluator handles via its ``defaults.unknown_metadata`` policy.
    """
    chunk_meta = dict(inputs.get("chunk_metadata") or {})
    ingested_at = chunk_meta.pop("ingested_at", None)
    content_source = chunk_meta.pop("content_source", None)
    chunk_ctx = ChunkContext(
        fingerprint="",  # not needed at evaluate time
        document_id=None,
        document_version=None,
        ingested_at=ingested_at,
        metadata=chunk_meta,
        content_source=content_source,
    )

    req = inputs.get("request_context") or {}
    request_ctx = RequestContext(
        caller=dict(req.get("caller") or {}),
        jurisdiction=req.get("jurisdiction"),
        purpose=req.get("purpose"),
        timestamp=req.get("timestamp"),
    )
    return chunk_ctx, request_ctx


def simulate(
    new_policy: Policy,
    receipts_path: Path,
) -> SimulationReport:
    """Replay decisions against ``new_policy``; report which ones flip.

    Args:
        new_policy: The proposed new :class:`Policy`. Only the
            ``access_control`` half is consulted (verification rules
            are outcome-driven, not policy-evaluated).
        receipts_path: Directory or file path. Each ``.json`` under the
            path is parsed as a receipt; any file that isn't a JSON
            object is silently skipped.

    Returns:
        A :class:`SimulationReport` aggregating the run.

    Raises:
        ValueError: If ``new_policy`` has no access_control configured;
            then there's nothing to simulate (every decision would be
            allow-by-default).
    """
    if new_policy.access_control is None:
        raise ValueError(
            "simulate: new_policy.access_control is None; nothing to simulate."
        )
    report = SimulationReport()

    for _, body in _iter_receipts(receipts_path):
        report.receipts_examined += 1
        receipt_id = body.get("receipt_id")
        policy_block = (body.get("policy") or {}).get("access_control") or {}
        decisions = policy_block.get("decisions") or []
        if not decisions:
            continue
        for d in decisions:
            report.decisions_examined += 1
            inputs = d.get("inputs")
            if inputs is None:
                report.decisions_skipped_redacted += 1
                continue
            chunk_ctx, request_ctx = _reconstruct_contexts(inputs)
            new = new_policy.access_control.evaluate(chunk_ctx, request_ctx)
            original = d.get("decision")
            if new.decision != original:
                report.flips.append(
                    DecisionFlip(
                        receipt_id=receipt_id,
                        chunk_fingerprint=d.get("chunk_fingerprint", ""),
                        original_decision=original or "",
                        new_decision=new.decision,
                        original_rules_fired=list(d.get("rules_fired") or []),
                        new_rules_fired=list(new.rules_fired),
                    )
                )
    return report
