"""OCSF v1.3 mapping for Provenex receipts (0.6.7+).

Pure JSON shape-shifting. One signed receipt maps to one or more
events in the Open Cybersecurity Schema Framework (OCSF) — the
emerging cross-vendor standard for security events that Splunk,
Datadog, Elastic, Microsoft Sentinel, and others consume.

This module is the implementation of the public mapping spec
documented in [`docs/ocsf_mapping.md`](../../docs/ocsf_mapping.md).
The spec is the artifact a SIEM vendor or enterprise security
architect reads to wire Provenex into their pipeline; this code is
the executable spec.

OCSF version targeted: **v1.3.0**.

Class mapping at a glance:

    * Tool-call admission (admit_memory_write,
      admit_model_inference, raw admission_check) → **API Activity
      (class_uid 6003)** on allow.
    * Retrieval verification (verify_chunks, verify_memory)
      → **Application Activity (class_uid 6005)** per allowed source.
    * Any **block** or **deny** → **Detection Finding
      (class_uid 2004)**.

Why these classes (and why NOT yet AI-specific OCSF classes):
OCSF AI/LLM classes are still emerging. We map to the existing
closest classes now — receipts don't change. When AI-specific
classes stabilize, this module is the only thing that needs
updating.

Trajectory metadata flows as ``metadata.correlation_uid`` (the
trajectory_id) and ``metadata.session_uid`` (the session_id, when
present). No separate trajectory event is emitted; OCSF's
correlation_uid is exactly the multi-event correlator SIEMs join on.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# OCSF v1.3 class identifiers we target. Kept as module constants for
# discoverability and so a downstream consumer can ``from
# provenex.export.ocsf import OCSF_CLASS_*`` for switch-table style
# dispatch.
OCSF_CLASS_APPLICATION_ACTIVITY = 6005
OCSF_CLASS_API_ACTIVITY = 6003
OCSF_CLASS_DETECTION_FINDING = 2004

OCSF_CATEGORY_APPLICATION_ACTIVITY = 6
OCSF_CATEGORY_FINDINGS = 2

# OCSF activity-id within the chosen class. We pick the most precise
# match the spec offers for the action we're mirroring.
_OCSF_ACTIVITY_ACCESS = 1
_OCSF_ACTIVITY_CREATE = 1
_OCSF_ACTIVITY_OTHER = 99

# OCSF severity-id values. Used for both Detection Finding and
# Application Activity events.
_OCSF_SEVERITY_INFORMATIONAL = 1
_OCSF_SEVERITY_LOW = 2
_OCSF_SEVERITY_MEDIUM = 3
_OCSF_SEVERITY_HIGH = 4
_OCSF_SEVERITY_CRITICAL = 5

# OCSF status-id values.
_OCSF_STATUS_SUCCESS = 1
_OCSF_STATUS_FAILURE = 2

# Provenex-emitted event codes — used on ``metadata.event_code`` so a
# downstream rule can fire on Provenex events specifically without
# inspecting the rest of the payload.
_EVENT_CODE_VERIFICATION_ALLOW = "provenex.verification.allow"
_EVENT_CODE_VERIFICATION_BLOCK = "provenex.verification.block"
_EVENT_CODE_ADMISSION_ALLOW = "provenex.admission.allow"
_EVENT_CODE_ADMISSION_DENY = "provenex.admission.deny"


# --------------------------------------------------------------------------- #
# Top-level entry point                                                       #
# --------------------------------------------------------------------------- #


def receipt_to_ocsf(
    receipt: Dict[str, Any],
    *,
    include_trajectory_correlator: bool = True,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Map one Provenex receipt to one or more OCSF v1.3 events.

    The mapping is deterministic and side-effect-free. Returns a list:

        * One :data:`OCSF_CLASS_APPLICATION_ACTIVITY` event per allowed
          source (chunk that passed both gates).
        * One :data:`OCSF_CLASS_DETECTION_FINDING` event per blocked
          source.
        * One :data:`OCSF_CLASS_API_ACTIVITY` event per allowed action.
        * One :data:`OCSF_CLASS_DETECTION_FINDING` event per denied
          action.

    A receipt with three sources (two allowed + one blocked) plus one
    allowed action emits four events. A receipt with no sources and
    no actions emits zero events.

    Args:
        receipt: Parsed receipt dict, typically
            ``json.loads(receipt.to_json())`` or
            ``receipt.to_dict()``.
        include_trajectory_correlator: When True (default), emit
            ``metadata.correlation_uid = trajectory.trajectory_id`` on
            every event so downstream consumers can JOIN events from
            one DAG. Set False to suppress (useful when the
            correlation is implicit in single-step receipts).
        extra_metadata: Optional dict merged into every emitted
            event's ``metadata`` block. Use for deployment-level tags
            (``organization_uid``, ``environment``, ``tenant``).

    Returns:
        A list of OCSF event dicts ready to JSON-serialise and ship.
        Empty list when the receipt records nothing actionable.
    """
    events: List[Dict[str, Any]] = []

    sources = receipt.get("sources", []) or []
    actions = receipt.get("actions", []) or []
    access_control = (receipt.get("policy") or {}).get("access_control") or {}
    tool_call_control = (receipt.get("policy") or {}).get("tool_call_control") or {}

    # Per-source events. The verification outcome + access-control
    # decision together determine whether the chunk was blocked.
    ac_decisions = access_control.get("decisions") or []
    ac_decisions_by_fp: Dict[str, Dict[str, Any]] = {
        d.get("chunk_fingerprint"): d for d in ac_decisions if d.get("chunk_fingerprint")
    }
    for source in sources:
        decision = ac_decisions_by_fp.get(source.get("fingerprint"))
        if _is_source_blocked(receipt, source, decision):
            events.append(
                receipt_to_detection_finding_for_blocked_source(
                    receipt,
                    source,
                    decision,
                    include_trajectory_correlator=include_trajectory_correlator,
                    extra_metadata=extra_metadata,
                )
            )
        else:
            events.append(
                receipt_to_application_activity(
                    receipt,
                    source,
                    decision,
                    include_trajectory_correlator=include_trajectory_correlator,
                    extra_metadata=extra_metadata,
                )
            )

    # Per-action events. The tool-call-control decision determines
    # allow / deny.
    tcc_decisions = tool_call_control.get("decisions") or []
    tcc_decisions_by_idx: Dict[int, Dict[str, Any]] = {
        d.get("action_index"): d for d in tcc_decisions if "action_index" in d
    }
    for action in actions:
        decision = tcc_decisions_by_idx.get(action.get("action_index"))
        if decision is not None and decision.get("decision") == "deny":
            events.append(
                receipt_to_detection_finding_for_denied_action(
                    receipt,
                    action,
                    decision,
                    include_trajectory_correlator=include_trajectory_correlator,
                    extra_metadata=extra_metadata,
                )
            )
        else:
            events.append(
                receipt_to_api_activity(
                    receipt,
                    action,
                    decision,
                    include_trajectory_correlator=include_trajectory_correlator,
                    extra_metadata=extra_metadata,
                )
            )

    return events


# --------------------------------------------------------------------------- #
# Per-event-class helpers (lower-level public API)                            #
# --------------------------------------------------------------------------- #


def receipt_to_application_activity(
    receipt: Dict[str, Any],
    source: Dict[str, Any],
    decision: Optional[Dict[str, Any]] = None,
    *,
    include_trajectory_correlator: bool = True,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one OCSF Application Activity (6005) event for an allowed source."""
    event = _base_event(
        receipt,
        class_uid=OCSF_CLASS_APPLICATION_ACTIVITY,
        class_name="Application Activity",
        category_uid=OCSF_CATEGORY_APPLICATION_ACTIVITY,
        category_name="Application Activity",
        activity_id=_OCSF_ACTIVITY_ACCESS,
        activity_name="Access",
        severity_id=_OCSF_SEVERITY_INFORMATIONAL,
        severity="Informational",
        event_code=_EVENT_CODE_VERIFICATION_ALLOW,
        include_trajectory_correlator=include_trajectory_correlator,
        extra_metadata=extra_metadata,
    )
    event["status_id"] = _OCSF_STATUS_SUCCESS
    event["status"] = "Success"
    event["resources"] = [_resource_from_source(source)]

    # Step-kind label so a detector can filter retrieval-shape vs
    # memory-read-shape events without parsing the full receipt.
    _add_step_kind_label(event, receipt)
    _add_verification_outcome_label(event, source)

    # Access-control policy context — only when policy was configured.
    if decision is not None:
        _attach_access_control_decision_to_metadata(event["metadata"], decision)
    _attach_access_control_policy_to_metadata(
        event["metadata"], (receipt.get("policy") or {}).get("access_control")
    )
    return event


def receipt_to_detection_finding_for_blocked_source(
    receipt: Dict[str, Any],
    source: Dict[str, Any],
    decision: Optional[Dict[str, Any]] = None,
    *,
    include_trajectory_correlator: bool = True,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one OCSF Detection Finding (2004) event for a blocked source.

    Block source: either verification (TAMPERED / UNAUTHORIZED+block /
    UNVERIFIED+block / STALE+block) or access-control deny.
    """
    outcome = source.get("verification_outcome")
    blocked_by_verification = outcome in {"TAMPERED", "UNAUTHORIZED", "UNVERIFIED", "STALE"}
    blocked_by_policy = decision is not None and decision.get("decision") == "deny"

    if blocked_by_verification:
        severity_id, severity = _OCSF_SEVERITY_CRITICAL, "Critical"
        finding_types = [outcome]
        rule_names: List[str] = []
        title = f"Verification block: {outcome}"
    elif blocked_by_policy:
        severity_id, severity = _OCSF_SEVERITY_HIGH, "High"
        finding_types = ["ACCESS_CONTROL_DENY"]
        rule_names = list(decision.get("rules_fired") or [])
        title = (
            "Access control denied chunk"
            + (f"; rules: {', '.join(rule_names)}" if rule_names else "")
        )
    else:
        severity_id, severity = _OCSF_SEVERITY_MEDIUM, "Medium"
        finding_types = [outcome or "UNKNOWN"]
        rule_names = []
        title = "Source blocked (unspecified)"

    event = _base_event(
        receipt,
        class_uid=OCSF_CLASS_DETECTION_FINDING,
        class_name="Detection Finding",
        category_uid=OCSF_CATEGORY_FINDINGS,
        category_name="Findings",
        activity_id=_OCSF_ACTIVITY_CREATE,
        activity_name="Create",
        severity_id=severity_id,
        severity=severity,
        event_code=_EVENT_CODE_VERIFICATION_BLOCK,
        include_trajectory_correlator=include_trajectory_correlator,
        extra_metadata=extra_metadata,
    )
    event["status_id"] = _OCSF_STATUS_SUCCESS
    event["status"] = "Success"
    event["finding_info"] = {
        "uid": receipt.get("receipt_id"),
        "title": title,
        "types": finding_types,
    }
    if decision is not None:
        related: List[Dict[str, Any]] = []
        if decision.get("inputs_hash"):
            related.append({"uid": decision["inputs_hash"], "type": "policy_inputs_hash"})
        if related:
            event["finding_info"]["related_events"] = related
    event["resources"] = [_resource_from_source(source)]
    _add_step_kind_label(event, receipt)
    _add_verification_outcome_label(event, source)
    if rule_names:
        _add_label(event, "rules_fired", ",".join(rule_names))
    _attach_access_control_policy_to_metadata(
        event["metadata"], (receipt.get("policy") or {}).get("access_control")
    )
    return event


def receipt_to_api_activity(
    receipt: Dict[str, Any],
    action: Dict[str, Any],
    decision: Optional[Dict[str, Any]] = None,
    *,
    include_trajectory_correlator: bool = True,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one OCSF API Activity (6003) event for an allowed action."""
    event = _base_event(
        receipt,
        class_uid=OCSF_CLASS_API_ACTIVITY,
        class_name="API Activity",
        category_uid=OCSF_CATEGORY_APPLICATION_ACTIVITY,
        category_name="Application Activity",
        activity_id=_OCSF_ACTIVITY_CREATE,
        activity_name="Create",
        severity_id=_OCSF_SEVERITY_INFORMATIONAL,
        severity="Informational",
        event_code=_EVENT_CODE_ADMISSION_ALLOW,
        include_trajectory_correlator=include_trajectory_correlator,
        extra_metadata=extra_metadata,
    )
    event["status_id"] = _OCSF_STATUS_SUCCESS
    event["status"] = "Success"

    api_block: Dict[str, Any] = {
        "operation": action.get("operation"),
        "service": _service_from_action(action),
        "request": {"uid": action.get("parameters_hash")},
    }
    event["api"] = api_block
    _add_step_kind_label(event, receipt)
    if decision is not None:
        rules = decision.get("rules_fired") or []
        if rules:
            _add_label(event, "rules_fired", ",".join(rules))
        _attach_tool_call_control_decision_to_metadata(event["metadata"], decision)
    _attach_tool_call_control_policy_to_metadata(
        event["metadata"], (receipt.get("policy") or {}).get("tool_call_control")
    )
    return event


def receipt_to_detection_finding_for_denied_action(
    receipt: Dict[str, Any],
    action: Dict[str, Any],
    decision: Dict[str, Any],
    *,
    include_trajectory_correlator: bool = True,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one OCSF Detection Finding (2004) event for a denied action."""
    rule_names = list(decision.get("rules_fired") or [])
    title = (
        "Tool-call admission denied"
        + (f"; rules: {', '.join(rule_names)}" if rule_names else "")
    )

    event = _base_event(
        receipt,
        class_uid=OCSF_CLASS_DETECTION_FINDING,
        class_name="Detection Finding",
        category_uid=OCSF_CATEGORY_FINDINGS,
        category_name="Findings",
        activity_id=_OCSF_ACTIVITY_CREATE,
        activity_name="Create",
        severity_id=_OCSF_SEVERITY_HIGH,
        severity="High",
        event_code=_EVENT_CODE_ADMISSION_DENY,
        include_trajectory_correlator=include_trajectory_correlator,
        extra_metadata=extra_metadata,
    )
    event["status_id"] = _OCSF_STATUS_SUCCESS
    event["status"] = "Success"
    event["finding_info"] = {
        "uid": receipt.get("receipt_id"),
        "title": title,
        "types": ["ADMISSION_DENY"],
    }
    related: List[Dict[str, Any]] = []
    if decision.get("inputs_hash"):
        related.append({"uid": decision["inputs_hash"], "type": "policy_inputs_hash"})
    if action.get("parameters_hash"):
        related.append(
            {"uid": action["parameters_hash"], "type": "action_parameters_hash"}
        )
    if related:
        event["finding_info"]["related_events"] = related
    event["api"] = {
        "operation": action.get("operation"),
        "service": _service_from_action(action),
        "request": {"uid": action.get("parameters_hash")},
    }
    _add_step_kind_label(event, receipt)
    if rule_names:
        _add_label(event, "rules_fired", ",".join(rule_names))
    _attach_tool_call_control_policy_to_metadata(
        event["metadata"], (receipt.get("policy") or {}).get("tool_call_control")
    )
    return event


# --------------------------------------------------------------------------- #
# Streaming sink adapter                                                      #
# --------------------------------------------------------------------------- #


class OCSFAdapter:
    """ReceiptSink wrapper that emits OCSF events to a downstream ReceiptSink.

    Composes any :class:`provenex.ReceiptSink` (StdoutJSONLSink,
    FileJSONLSink, KafkaSink, SQSSink, S3AppendSink, PubSubSink, your
    own custom sink) into an OCSF emitter. Each incoming receipt is
    converted via :func:`receipt_to_ocsf` and every resulting OCSF
    event is forwarded to the downstream sink.

    Because OCSF events are dicts (not :class:`ProvenanceReceipt`
    instances), the adapter wraps each event in a tiny carrier that
    duck-types the receipt interface
    (``to_json(indent=...)`` / ``to_dict()`` / ``receipt_id``) so the
    downstream sink doesn't need to know it's not getting a real
    receipt. The carrier's ``receipt_id`` is the parent receipt's id,
    which makes correlating OCSF events back to source receipts easy
    in log lines.

    Usage:

        from provenex import FileJSONLSink
        from provenex.export.ocsf import OCSFAdapter

        ocsf_sink = OCSFAdapter(
            downstream=FileJSONLSink("/var/log/provenex/ocsf"),
            extra_metadata={"organization_uid": "acme-corp"},
        )
        admission_check(..., sink=ocsf_sink)

    Args:
        downstream: The underlying :class:`ReceiptSink` to forward
            OCSF events to.
        include_trajectory_correlator: Passed through to
            :func:`receipt_to_ocsf`.
        extra_metadata: Passed through to :func:`receipt_to_ocsf`.
    """

    def __init__(
        self,
        downstream: Any,
        *,
        include_trajectory_correlator: bool = True,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._downstream = downstream
        self._include_traj = include_trajectory_correlator
        self._extra_metadata = extra_metadata
        self._closed = False

    def publish(self, receipt: Any) -> None:
        if self._closed:
            from .streaming import SinkClosedError

            raise SinkClosedError("OCSFAdapter is closed")
        events = receipt_to_ocsf(
            receipt.to_dict(),
            include_trajectory_correlator=self._include_traj,
            extra_metadata=self._extra_metadata,
        )
        parent_id = receipt.receipt_id
        for event in events:
            self._downstream.publish(_OCSFEventCarrier(event, parent_id))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._downstream.close()
        except Exception:
            pass


class _OCSFEventCarrier:
    """Tiny receipt-like wrapper around an OCSF event dict.

    Exposes the subset of the receipt interface every downstream
    sink uses: ``to_json(indent=...)``, ``to_dict()``, and
    ``receipt_id`` (set to the parent receipt's id for backtracking).
    """

    def __init__(self, event: Dict[str, Any], parent_receipt_id: str) -> None:
        self._event = event
        self.receipt_id = parent_receipt_id

    def to_json(self, indent: Optional[int] = None) -> str:
        return json.dumps(self._event, indent=indent, sort_keys=False)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._event)


# --------------------------------------------------------------------------- #
# Internal helpers                                                            #
# --------------------------------------------------------------------------- #


def _base_event(
    receipt: Dict[str, Any],
    *,
    class_uid: int,
    class_name: str,
    category_uid: int,
    category_name: str,
    activity_id: int,
    activity_name: str,
    severity_id: int,
    severity: str,
    event_code: str,
    include_trajectory_correlator: bool,
    extra_metadata: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the OCSF skeleton shared by every emitted event."""
    metadata = _build_metadata(
        receipt,
        include_trajectory_correlator=include_trajectory_correlator,
        extra_metadata=extra_metadata,
        event_code=event_code,
    )
    event: Dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": severity_id,
        "severity": severity,
        "metadata": metadata,
        "actor": _actor_from_receipt(receipt),
    }
    # OCSF requires a time field. We parse the receipt's issued_at
    # into epoch milliseconds; the original ISO-8601 string flows
    # through as time_dt for SIEMs that prefer string timestamps.
    issued_at = receipt.get("issued_at")
    if issued_at:
        event["time"] = _iso8601_to_epoch_ms(issued_at)
        event["time_dt"] = issued_at
    return event


def _build_metadata(
    receipt: Dict[str, Any],
    *,
    include_trajectory_correlator: bool,
    extra_metadata: Optional[Dict[str, Any]],
    event_code: str,
) -> Dict[str, Any]:
    """Build the OCSF metadata block — shared across every event class."""
    issuer = receipt.get("issuer") or ""
    product_name, _, product_version = issuer.partition("/")
    md: Dict[str, Any] = {
        "uid": receipt.get("receipt_id"),
        "event_code": event_code,
        "version": "1.3.0",
        "product": {
            "name": product_name or "provenex-core",
            "version": product_version or "",
            "vendor_name": "Provenex",
        },
        "labels": [],
    }
    schema_ver = receipt.get("schema_version")
    if schema_ver:
        md["product"]["feature"] = {
            "name": "provenex-receipt",
            "version": schema_ver,
        }
    trajectory = receipt.get("trajectory") or {}
    if include_trajectory_correlator and trajectory.get("trajectory_id"):
        md["correlation_uid"] = trajectory["trajectory_id"]
    if trajectory.get("session_id"):
        md["session_uid"] = trajectory["session_id"]
    if extra_metadata:
        for k, v in extra_metadata.items():
            md[k] = v
    return md


def _actor_from_receipt(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """Build the OCSF actor block — caller_hash + agent_id."""
    actor: Dict[str, Any] = {}
    if receipt.get("caller_hash"):
        actor["user"] = {"uid": receipt["caller_hash"], "type_id": 1}
    trajectory = receipt.get("trajectory") or {}
    if trajectory.get("agent_id"):
        actor["process"] = {"name": trajectory["agent_id"]}
    return actor


def _resource_from_source(source: Dict[str, Any]) -> Dict[str, Any]:
    """Build an OCSF resource entry for a chunk source record."""
    resource: Dict[str, Any] = {
        "uid": source.get("document_id") or source.get("fingerprint") or "",
        "type": "document_chunk",
        "data": {"fingerprint": source.get("fingerprint")},
    }
    if source.get("document_version"):
        resource["data"]["document_version"] = source["document_version"]
    if source.get("content_source"):
        resource["data"]["content_source"] = source["content_source"]
    return resource


def _service_from_action(action: Dict[str, Any]) -> Dict[str, Any]:
    """Build an OCSF api.service entry for an action record."""
    service: Dict[str, Any] = {"name": action.get("name") or ""}
    if action.get("target_system"):
        service["labels"] = [f"target_system:{action['target_system']}"]
    return service


def _attach_access_control_decision_to_metadata(
    metadata: Dict[str, Any], decision: Dict[str, Any]
) -> None:
    """Attach per-decision access-control fields onto metadata."""
    if decision.get("inputs_hash"):
        metadata.setdefault("labels", []).append(
            f"inputs_hash:{decision['inputs_hash']}"
        )
    rules = decision.get("rules_fired") or []
    if rules:
        metadata.setdefault("labels", []).append(
            f"rules_fired:{','.join(rules)}"
        )


def _attach_tool_call_control_decision_to_metadata(
    metadata: Dict[str, Any], decision: Dict[str, Any]
) -> None:
    """Attach per-decision tool-call-control fields onto metadata."""
    _attach_access_control_decision_to_metadata(metadata, decision)


def _attach_access_control_policy_to_metadata(
    metadata: Dict[str, Any], access_control: Optional[Dict[str, Any]]
) -> None:
    if not access_control:
        return
    if access_control.get("policy_id"):
        metadata["policy_uid"] = access_control["policy_id"]
    if access_control.get("policy_version_hash"):
        metadata["policy_uid_alt"] = access_control["policy_version_hash"]


def _attach_tool_call_control_policy_to_metadata(
    metadata: Dict[str, Any], tool_call_control: Optional[Dict[str, Any]]
) -> None:
    if not tool_call_control:
        return
    if tool_call_control.get("policy_id"):
        metadata["policy_uid"] = tool_call_control["policy_id"]
    if tool_call_control.get("policy_version_hash"):
        metadata["policy_uid_alt"] = tool_call_control["policy_version_hash"]


def _add_label(event: Dict[str, Any], key: str, value: str) -> None:
    event["metadata"].setdefault("labels", []).append(f"{key}:{value}")


def _add_step_kind_label(event: Dict[str, Any], receipt: Dict[str, Any]) -> None:
    trajectory = receipt.get("trajectory") or {}
    if trajectory.get("step_kind"):
        _add_label(event, "step_kind", trajectory["step_kind"])


def _add_verification_outcome_label(event: Dict[str, Any], source: Dict[str, Any]) -> None:
    if source.get("verification_outcome"):
        _add_label(event, "verification_outcome", source["verification_outcome"])


def _is_source_blocked(
    receipt: Dict[str, Any],
    source: Dict[str, Any],
    decision: Optional[Dict[str, Any]],
) -> bool:
    """Determine whether a source was blocked under the receipt's policy.

    A chunk is blocked if either:
      * The verification policy would block its outcome (block_unauthorized,
        block_tampered, etc., on the verification block).
      * The access-control policy returned deny.

    The verification policy is on receipt.policy.verification; we read
    it to decide whether a non-VERIFIED outcome is a block or just a
    flag.
    """
    outcome = source.get("verification_outcome")
    if outcome != "VERIFIED":
        verification = (receipt.get("policy") or {}).get("verification") or {}
        # Map outcome → corresponding "block_<lower>" flag.
        flag = f"block_{outcome.lower()}" if outcome else ""
        if verification.get(flag):
            return True
    if decision is not None and decision.get("decision") == "deny":
        return True
    return False


def _iso8601_to_epoch_ms(value: str) -> int:
    """Parse an ISO-8601 UTC string (``...Z``) into epoch milliseconds."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        # Defensive: if we can't parse, fall back to "now". The
        # receipt's issued_at has been ISO-8601 since 1.0.0 so this
        # path should never fire in practice.
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


__all__ = [
    "OCSF_CLASS_APPLICATION_ACTIVITY",
    "OCSF_CLASS_API_ACTIVITY",
    "OCSF_CLASS_DETECTION_FINDING",
    "OCSF_CATEGORY_APPLICATION_ACTIVITY",
    "OCSF_CATEGORY_FINDINGS",
    "OCSFAdapter",
    "receipt_to_ocsf",
    "receipt_to_application_activity",
    "receipt_to_detection_finding_for_blocked_source",
    "receipt_to_api_activity",
    "receipt_to_detection_finding_for_denied_action",
]
