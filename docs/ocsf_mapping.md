# OCSF mapping — Provenex receipts as cross-vendor security events

This document is the public specification for how Provenex receipts
land in your SIEM. It is the artifact a SIEM vendor or enterprise
security architect reads to wire Provenex into their pipeline. The
mapping itself is implemented in [`provenex/export/ocsf.py`](../provenex/export/ocsf.py)
and is shipped with the OSS core in `provenex.export.ocsf`. The
function `receipt_to_ocsf(receipt_dict)` is the public entrypoint;
`OCSFAdapter` is the streaming-sink wrapper.

## OCSF version targeted

**v1.3.0** (the most recent stable release as of late 2025). The
mapping is forward-compatible — OCSF treats new optional fields the
same way Provenex does, so receipts produced today flow through
unchanged into v1.4 / v2.0 consumers that ignore unknown fields.

When OCSF stabilizes AI-specific event classes (6008-series "AI/ML
Operations" was draft as of late 2025; 7XXX-series for AI agent
events is being discussed), this document changes. Receipts do not
— only the mapping table moves.

## Class mapping summary

| Provenex event | OCSF class | OCSF class UID | Severity |
| --- | --- | --- | --- |
| Allowed retrieval (Phase 1) — one per allowed source on a `verify_chunks` / `verify_memory` receipt | Application Activity | **6005** | Informational (1) |
| Allowed admission (Phase 2) — one per allowed action: tool-call / `admit_memory_write` / `admit_model_inference` | API Activity | **6003** | Informational (1) |
| Blocked retrieval — verification policy blocked the chunk (TAMPERED / UNAUTHORIZED+block / UNVERIFIED+block / STALE+block) | Detection Finding | **2004** | **Critical (5)** |
| Denied access-control decision — chunk passed verification but was denied by `policy.access_control` | Detection Finding | **2004** | **High (4)** |
| Denied admission — action denied by `policy.tool_call_control` | Detection Finding | **2004** | **High (4)** |

One Provenex receipt with N sources and M actions can emit up to
N+M OCSF events. A receipt with zero of each (a pure output-hash
receipt) emits zero events.

### Why these classes (and why not yet AI-specific)

- **6005 (Application Activity)** for allowed retrievals: "verify
  chunk reached LLM" maps cleanly to "subject accessed a resource"
  — the spec's intended semantics for 6005. Every OCSF-aware SIEM
  already ingests 6005; a custom Data Access class extension would
  require vendor-side work for every SIEM.
- **6003 (API Activity)** for allowed admissions: tool calls,
  memory writes, and model inferences are all "subject invoked an
  operation on a service." 6003 is the canonical OCSF class for
  that. `api.service.name` carries the tool / memory key / model
  identifier; `api.operation` carries the operation;
  `api.service.labels` carries the target_system.
- **2004 (Detection Finding)** for all blocks / denies: a security
  control fired and stopped an event. That's the spec's semantics
  for 2004 exactly. `finding_info.types` carries the discriminator
  (`TAMPERED`, `UNVERIFIED`, `ACCESS_CONTROL_DENY`, `ADMISSION_DENY`).

When OCSF AI-specific classes ship, the mapping for admissions
(6003) likely moves; the retrieval mapping (6005) likely stays.
Receipts are unaffected.

## Severity assignment

The severity-id encoding follows the OCSF severity dictionary. Our
choices:

| Provenex condition | OCSF severity_id | OCSF severity name |
| --- | --- | --- |
| Verification block (`TAMPERED`, `UNVERIFIED+block`, etc.) | **5** | Critical |
| Policy deny (`access_control.decision="deny"` or `tool_call_control.decision="deny"`) | **4** | High |
| Other findings (catch-all) | **3** | Medium |
| Allow (every Application / API Activity event) | **1** | Informational |

The verification block → Critical reflects that fingerprint
tampering is a high-confidence integrity violation — an authorised
chunk's signature failed, or an unrecognised chunk attempted to
enter the LLM. Routing to a SOC's high-priority queue is the right
default. Policy deny → High reflects that the operator's authoring
of the policy is the trust root; a deny is intended behaviour, not
an integrity violation.

If your SOC's routing wants different thresholds, the only file
that needs to change is `provenex/export/ocsf.py` — the receipts
themselves are unchanged.

## Field-by-field — Application Activity (6005, allowed retrieval)

```json
{
  "class_uid": 6005,
  "class_name": "Application Activity",
  "category_uid": 6,
  "category_name": "Application Activity",
  "activity_id": 1,
  "activity_name": "Access",
  "type_uid": 600501,
  "severity_id": 1,
  "severity": "Informational",
  "status_id": 1,
  "status": "Success",
  "time": 1747308600000,
  "time_dt": "2026-05-15T11:30:00.000Z",
  "metadata": {
    "uid": "prx_…",
    "event_code": "provenex.verification.allow",
    "version": "1.3.0",
    "product": {
      "name": "provenex-core",
      "version": "0.6.7",
      "vendor_name": "Provenex",
      "feature": { "name": "provenex-receipt", "version": "2.3.0" }
    },
    "correlation_uid": "trj_…",
    "session_uid": "incident-2026-05-14-001",
    "policy_uid": "hr-corpus-retrieval-v3",
    "policy_uid_alt": "sha256:…",
    "labels": [
      "step_kind:retrieval",
      "verification_outcome:VERIFIED",
      "rules_fired:jurisdiction_eu_only"
    ]
  },
  "actor": {
    "user": { "uid": "sha256:7a2bf01…", "type_id": 1 },
    "process": { "name": "incident_agent" }
  },
  "resources": [
    {
      "uid": "policy_v4",
      "type": "document_chunk",
      "data": {
        "fingerprint": "sha256:1ebcde39…",
        "document_version": "sha256:…",
        "content_source": "indexed_corpus"
      }
    }
  ]
}
```

| Provenex receipt field | OCSF field |
| --- | --- |
| `receipt_id` | `metadata.uid` |
| `schema_version` | `metadata.product.feature.version` |
| `issued_at` | `time` (epoch ms) + `time_dt` (ISO-8601 verbatim) |
| `issuer` (split on `/`) | `metadata.product.name` / `metadata.product.version` |
| `caller_hash` | `actor.user.uid` (prefix `sha256:` or `hmac-sha256:` survives — the algorithm tag is the dispatcher) |
| `trajectory.trajectory_id` | `metadata.correlation_uid` |
| `trajectory.session_id` | `metadata.session_uid` |
| `trajectory.agent_id` | `actor.process.name` |
| `trajectory.step_kind` | `metadata.labels[]` (one label `step_kind:<value>`) |
| `sources[i].fingerprint` | `resources[].data.fingerprint` |
| `sources[i].document_id` | `resources[].uid` |
| `sources[i].document_version` | `resources[].data.document_version` |
| `sources[i].content_source` | `resources[].data.content_source` |
| `sources[i].verification_outcome` | `metadata.labels[]` (`verification_outcome:VERIFIED`) |
| `policy.access_control.policy_id` | `metadata.policy_uid` |
| `policy.access_control.policy_version_hash` | `metadata.policy_uid_alt` |
| `policy.access_control.decisions[i].rules_fired` | `metadata.labels[]` (`rules_fired:<comma-joined>`) |
| (constant) | `class_uid` `6005`, `severity_id` `1`, `status_id` `1`, `event_code` `provenex.verification.allow` |

## Field-by-field — API Activity (6003, allowed admission)

```json
{
  "class_uid": 6003,
  "class_name": "API Activity",
  "category_uid": 6,
  "activity_id": 1,
  "activity_name": "Create",
  "type_uid": 600301,
  "severity_id": 1,
  "severity": "Informational",
  "status_id": 1,
  "status": "Success",
  "time": 1747308601000,
  "time_dt": "2026-05-15T11:30:01.000Z",
  "metadata": {
    "uid": "prx_…",
    "event_code": "provenex.admission.allow",
    "correlation_uid": "trj_…",
    "session_uid": "incident-…",
    "policy_uid": "incident-response-agent-v1",
    "policy_uid_alt": "sha256:…",
    "labels": ["step_kind:tool_call", "rules_fired:web_search_provider_allowlist"]
  },
  "actor": {
    "user": { "uid": "sha256:7a2bf01…", "type_id": 1 },
    "process": { "name": "incident_agent" }
  },
  "api": {
    "operation": "query",
    "service": {
      "name": "web_search",
      "labels": ["target_system:google_custom_search"]
    },
    "request": { "uid": "sha256:7a2bf015…" }
  }
}
```

| Provenex receipt field | OCSF field |
| --- | --- |
| `actions[i].name` | `api.service.name` (tool name, memory key class, or model identifier) |
| `actions[i].operation` | `api.operation` |
| `actions[i].target_system` | `api.service.labels[]` (`target_system:<value>`) |
| `actions[i].parameters_hash` | `api.request.uid` (the audit anchor) |
| `policy.tool_call_control.policy_id` | `metadata.policy_uid` |
| `policy.tool_call_control.policy_version_hash` | `metadata.policy_uid_alt` |
| `policy.tool_call_control.decisions[i].rules_fired` | `metadata.labels[]` (`rules_fired:<comma-joined>`) |

The verbatim parameters / value / prompt are **not** mapped onto the
OCSF event. If the receipt redacted them, they don't exist; if it
recorded them (caller opted out of redaction), they stay on the
receipt — Provenex stays decision-and-proof, never on the data
path. The hash anchor on `api.request.uid` is the auditor's
re-derivation point.

## Field-by-field — Detection Finding (2004, block/deny)

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "category_uid": 2,
  "category_name": "Findings",
  "activity_id": 1,
  "activity_name": "Create",
  "type_uid": 200401,
  "severity_id": 5,
  "severity": "Critical",
  "status_id": 1,
  "status": "Success",
  "time": 1747308602000,
  "time_dt": "2026-05-15T11:30:02.000Z",
  "metadata": {
    "uid": "prx_…",
    "event_code": "provenex.verification.block",
    "correlation_uid": "trj_…",
    "labels": ["step_kind:retrieval", "verification_outcome:TAMPERED"]
  },
  "actor": {
    "user": { "uid": "sha256:7a2bf01…", "type_id": 1 }
  },
  "finding_info": {
    "uid": "prx_…",
    "title": "Verification block: TAMPERED",
    "types": ["TAMPERED"],
    "related_events": []
  },
  "resources": [ { "uid": "policy_v4", "type": "document_chunk", "data": { ... } } ]
}
```

For denied admissions, the same shape applies but `finding_info.types`
is `["ADMISSION_DENY"]`, `severity_id` is `4` (High), and the event
carries an `api` block describing the denied action (so a SOC analyst
can trace what was attempted).

## Trajectory correlation

`trajectory.trajectory_id` becomes `metadata.correlation_uid` on
every emitted event by default. That is the field a SIEM joins on
to reconstruct a multi-step agent flow:

```sql
-- Splunk SPL example
| stats count by metadata.correlation_uid metadata.labels{}
| where 'metadata.labels{}' = "step_kind:tool_call"
```

`trajectory.session_id` becomes `metadata.session_uid` — useful when
one user's "session" spans multiple trajectories (a chat
conversation, an incident-response engagement, a multi-day
investigation).

Pass `include_trajectory_correlator=False` to suppress
`metadata.correlation_uid` when the correlation is implicit (e.g.
single-step receipts in a non-DAG flow).

## Deployment-level metadata

`receipt_to_ocsf(receipt_dict, extra_metadata={...})` merges every
key/value into every emitted event's `metadata` block. The conventional
fields:

| Key | Meaning |
| --- | --- |
| `organization_uid` | Tenant / customer identifier. SIEMs use this to scope rules per customer. |
| `environment` | `"prod"`, `"staging"`, `"dev"`. Drives alert routing. |
| `tenant` | Sub-tenant identifier where applicable. |

```python
events = receipt_to_ocsf(
    receipt.to_dict(),
    extra_metadata={
        "organization_uid": "acme-corp",
        "environment": "prod",
        "tenant": "platform-team",
    },
)
```

`OCSFAdapter` accepts the same parameter for the streaming-sink path.

## Streaming integration — `OCSFAdapter`

```python
from provenex import FileJSONLSink, MultiSink, OCSFAdapter
from provenex.export.kafka import KafkaSink

# Two destinations: real-time OCSF firehose to the SIEM + raw
# receipts to long-term archive.
ocsf_to_siem = OCSFAdapter(
    downstream=KafkaSink(bootstrap_servers="...", topic="ocsf-security-events"),
    extra_metadata={"organization_uid": "acme-corp", "environment": "prod"},
)
raw_archive = FileJSONLSink("/var/log/provenex/raw")

sink = MultiSink([ocsf_to_siem, raw_archive])

result = admission_check(..., sink=sink)
# Receipt landed in two places: the OCSF firehose (one or more OCSF
# events per receipt, formatted for the SIEM) and the raw archive
# (one signed Provenex receipt per line, for the eventual auditor
# who needs to verify the signature).
```

`OCSFAdapter` wraps any `ReceiptSink` (`StdoutJSONLSink`,
`FileJSONLSink`, `KafkaSink`, `SQSSink`, `S3AppendSink`,
`PubSubSink`, your own custom sink). Each receipt converts to one
or more OCSF events; each event is forwarded to the downstream sink.

## What we deliberately do not map

- **Verbatim chunk text / parameters / prompts** that were redacted
  on the receipt — they aren't in the OCSF event either. Privacy-
  preserving by design.
- **Receipt signature value.** The `signature` block is on the
  receipt for offline verification; it's not on the OCSF event. A
  SIEM that needs to verify signatures should ingest both streams
  (`OCSFAdapter` for events, raw receipts for the signature path).
- **`metadata_binding`** (the per-decision trust-class annotation).
  Useful to an auditor reading a receipt; rarely useful to a SIEM.
  Available on the raw receipt if the SIEM-side pipeline wants to
  surface it.

## Vendor compatibility

OCSF v1.3 events flow into:

- **Splunk** — via the Splunk Add-on for OCSF (HEC ingest with
  sourcetype = `ocsf:application_activity` / `ocsf:detection_finding`
  / `ocsf:api_activity`).
- **Datadog** — via the Datadog Logs API; OCSF events are recognised
  by the Cloud SIEM pipeline.
- **Elastic** — via the Elastic Common Schema (ECS) integration with
  the OCSF schema package; OCSF events are stored in the `logs-*`
  data stream and mapped at index time.
- **Microsoft Sentinel** — via the Common Event Format (CEF) /
  Codeless Connectors framework; OCSF support is via the AMA / DCR
  pipeline.
- **Any OCSF-aware tool** — the Open Cybersecurity Schema Framework
  is a cross-vendor spec; consuming the JSON is sufficient.

## Migration path to AI-specific OCSF classes

OCSF AI/LLM classes are still emerging. When they stabilize, the
plan is:

1. Add new OCSF class constants to `provenex/export/ocsf.py`
   (e.g. `OCSF_CLASS_AI_AGENT_ACTION`).
2. Route `model_inference` admissions to the new class (away from
   6003) when an opt-in flag is set on `receipt_to_ocsf` /
   `OCSFAdapter`.
3. Document the field-by-field mapping for the new class here.
4. The default for one minor remains 6003; the opt-in flag flips
   when the spec is stable. The eventual breaking change to default
   to the AI-specific class would be a major release with the
   prior-class path available behind a flag for back-compat.

**No receipt changes at any step.** The mapping is the spec; the
receipts are stable.

## Implementation reference

- [`provenex/export/ocsf.py`](../provenex/export/ocsf.py) — the
  executable implementation of every mapping in this document.
- [`tests/test_ocsf_export.py`](../tests/test_ocsf_export.py) — 21
  cases covering class selection, severity, correlation fields,
  redaction, OCSFAdapter wiring, and serialisability.
- [`examples/ocsf_export_demo.py`](../examples/ocsf_export_demo.py)
  — runnable end-to-end demo: emits mixed-step-kind receipts,
  converts each to OCSF, prints the wire JSON, demonstrates
  OCSFAdapter forwarding.
