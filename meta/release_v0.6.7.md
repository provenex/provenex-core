# Release notes — v0.6.7

**Headline.** OCSF v1.3 mapping. `provenex.export.ocsf` turns signed Provenex receipts into Open Cybersecurity Schema Framework events — the cross-vendor schema Splunk, Datadog, Elastic, and Microsoft Sentinel consume. One transformation function (`receipt_to_ocsf`) and one streaming adapter (`OCSFAdapter`) on the existing `ReceiptSink` substrate. No schema bump — wire format stays at 2.3.0.

The mapping is the public spec — [`docs/ocsf_mapping.md`](docs/ocsf_mapping.md) is the artifact a SIEM vendor or enterprise security architect reads to wire Provenex into their pipeline.

## What's new since 0.6.6

### `provenex.export.ocsf` (new module, stdlib core)

- **`receipt_to_ocsf(receipt_dict, *, include_trajectory_correlator=True, extra_metadata=None) → List[Dict]`** — pure transformation function. One receipt maps to one OCSF event per source (allowed sources → Application Activity 6005; blocked sources → Detection Finding 2004) plus one OCSF event per action (allowed → API Activity 6003; denied → Detection Finding 2004). Deterministic, side-effect-free, JSON-shape-shifting only.

- **`OCSFAdapter(downstream, *, extra_metadata=None)`** — streaming-sink wrapper. Implements `ReceiptSink` so it composes with every existing reference sink (`StdoutJSONLSink`, `FileJSONLSink`, `KafkaSink`, `SQSSink`, `S3AppendSink`, `PubSubSink`) or any custom sink. Each incoming receipt is converted to OCSF events; each event is forwarded to the downstream sink via a tiny duck-typed carrier.

- **Lower-level helpers** (public, useful for custom severity logic or field merges): `receipt_to_application_activity`, `receipt_to_detection_finding_for_blocked_source`, `receipt_to_api_activity`, `receipt_to_detection_finding_for_denied_action`.

- **OCSF class constants** exported for switch-table style dispatch: `OCSF_CLASS_APPLICATION_ACTIVITY` (6005), `OCSF_CLASS_API_ACTIVITY` (6003), `OCSF_CLASS_DETECTION_FINDING` (2004).

### Class mapping

| Provenex condition | OCSF class | UID | Severity |
| --- | --- | --- | --- |
| Allowed retrieval (Phase 1) / `memory_read` | Application Activity | 6005 | Informational (1) |
| Allowed `tool_call` / `memory_write` / `model_inference` | API Activity | 6003 | Informational (1) |
| Verification block (TAMPERED / UNAUTHORIZED+block / UNVERIFIED+block / STALE+block) | Detection Finding | 2004 | **Critical (5)** |
| Policy deny (access_control or tool_call_control) | Detection Finding | 2004 | **High (4)** |

### Correlation fields land where SIEMs expect them

| Provenex field | OCSF field |
| --- | --- |
| `receipt_id` | `metadata.uid` |
| `caller_hash` | `actor.user.uid` (prefix `sha256:` or `hmac-sha256:` survives — the algorithm tag is the dispatcher) |
| `trajectory.trajectory_id` | `metadata.correlation_uid` |
| `trajectory.session_id` | `metadata.session_uid` |
| `trajectory.agent_id` | `actor.process.name` |
| `trajectory.step_kind` | `metadata.labels[]` (`step_kind:<value>`) |
| `sources[i].fingerprint` | `resources[].data.fingerprint` |
| `actions[i].name` | `api.service.name` (tool, memory key class, or model identifier) |
| `actions[i].operation` | `api.operation` |
| `actions[i].target_system` | `api.service.labels[]` (`target_system:<value>`) |
| `actions[i].parameters_hash` | `api.request.uid` (audit anchor) |
| `policy.*.policy_id` | `metadata.policy_uid` |
| `policy.*.policy_version_hash` | `metadata.policy_uid_alt` |
| `policy.*.decisions[i].rules_fired` | `metadata.labels[]` (`rules_fired:<comma-joined>`) |

`include_trajectory_correlator=False` suppresses the `correlation_uid` for single-step receipts where the correlation is implicit.

### Why not AI-specific OCSF classes (yet)

OCSF AI/LLM classes are still emerging (6008 "AI/ML Operations" was draft as of late 2025; 7XXX-series for AI agent events is being discussed). Per the source-of-record discipline: **map to existing closest classes now and migrate later**. Receipts don't change. When the AI-specific classes stabilize, only `provenex/export/ocsf.py` + `docs/ocsf_mapping.md` need updating, behind an opt-in flag with the prior path preserved for back-compat. Documented migration path in [`docs/ocsf_mapping.md`](docs/ocsf_mapping.md#migration-path-to-ai-specific-ocsf-classes).

### Privacy-preserving by default

Verbatim parameters / values / prompts **never** land on the OCSF event. If the receipt redacted them (`redact_value=True` / `redact_prompt=True` / `redact_parameters=True`), they don't exist; if the receipt recorded them, they stay on the receipt but the OCSF mapping does not forward them. The hash anchor on `api.request.uid` is the auditor's re-derivation point — same discipline as the receipt itself. Provenex stays decision-and-proof, never on the data path.

### Comprehensive doc + example sweep

- **New: [`docs/ocsf_mapping.md`](docs/ocsf_mapping.md)** — the public spec. OCSF version targeted, class mapping summary, severity assignment, per-class field-by-field tables, sample events, deployment-level metadata convention, vendor compatibility matrix, migration path to AI-specific classes.
- **`README.md`** — new "OCSF export — receipts as cross-vendor security events" section; OSS feature list updated.
- **[`docs/quickstart.md`](docs/quickstart.md)** — new "OCSF export — feeding receipts into your SIEM" subsection with the two surfaces (pure function + streaming adapter).
- **New: [`examples/ocsf_export_demo.py`](examples/ocsf_export_demo.py)** — runnable end-to-end. Five receipts across mixed step kinds; converts each via `receipt_to_ocsf`; prints sample events per class; demonstrates SIEM-side `GROUP BY metadata.correlation_uid` / `actor.user.uid` / `step_kind` / `severity`; shows `OCSFAdapter` streaming.

## Compatibility

- **No schema bump.** Wire format stays at `2.3.0`. The OCSF module reads receipt dicts; the receipt itself is unchanged.
- **Backward compatible across the board.** Nothing in the 0.6.6 surface changed. The OCSF mapping is purely additive — opt in via `receipt_to_ocsf(...)` or `OCSFAdapter(downstream=...)`.
- **All 7 example demos green** against 0.6.7.

## Example

```python
from provenex import (
    HmacSha256Signer, RequestContext, ToolCallContext,
    admission_check, MultiSink, FileJSONLSink, OCSFAdapter, receipt_to_ocsf,
)
from provenex.export.kafka import KafkaSink

# Stream OCSF events to the SIEM while archiving raw receipts in parallel.
sink = MultiSink([
    OCSFAdapter(
        downstream=KafkaSink(bootstrap_servers="kafka:9092", topic="ocsf-events"),
        extra_metadata={"organization_uid": "acme-corp", "environment": "prod"},
    ),
    FileJSONLSink("/var/log/provenex/raw"),  # raw archive for offline verification
])

result = admission_check(
    tool=ToolCallContext(name="jira", operation="create_issue", parameters={...}),
    request=RequestContext(...),
    signer=HmacSha256Signer(),
    sink=sink,
)

# Or ad-hoc transform for batch pipelines:
events = receipt_to_ocsf(
    result.receipt.to_dict(),
    extra_metadata={"organization_uid": "acme-corp"},
)
# events → [{"class_uid": 6003, "class_name": "API Activity", ...}]
```

## Install

```bash
pip install provenex-core==0.6.7
pip install "provenex-core[policy]==0.6.7"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[postgres]==0.6.7"      # Postgres backend (UTF8-hardened in 0.6.5)
pip install "provenex-core[langgraph]==0.6.7"     # LangGraph nodes
pip install "provenex-core[crewai]==0.6.7"        # CrewAI session + admission
pip install "provenex-core[langchain]==0.6.7"     # LangChain retriever + admission wrapper
pip install "provenex-core[ed25519]==0.6.7"       # asymmetric receipt signing
pip install "provenex-core[export-kafka]==0.6.7"  # KafkaSink (kafka-python)
pip install "provenex-core[export-aws]==0.6.7"    # SQSSink / S3AppendSink (boto3)
pip install "provenex-core[export-gcp]==0.6.7"    # PubSubSink (google-cloud-pubsub)
```

The OCSF mapping is in the stdlib core — no extra needed.
