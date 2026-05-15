# Anomaly detection over Provenex receipts

**Provenex receipts are the source-of-record AI agent anomaly detectors consume.** This document is the canonical reference: what Provenex emits, what the detector does with it, and where the line between the two is drawn.

If you are evaluating Provenex alongside a UEBA / SIEM / agent-anomaly-detection tool, this is the doc to read.

---

## What this document is

A working integration spec for an anomaly-detection layer sitting downstream of Provenex. Three things you'll find here:

1. **Architecture** — the per-decision admission layer (Provenex) and the sequence/pattern detection layer (your detector), and the receipt stream that connects them.
2. **Schema field reference for detectors** — every field a detection rule typically reads, with a one-line "what to do with this in detection."
3. **Worked detection patterns** — concrete examples, with the receipt fields each one consumes and SQL/pseudocode snippets a SIEM analyst can adapt.

Provenex deliberately does not implement these detections itself. The line between admission and detection is load-bearing — see [§ The line we don't cross](#the-line-we-dont-cross).

---

## The architecture

```
                         AGENT RUNTIME
   ┌─────────────────────────────────────────────────────────┐
   │                                                         │
   │   query → retriever → [Provenex] → LLM → answer         │
   │                          │                              │
   │   tool call → [Provenex] │ ← decision & proof           │
   │                          │                              │
   │                          ▼                              │
   │                    signed receipt                       │
   │                          │                              │
   └──────────────────────────┼──────────────────────────────┘
                              │
                              ▼  ReceiptSink / OCSFAdapter
                  ┌───────────────────────┐
                  │  ANOMALY DETECTOR     │   ← different category,
                  │   - per-caller        │     different vendor,
                  │     baselining        │     different budget
                  │   - sequence /        │     (UEBA, SIEM,
                  │     pattern alerts    │     custom agent
                  │   - cross-trajectory  │     anomaly tool)
                  │     correlation       │
                  └───────────────────────┘
```

**Provenex side.** Per-decision: every retrieval verification, every tool-call admission, every memory read/write, every model-inference call produces a signed receipt with:
- The decision (`allow` / `deny` / verification outcome).
- The rules that fired.
- Stable correlation keys: `caller_hash`, `trajectory_id`, `session_id`, `step_kind`.
- The hash anchors for the inputs (`inputs_hash`, `parameters_hash`, `value_hash`, `prompt_hash`).
- An end-to-end cryptographic signature.

**Detector side.** Sequence / pattern: read the receipt stream, group by stable keys, baseline normal behaviour, alert when sequence shape drifts.

**The receipt stream is the API between the two.** Receipts ship via `ReceiptSink` (`StdoutJSONLSink` / `FileJSONLSink` / `KafkaSink` / `SQSSink` / `S3AppendSink` / `PubSubSink`) or, for OCSF-aware consumers, via `OCSFAdapter` wrapping any of the above. See [`streaming_export.md`](streaming_export.md) and [`ocsf_mapping.md`](ocsf_mapping.md).

---

## Schema field reference for detectors

Every field below is on every receipt where it makes sense. Optional fields are noted.

### Identity + correlation (group-by keys)

| Field | Type | What detectors do with it |
| --- | --- | --- |
| `caller_hash` | `"sha256:<hex>"` or `"hmac-sha256:<hex>"` | Primary GROUP BY for per-caller baselining. Stable across receipts; opaque to the detector. The prefix tags the algorithm — bare SHA-256 vs salted HMAC for per-deployment unlinkability. |
| `trajectory.trajectory_id` | `"trj_<hex>"` | GROUP BY for within-trajectory correlation. Every receipt in one agent flow shares this. JOIN on it to reconstruct multi-step flows. |
| `trajectory.session_id` | opaque caller-chosen string | GROUP BY for multi-trajectory correlation (a chat session, an incident-response engagement, a multi-day investigation). |
| `trajectory.agent_id` | opaque string | Sub-grouping for multi-agent flows. Often combined with `caller_hash`. |
| `trajectory.step_kind` | `retrieval` / `tool_call` / `memory_read` / `memory_write` / `model_inference` / `compilation` / `<custom>` | Filter and bucket detection rules by action class. The single most useful label for shaping detector queries. |
| `receipt_id` | `"prx_<hex>"` | Unique event identifier. Use for dedup and back-references in detector findings. |
| `trajectory.parent_step_ids[]` | list of `receipt_id` | DAG structure within a trajectory. Useful for "what immediately preceded this denial?" queries. |

### Timing

| Field | Type | What detectors do with it |
| --- | --- | --- |
| `issued_at` | ISO-8601 UTC, ms precision | Time bucket for rate / sliding-window detection. The authoritative timestamp; not the detector's ingest time. |
| `trajectory.trajectory_started_at` | ISO-8601 UTC, ms precision | Trajectory start time. Trajectory duration = `issued_at − trajectory_started_at`. |

### Policy decision (what fired)

| Field | Type | What detectors do with it |
| --- | --- | --- |
| `policy.access_control.policy_id` | string | Which retrieval policy was in effect. Useful for "this caller suddenly hit a different policy" anomalies. |
| `policy.access_control.policy_version_hash` | `"sha256:<hex>"` | Canonical policy version. Detect "policy version changed" silently. |
| `policy.access_control.decisions[i].decision` | `allow` / `deny` | Per-chunk decision. Aggregate to per-caller deny rates. |
| `policy.access_control.decisions[i].rules_fired[]` | list of string | The rules whose `when` clauses matched. Even allowed decisions list rules — this is the **near-miss** signal: rule fired but `require` passed. |
| `policy.tool_call_control.*` | mirror of access_control | tool-call admission equivalent. Same fields, parallel semantics. |

### Verification (retrieval-side integrity)

| Field | Type | What detectors do with it |
| --- | --- | --- |
| `sources[i].verification_outcome` | `VERIFIED` / `STALE` / `UNAUTHORIZED` / `UNVERIFIED` / `TAMPERED` | The integrity outcome. `TAMPERED` and `UNVERIFIED` at non-trivial rates are alarms; `STALE` and `UNAUTHORIZED` are operational issues. |
| `sources[i].content_source` | `indexed_corpus` / `live_tool_output` / `memory_store` / `compiled_artifact` | Origin classifier. Tells the detector whether to expect an UNVERIFIED outcome (live tool output) or alarm on it (corpus miss). |
| `sources[i].fingerprint` | `"sha256:<hex>"` | The chunk's identity. GROUP BY fingerprint detects "same poisoned chunk delivered to multiple callers." |
| `sources[i].document_id` | opaque string | Document identity from the index. Useful for "this document is over-retrieved" patterns. |

### Action identity

| Field | Type | What detectors do with it |
| --- | --- | --- |
| `actions[i].name` | string | Tool / memory key class / model identifier. For memory writes the constant `"memory.write"`; for model inferences the model name (`"claude-opus-4-7"`). Primary group-by for per-tool / per-model detection. |
| `actions[i].operation` | string | The operation on the tool (`"create_issue"`, `"query"`). For memory writes the memory key itself — write-rate-per-key falls out naturally. For model inferences the verb (`"complete"` / `"stream"` / `"embed"`). |
| `actions[i].target_system` | string | Logical target (`"acme.atlassian.net"`, `"anthropic"`). Provider-allowlist detection grouping. |
| `actions[i].parameters_hash` | `"sha256:<hex>"` | The audit anchor over the verbatim parameters. Detect "same exact parameters submitted N times" (replay-shape) patterns; cross-check independently if the detector has the verbatim values out-of-band. |

### Aggregate

| Field | Type | What detectors do with it |
| --- | --- | --- |
| `summary.overall_status` | `PASS` / `PARTIAL` / `FAIL` | Per-receipt rollup. Trivial first-pass filter. |
| `summary.total_chunks`, `verified`, etc. | integers | Counts per verification outcome. Trend over time. |
| `summary.total_actions`, `actions_allowed`, `actions_denied` | integers | Counts per admission outcome. |

---

## Common detection patterns (worked)

The five patterns below cover most of what an AI-agent anomaly detector looks for. Each one names the receipt fields it consumes and shows a pseudocode rule.

### Pattern 1: Per-caller tool-call rate anomaly

**The signal.** A specific caller is doing more (or fewer) tool calls than their baseline.

**Receipt fields.** `caller_hash`, `trajectory.step_kind == "tool_call"` (or `"model_inference"` etc.), `issued_at`.

**Rule shape.**

```sql
-- Splunk-style sliding window
| eval window_start = relative_time(now(), "-1h@h")
| stats count as recent_count by caller_hash
        where issued_at > window_start
| join caller_hash type=outer [
    -- baseline: same caller, last 30 days, same hour-of-day bucket
    search index=provenex earliest=-30d@d latest=-1d@d
    | eval bucket = strftime(issued_at, "%H")
    | stats avg(count) as baseline by caller_hash bucket
  ]
| where recent_count > baseline * 5
| eval severity = "high"
```

**Why this works.** `caller_hash` is the deliberate group-by key — stable across schema changes, opaque to the detector, no PII. The 5× threshold is illustrative; tune to your environment.

**Refinements.**
- Add `tool.name` to the group-by for per-tool baselines (`per-(caller, claude-opus-4-7)` rate).
- For multi-tenant deployments using salted `caller_hash`, the detection works the same — `hmac-sha256:<hex>` is just a different prefix.

### Pattern 2: Trajectory shape drift

**The signal.** An agent's mix of step kinds shifts — suddenly 90% tool calls vs. a baseline of 60% retrievals.

**Receipt fields.** `trajectory.trajectory_id`, `trajectory.step_kind`.

**Rule shape.**

```python
# Pseudocode for a tumbling-window detector
def detect_shape_drift(window_receipts, baseline_distribution):
    """Alert if the per-step_kind distribution in the window
    differs from the baseline by more than a KL-divergence threshold."""
    window_dist = Counter(
        r["trajectory"]["step_kind"] for r in window_receipts
        if r.get("trajectory", {}).get("step_kind")
    )
    window_dist = normalize(window_dist)
    div = kl_divergence(window_dist, baseline_distribution)
    if div > THRESHOLD:
        emit_alert(
            "step_kind distribution drift",
            window_dist=window_dist,
            baseline=baseline_distribution,
        )
```

**Why this works.** `trajectory.step_kind` is a finite-alphabet classifier (5 standard values + custom). The distribution over time is a low-dimensional signal an autoencoder or simple statistical test handles well.

**Refinements.**
- Per-`agent_id` baselines if your agent fleet is heterogeneous.
- Per-`caller_hash × step_kind` matrices for finer-grained detection.

### Pattern 3: Policy near-miss

**The signal.** A rule's `when` clause fires often but the `require` clause keeps passing — i.e. the caller keeps brushing against the rule without tripping it. Provenex records both: every rule whose `when` matched lands in `rules_fired`, even on allows. Frequent near-misses are a leading indicator that someone is probing the edges of the policy.

**Receipt fields.** `caller_hash`, `policy.access_control.decisions[i].rules_fired[]`, `policy.access_control.decisions[i].decision`.

**Rule shape.**

```sql
| where decisions{}.decision = "allow"
| mvexpand decisions{}.rules_fired
| stats count by caller_hash decisions{}.rules_fired
| where count > NEAR_MISS_THRESHOLD
| eval severity = "medium"
| eval description = "Caller " + caller_hash + " hit rule "
                   + 'decisions{}.rules_fired' + " " + count
                   + " times without violating it"
```

**Why this works.** The `rules_fired` array is the trace of rule participation, NOT the trace of rule violations. That distinction is what makes the near-miss pattern detectable.

**Refinements.**
- Combine with the time dimension to catch "near-miss rate increased."
- Combine with `tool.parameters_hash` to detect "same near-miss pattern across many calls."

### Pattern 4: Cross-trajectory correlation (memory-write → external tool-call)

**The signal.** A caller writes to memory then immediately does an external tool call within K seconds — a possible data-exfiltration sequence.

**Receipt fields.** `caller_hash`, `trajectory.session_id`, `trajectory.step_kind`, `actions[i].name`, `issued_at`.

**Rule shape.**

```python
def detect_memwrite_then_external_call(session_receipts, K_seconds=10):
    """Within one session, alert on memory_write step closely followed
    by a tool_call to an external target_system."""
    sorted_receipts = sorted(session_receipts, key=lambda r: r["issued_at"])
    for prev, curr in zip(sorted_receipts, sorted_receipts[1:]):
        if (
            prev["trajectory"]["step_kind"] == "memory_write"
            and curr["trajectory"]["step_kind"] == "tool_call"
            and is_external(curr["actions"][0]["target_system"])
            and time_delta(prev, curr) <= K_seconds
        ):
            emit_alert(
                "memory write followed by external tool call",
                session_id=prev["trajectory"]["session_id"],
                caller_hash=prev["caller_hash"],
                memory_key=prev["actions"][0]["operation"],
                external_call=curr["actions"][0],
            )
```

**Why this works.** `session_id` is the multi-trajectory correlator — exactly the boundary across which this pattern needs to look. Without it, the detector would have to reconstruct sessions from `caller_hash` + time-bucketing, which is fragile.

**Refinements.**
- Filter to `memory_write` operations on sensitive keys (`actions[0].operation in {"customer_pii", "incident_data"}`).
- Define `is_external(target_system)` per your tenant — `"acme.atlassian.net"` is internal; `"google_custom_search"` is external.

### Pattern 5: Content-source anomaly

**The signal.** An agent's mix of `content_source` values shifts — suddenly 40% `live_tool_output` vs a baseline of 5%. Implication: the agent is relying more on live retrieval than its grounded corpus, which is a quality/safety signal.

**Receipt fields.** `caller_hash` or `agent_id`, `sources[i].content_source`.

**Rule shape.**

```sql
| where sources{}
| mvexpand sources{}
| stats count by agent_id sources{}.content_source bin(_time, 1h)
| eventstats sum(count) as total_per_hour by agent_id bin(_time, 1h)
| eval ratio = count / total_per_hour
| where 'sources{}.content_source' = "live_tool_output"
| where ratio > 0.30
| eval severity = "medium"
| eval description = "agent " + agent_id + " using live_tool_output for "
                   + round(ratio * 100, 1) + "% of retrievals"
```

**Why this works.** `content_source` was added in schema 1.4.0 precisely to make this distinction auditable. It's a free-form classifier from the agent's side (the caller declares it), but it's covered by the receipt signature — an attacker can't dampen the alarm by retroactively rewriting it.

---

## Export shapes

Receipts ship in two formats:

### Raw JSONL — one signed Provenex receipt per line

Used when the detector reads receipts directly (custom UEBA tools, in-house pipelines, batch analytics).

```bash
# Tail the raw receipt stream — one signed receipt per line
tail -F /var/log/provenex/receipts-*.jsonl | jq -c '
  select(.summary.overall_status == "FAIL")
  | {receipt_id, caller_hash, decision: .policy.tool_call_control.decisions[0].decision, rules: .policy.tool_call_control.decisions[0].rules_fired}
'
```

The signature on every line lets the detector independently verify that the receipt was emitted by Provenex (and not a forged event). See [`streaming_export.md`](streaming_export.md) for `FileJSONLSink` / `KafkaSink` / `SQSSink` / `S3AppendSink` / `PubSubSink` configuration.

### OCSF v1.3 events — one or more per receipt

Used when the detector is an OCSF-aware SIEM (Splunk, Datadog, Elastic, Microsoft Sentinel). `OCSFAdapter` wraps any `ReceiptSink` so receipts are translated to OCSF events before publishing:

```python
from provenex import OCSFAdapter, MultiSink, FileJSONLSink
from provenex.export.kafka import KafkaSink

sink = MultiSink([
    OCSFAdapter(
        downstream=KafkaSink(bootstrap_servers="...", topic="ocsf-security-events"),
        extra_metadata={"organization_uid": "acme-corp", "environment": "prod"},
    ),
    FileJSONLSink("/var/log/provenex/raw"),
])
```

OCSF receivers can apply standard correlation rules out of the box:
- `GROUP BY metadata.correlation_uid` → reconstruct trajectories
- `GROUP BY actor.user.uid` → per-caller baseline
- `GROUP BY metadata.session_uid` → multi-trajectory correlation
- `WHERE class_uid = 2004` → all blocks and denials
- `WHERE severity_id >= 4` → high-severity findings only

See [`ocsf_mapping.md`](ocsf_mapping.md) for the full field-by-field translation.

---

## The line we don't cross

Provenex is the admission layer. The anomaly detector is the SIEM that reads admission events. **We do not build the detector.**

**Why this matters operationally.**

Per-decision admission and cross-decision detection have different engineering requirements. The admission layer must be:
- **Deterministic** — same `(input, policy)` produces the same decision, every time, forever.
- **Per-decision-pure** — no trajectory state, no aggregations, no external lookups during evaluation. This is what makes `inputs_hash` an audit anchor a regulator can reproduce years later.
- **Side-effect-free** — logging, emission, sink shipping all happen *after* the decision, not inside it.
- **Synchronous and fast** — sub-millisecond at the 99th percentile (see [`scaling.md`](scaling.md)).

The detector layer needs the opposite shape:
- **Stateful** — windows, baselines, cohorts.
- **Cross-decision** — sequence patterns, ratio drifts, near-miss frequencies.
- **External-data-aware** — IdP lookups, asset inventory, threat intel feeds.
- **Asynchronous** — millisecond or second latency is fine; minutes is often fine.

**One engine doing both is worse at each.** Bundling sequence detection into a per-decision admission engine breaks the audit guarantees and the latency budget. Bundling per-decision purity into a sequence detector breaks the detector's expressivity and forces it to swallow Provenex's design constraints. Each is better-engineered because it doesn't try to be the other.

**The receipt is the API.** Receipts have stable correlation keys (`caller_hash`, `trajectory_id`, `session_id`, `step_kind`), explicit decision metadata (`rules_fired`, `decision`, `verification_outcome`), and time with millisecond precision. They are deliberately the right shape for a detector to consume — and deliberately not the right shape to mutate during detection. See [`policy.md`](policy.md#what-the-native-dsl-deliberately-doesnt-do-and-why) for the design rationale.

**Strategically, this is the same line as firewall / SIEM.** A firewall enforces per-packet rules deterministically. A SIEM correlates across packets. Nobody asks the firewall to also be the SIEM; the firewall would be worse at firewalling and the operator would have one tool to debug instead of two. Provenex is the firewall (for AI access); the detector is the SIEM. Two categories, two budget lines, two vendors. By design.

---

## Trust model for the detector

The receipt is the cryptographic source-of-truth. The detector's downstream guarantees inherit from how the receipt stream is transported.

### What the receipt guarantees

- **Receipt integrity.** Every receipt is signed (HMAC-SHA256 default; Ed25519 optional). Modify any field, the signature fails. A detector that verifies signatures detects forged events.
- **Decision integrity.** `inputs_hash` covers the verbatim inputs the policy evaluator looked at. Two regulators with the original inputs + the original policy bundle reproduce `inputs_hash` exactly — the receipt's claim about *what was decided* is non-repudiable.
- **Per-action identity.** `parameters_hash` covers the verbatim tool-call parameters; `value_hash` / `prompt_hash` cover memory writes / model inferences. The audit anchor survives redaction (`parameters: null` on the receipt is fine; the hash stays).

### What the receipt does NOT guarantee

- **Sequence ordering** — a malicious transport can drop, duplicate, or reorder receipts in transit. Detectors that rely on sequence reconstruction need a transport with delivery guarantees (Kafka with min.insync.replicas, SQS FIFO queues, the transparency-log integration on the commercial Provenex roadmap) — or they need to reconstruct ordering from `issued_at` + `trajectory.parent_step_ids[]` and accept that a sophisticated attacker can manipulate either.
- **Completeness** — the receipt asserts what *was* decided. It does not assert that *every* decision the agent made resulted in a receipt. An agent that bypasses Provenex (calls a tool without going through `admission_check`) produces no receipt at all; the detector cannot detect what was never recorded. Mitigation: framework-level wrappers (LangChain `ProvenexToolWrapper`, LangGraph nodes, MCP middleware) that make bypass syntactically inconvenient.

### Recommended detector posture

1. **Verify signatures on ingest.** The detector should reject any receipt whose signature doesn't validate against the operator's published public key (Ed25519) or shared HMAC secret. See [`threat_model.md`](threat_model.md) for the full trust model.
2. **Ship via at-least-once transport.** Kafka with replication, SQS FIFO, S3 with versioning. The `RetryQueueSink` in `provenex.export.streaming` handles transient hiccups; persistent durability is your transport's job.
3. **Treat unsigned receipts as alarms.** Development receipts are emitted unsigned. A production detector should never see an unsigned receipt; the appearance of one is itself an alarm condition.
4. **Cross-reference `caller_hash` to IdM out-of-band.** The detector groups by the opaque hash; for human-readable alerts, join to the operator's IdM record using the original caller dict (which the operator's system has).

---

## Compatibility

This document is the canonical positioning for Provenex's source-of-record architecture. It does not affect the wire format or any API surface. Receipts produced under any Provenex version since 0.5.0 (when Postgres landed) are usable as detector input; receipts produced under 0.6.0+ also carry tool-call admission events; receipts produced under 0.6.4+ carry the source-of-record correlation fields (`caller_hash`, `session_id`); receipts produced under 0.6.5+ cover the full agent surface (memory + model inference); receipts produced under 0.6.6+ ship via `ReceiptSink`; receipts produced under 0.6.7+ translate to OCSF v1.3.

When OCSF stabilizes AI-specific event classes, this document is updated; receipts are not. The five verification outcomes (`VERIFIED` / `STALE` / `UNAUTHORIZED` / `UNVERIFIED` / `TAMPERED`) are sacred. The decision values (`allow` / `deny`) and the trajectory step kinds are stable. **Detectors written against today's receipts will keep working.**

---

## See also

- [`streaming_export.md`](streaming_export.md) — `ReceiptSink` Protocol and the reference sinks
- [`ocsf_mapping.md`](ocsf_mapping.md) — OCSF v1.3 field-by-field mapping
- [`receipt_format.md`](receipt_format.md) — the receipt schema
- [`policy.md`](policy.md#what-the-native-dsl-deliberately-doesnt-do-and-why) — the per-decision-purity design rationale
- [`threat_model.md`](threat_model.md) — the cryptographic trust model
- [`../examples/anomaly_correlation_demo.py`](../examples/anomaly_correlation_demo.py) — runnable demo of Pattern 1 + 2 + 5 over a synthetic event stream (stdlib only)
- [`../examples/ocsf_export_demo.py`](../examples/ocsf_export_demo.py) — runnable demo of OCSF translation + SIEM-side group-bys
