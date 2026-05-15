# provenex-core

[![test](https://github.com/provenex/provenex-core/actions/workflows/test.yml/badge.svg)](https://github.com/provenex/provenex-core/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/provenex-core.svg?cacheSeconds=300&v=0.6.9)](https://pypi.org/project/provenex-core/)
[![Python](https://img.shields.io/pypi/pyversions/provenex-core.svg?cacheSeconds=300&v=0.6.9)](https://pypi.org/project/provenex-core/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/provenex/provenex-core/blob/main/LICENSE)

**Policy enforcement for AI data access, with cryptographic proof.**

Platform engineering champions Provenex (a runtime guardrail they don't have to build). Security signs off (cryptographic enforcement, not promises). Compliance consumes the output (a queryable, exportable, regulator-ready record). 

Provenex is the policy enforcement layer for AI data access. You declare your security policy once — in our native YAML config (or OPA/Rego, commercial) — and Provenex enforces it on every retrieval **and on every agentic tool call**, then emits a cryptographically signed receipt that proves which chunks reached the LLM, which tool calls were admitted, and under what policy.

> **Scope of this repo.** `provenex-core` covers both enforcement fronts on one policy-and-proof spine: **Phase 1 — retrieval enforcement** (what the AI *reads*) and **Phase 2 — agentic tool-call admission** (what the AI is allowed to *do*, including MCP-shaped tool calls and the "can this agent access Jira / Salesforce / this connector" question). Provenex is always **decision and proof, not execution** — an admission controller for AI data access, not a proxy that brokers calls or holds tokens.

This repository contains the open source core: fingerprinting, a Postgres-backed production index (SQLite for development), the native YAML policy DSL, receipt generation, the tool-call admission primitive, and integrations for LangChain / LangGraph / LlamaIndex / CrewAI / MCP. The algorithm is open so it can be audited. Hosted infrastructure, the Rego adapter, the OPA service adapter, Bloom-filter acceleration, compliance-grade exports, and cross-enterprise policy interoperability are available separately at [provenex.ai](https://provenex.ai).

## What you declare. What you get back.

A unified policy file:

```yaml
version: 1
policy_id: hr-corpus-retrieval-v3

# Five-outcome verification gate
verification:
  block_unauthorized: true
  block_tampered: true
  block_stale: false

# Data-access rules
access_control:
  rules:
    - name: jurisdiction_eu_only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency:
          in: [EU, EEA]
      on_violation: deny

    - name: pii_classification_gate
      when:
        chunk.metadata.contains_pii: true
      require:
        request.caller.role:
          in: [hr_admin, payroll]
      on_violation: deny

    - name: freshness_for_policy_corpus
      when:
        chunk.metadata.corpus: policy_documents
      require:
        chunk.ingested_at:
          not_older_than: 90d
      on_violation: deny

  defaults:
    unknown_metadata: deny

# Tool-call admission rules (Phase 2, schema 2.2.0)
tool_call_control:
  rules:
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny

    - name: no_secrets_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*(api[_-]?key|password|secret)*"
      on_violation: deny

    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue, update_issue, delete_issue] }
      require:
        request.caller.role:
          in: [engineer, manager, admin]
      on_violation: deny

  defaults:
    unknown_metadata: deny
```

A signed receipt per retrieval **or per tool-call** — verifiable offline by anyone with the public key. Retrieval receipts carry `sources[]` and `policy.access_control`; tool-call receipts carry `actions[]` and `policy.tool_call_control`; mixed agentic flows link both into one trajectory.

```json
{
  "receipt_id": "prx_f2de431dc125ccfc6b57e6ca327fa504",
  "schema_version": "2.3.0",
  "issuer": "provenex-core/0.6.9",
  "caller_hash": "sha256:7a2bf01571c43f...",
  "output": { "hash": "sha256:...", "hash_algorithm": "sha256" },
  "sources": [
    { "chunk_index": 0, "fingerprint": "sha256:1ebcde39...",
      "verification_outcome": "VERIFIED", "...": "..." }
  ],
  "actions": [
    { "action_index": 0, "name": "web_search", "operation": "query",
      "parameters_hash": "sha256:7a2bf015...", "target_system": "google_custom_search",
      "parameters": { "q": "..." } }
  ],
  "policy": {
    "verification": { "block_unauthorized": true, "block_tampered": true, "...": "..." },
    "access_control": {
      "evaluator": "native_yaml",
      "policy_id": "hr-corpus-retrieval-v3",
      "policy_version_hash": "sha256:e10b1df5...",
      "policy_in_transparency_log": false,
      "decisions": [
        {
          "chunk_fingerprint": "sha256:1ebcde39...",
          "decision": "allow",
          "rules_fired": ["jurisdiction_eu_only", "freshness_for_policy_corpus"],
          "inputs_hash": "sha256:a3f9c2d1...",
          "inputs": { "chunk_metadata": { "...": "..." }, "request_context": { "...": "..." } }
        }
      ]
    },
    "tool_call_control": {
      "evaluator": "native_yaml",
      "policy_id": "hr-corpus-retrieval-v3",
      "policy_version_hash": "sha256:d9fdce46...",
      "policy_in_transparency_log": false,
      "decisions": [
        { "action_index": 0, "decision": "allow",
          "rules_fired": ["web_search_provider_allowlist", "no_secrets_in_query"],
          "inputs_hash": "sha256:b8e441f7...", "inputs": null }
      ]
    }
  },
  "summary": { "total_chunks": 3, "verified": 2, "unverified": 1,
               "total_actions": 1, "actions_allowed": 1, "actions_denied": 0,
               "overall_status": "PARTIAL" },
  "trajectory": { "trajectory_id": "trj_a3f1c0d2...", "step_index": 1,
                  "parent_step_ids": ["prx_c5d8e1f2..."], "step_kind": "tool_call",
                  "agent_id": "incident_agent",
                  "session_id": "incident-2026-05-14-customer-success-001" },
  "signature": { "algorithm": "hmac-sha256", "value": "fc5d40895ca2..." }
}
```

A chunk reaches the LLM only if it clears **both** gates: the verification policy AND the access-control policy. The receipt records both verdicts per chunk so an auditor can reason about them independently — and the signature covers everything.

**Source-of-record fields for downstream anomaly detectors / SIEMs (schema 2.3.0).** `caller_hash` is the SHA-256 over the canonical JSON of `request_context.caller` — a stable group-by key so a detector can baseline a single user's activity across receipts without crawling per-decision input blobs. `trajectory.session_id` is a caller-chosen opaque string that correlates multiple trajectories under one logical session (a chat conversation, an incident-response engagement, a multi-day investigation). Both fields are decision-and-proof artifacts: they don't influence policy decisions (so `inputs_hash` stays deterministic), they just make receipts joinable downstream. Provenex emits the source-of-record; your detector / SIEM is the SIEM that reads it.

## Where Provenex fits in your stack

```
Standard RAG:
  documents ─▶ chunker ─▶ embedder ─▶ vector DB
                                            │
  user query ─▶ embedder ─▶ vector DB.search() ──▶ retriever ─▶ LLM ─▶ answer


Same pipeline with Provenex:
  documents ─┬─▶ chunker ─▶ embedder ─▶ vector DB
             │
             └─▶ provenex.add()   (parallel signed write)

  user query ─▶ embedder ─▶ vector DB.search() ─▶ retriever ─┐
                                                              ▼
                                ┌───────────────────────────────────────┐
                                │  policy.verification (5-outcome gate) │
                                │  policy.access_control (rule engine)  │
                                │      BOTH must allow                  │
                                └────────────┬──────────────────────────┘
                                             ▼
                                    surviving chunks ─▶ LLM ─▶ answer
                                             │
                                             ▼
                              signed policy-decision receipt ─▶ audit / compliance
```

### The pieces

| Piece | What it does |
| --- | --- |
| **Provenex index** | A separate database that stores **cryptographic fingerprints** of every chunk you ingested, plus metadata: document ID, version, ingestion timestamp, authorization state, residency / classification / PII tags supplied by upstream tools. Not the embeddings. Not the chunk text. SHA-256 hashes and metadata only. Ships with two backends: **Postgres** for multi-node production deployments (point at your own RDS / Aurora / Cloud SQL / on-prem cluster), and **SQLite** for single-node development. Same `ProvenanceIndex` interface, identical canonical signing payload — receipts produced against one backend verify bit-identically against the other. |
| **Ingester** | At document-write time, alongside the code that writes embeddings to your vector DB, this writes fingerprints to the Provenex index. Two writes, both committed before "ingest" is done. |
| **Policy evaluator** | At query time, after your retriever pulls chunks from the vector DB, Provenex re-fingerprints each chunk and runs it through both gates: the verification policy (origin, freshness, tampering) and the access-control policy (jurisdiction, classification, PII tags, freshness windows, caller role). |
| **Receipt** | A signed JSON record of the whole transaction: chunks, verification outcomes, the unified policy, per-chunk decisions, the rules that fired, a hash of the LLM output, and a signature over the whole thing. |

### Where does your code change?

**Not in your vector DB.** Provenex doesn't talk to Pinecone, Weaviate, Milvus, or any vector store directly. There's no plugin to install, no schema migration, no managed-vendor permission to wire up. Your vector DB stays exactly as it is.

The integration lives in your **application code**, the same RAG glue layer that already calls your vector DB. Two spots:

1. **In your ingest pipeline.** Wherever your code currently writes chunks into the vector DB, add a parallel call to `provenex.add(...)` for each chunk.
2. **In your retrieval path.** Wherever you get chunks back from the vector DB and hand them to the LLM, run them through `provenex.verify_chunks(..., policy=Policy.from_yaml("hr_policy.yaml"), request_context=...)` first.

## What policy can express

In scope, in the open-source core:

- **Origin / provenance** — was this chunk ingested through Provenex (`VERIFIED` vs `UNVERIFIED`), is the document version current (`STALE`), is it authorized (`UNAUTHORIZED`), did the stored signature survive (`TAMPERED`).
- **Freshness / recency** — `chunk.ingested_at` against a duration window.
- **Access control** — fields under `request.caller.*` against rule expectations.
- **Jurisdiction / data residency** — `chunk.metadata.residency` against `request.jurisdiction`.
- **Sensitivity / classification** — `chunk.metadata.classification` against caller role or purpose.
- **PII presence and handling** — `chunk.metadata.contains_pii` (or any tag your upstream PII tool sets) against caller role.
- **Authorization scope** — `request.purpose` and arbitrary policy-defined combinations of the above.

Out of scope, deliberately:

- **Content quality assessment.**
- **Factual accuracy or hallucination detection.**
- **Bias detection.**
- **Output safety or content moderation.**
- **Cost-based routing.**
- **Business logic enforcement.**
- **PII detection.** Provenex enforces PII tags set by upstream tools; it does not detect PII itself.
- **Quality evaluation.** Provenex enforces quality decisions made by upstream data governance; it does not evaluate quality itself.

The refusal list is as important as the feature list. A policy enforcement layer that quietly drifts into hallucination detection becomes unpredictable.

## Policy languages: bring your own, or use ours

Provenex is **evaluator-agnostic**. The runtime accepts pluggable evaluator backends:

| Backend | Status | Use when |
| --- | --- | --- |
| **Native YAML DSL** | Open-source core (v0.4) | You aren't already on OPA. Want a small, opinionated DSL that fits in a config file. |
| **Rego adapter** | Commercial | You author authorization policies in Rego elsewhere and want one language across the stack. |
| **OPA service adapter** | Commercial | You run OPA as a service and want Provenex to delegate decisions to it. |

Compared to OPA alone, Provenex adds the **cryptographic enforcement record**, the **integration with retrieval**, and (in a future release) **transparency-log-backed proof** of which policy was in effect when. OPA tells you yes / no. Provenex tells you yes / no plus a signed receipt verifiable offline.

See [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md) for the full DSL reference, supported operators, and worked examples.

## Easy integration

### Production (Postgres, multi-node)

```python
from provenex import (
    verify_chunks, Policy, RequestContext,
    HmacSha256Signer, PostgresProvenanceIndex,
)

index = PostgresProvenanceIndex(
    dsn="postgresql://provenex:secret@db.internal:5432/provenex",
)
policy = Policy.from_yaml("hr_policy.yaml")
request = RequestContext(
    caller={"role": "hr_admin"}, jurisdiction="EU",
    purpose="customer_support", timestamp="2026-05-13T00:00:00Z",
)
result = verify_chunks(
    chunks=retrieved_chunks, index=index,
    signer=HmacSha256Signer(),
    policy=policy, request_context=request,
    chunk_metadata=[doc.metadata for doc in retrieved_documents],
)
feed_to_llm(result.kept)            # only chunks that cleared BOTH gates
save_receipt(result.receipt)        # signed, verifiable offline
```

Many verify pods plus one ingester pod is the recommended deployment shape — bulk ingest is a batch job; verify is per-request and scales horizontally via Postgres read replicas. Multi-writer ingest into the same index is supported and serialized at the document-row level. Bring your own Postgres (RDS, Aurora, Cloud SQL, Crunchy, Supabase, or self-managed) — Provenex doesn't host it.

### Development (SQLite, single-node)

```python
from provenex import SQLiteProvenanceIndex
index = SQLiteProvenanceIndex("provenance.db")
# ... rest is identical to the Postgres example
```

Stdlib-only, no service to stand up. Same interface, same canonical signing payload, same receipt format — a receipt produced against SQLite verifies identically against Postgres and vice versa.

Your existing vector store is untouched. Provenex runs alongside as a parallel signed index plus a policy gate. Whether you use **Pinecone, Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector, MongoDB Atlas Vector Search, Elasticsearch with vectors, Vespa, or a Postgres table you wrote yourself**, Provenex doesn't know and doesn't care.

### Tool-call admission (Phase 2, schema 2.2.0)

```python
from provenex import (
    HmacSha256Signer, Policy, RequestContext,
    ToolCallContext, admission_check,
)

policy = Policy.from_yaml("agent_policy.yaml")   # both halves live in one file
request = RequestContext(
    caller={"id": "u_42", "role": "engineer"}, jurisdiction="US",
    purpose="incident_response", timestamp="2026-05-14T11:30:00Z",
)
result = admission_check(
    tool=ToolCallContext(
        name="jira", operation="create_issue",
        parameters={"project": "INC", "summary": "..."},
        target_system="acme.atlassian.net",
    ),
    request=request, policy=policy, signer=HmacSha256Signer(),
)
if result.allowed:
    jira_client.create_issue(...)        # YOUR code, YOUR credentials
save_receipt(result.receipt)             # signed, verifiable offline — denies too
```

**Decision and proof, not execution.** Provenex returns a decision and emits a signed receipt; the caller makes the actual call against the target system using its own credentials. Provenex never holds OAuth tokens, never proxies traffic, and never sits on the response-data path. Use [`ProvenexToolWrapper`](https://github.com/provenex/provenex-core/blob/main/provenex/tool_call/integrations/langchain.py) to wrap any LangChain tool; use [`provenex_mcp_admission`](https://github.com/provenex/provenex-core/blob/main/provenex/tool_call/integrations/mcp.py) to decorate any MCP `tools/call` handler.

### Memory reads, memory writes, and model-inference (0.6.5+)

Every class of action an agent takes lands on a receipt under the right `trajectory.step_kind` classifier — not just retrieval (`step_kind="retrieval"`) and tool calls (`step_kind="tool_call"`). Three convenience entrypoints close the loop so a downstream anomaly detector / SIEM gets a complete event stream:

```python
from provenex import (
    HmacSha256Signer, RequestContext, SQLiteProvenanceIndex,
    admit_memory_write, admit_model_inference, verify_memory,
)

index = SQLiteProvenanceIndex("memory.db")
signer = HmacSha256Signer()
request = RequestContext(caller={"id": "u_42", "role": "engineer"},
                         jurisdiction="US", purpose="incident_response",
                         timestamp="2026-05-14T11:30:00Z")

# Memory read — emits a receipt with step_kind="memory_read" and
# content_source="memory_store" on every source. Same five outcomes
# (VERIFIED / STALE / UNAUTHORIZED / UNVERIFIED / TAMPERED) apply.
r1 = verify_memory(["last user message: ..."], index=index, signer=signer,
                   request_context=request)

# Memory write — emits an admission receipt with name="memory.write",
# operation=<memory_key>. By default the verbatim value is redacted
# (memory values often contain PII); value_hash is always recorded.
r2 = admit_memory_write(memory_key="user_profile", value={"prefers": "dark_mode"},
                        request=request, store_id="crewai_memory", signer=signer)

# Model inference — emits an admission receipt with name=<model_name>,
# target_system=<provider>, parameters={prompt_hash, **extras}. Verbatim
# prompt redacted by default. Enables detection on "this user is calling
# claude-opus 100x baseline" or "prompts contain pattern X".
r3 = admit_model_inference(model_name="claude-opus-4-7",
                           prompt="Summarize INC-2026-05-001",
                           request=request, target_provider="anthropic",
                           extra_parameters={"max_tokens": 4000}, signer=signer)
```

All three reuse the existing receipt schema unchanged (still 2.3.0). They produce admission-shaped receipts (`actions[]` + `policy.tool_call_control`) for `memory_write` / `model_inference`, and retrieval-shaped receipts (`sources[]` + `policy.access_control`) for `memory_read`. The unified YAML policy gates all of them the same way — a tool-call rule like `when: { tool.name: "memory.write", tool.operation: "user_profile" }` enforces per-key gates; a rule like `when: { tool.name: "claude-opus-4-7" }` gates model usage by provider/allowlist.

### Streaming receipts to a SIEM / firehose (0.6.6+)

Every receipt-emitting entrypoint accepts an optional `sink=` parameter. Provenex publishes to the sink after the receipt is finalised — your hot path stays the same; the firehose runs alongside.

```python
from provenex import (
    HmacSha256Signer, RequestContext, ToolCallContext,
    admission_check, MultiSink, FileJSONLSink,
)
from provenex.export.kafka import KafkaSink   # extra: [export-kafka]
from provenex.export.aws import S3AppendSink  # extra: [export-aws]

# Real-time firehose for the detector + long-term archive for compliance.
sink = MultiSink([
    KafkaSink(bootstrap_servers="kafka.internal:9092", topic="provenex-receipts"),
    S3AppendSink(bucket="audit-archive", prefix="provenex"),
    FileJSONLSink("/var/log/provenex"),
])

result = admission_check(..., sink=sink)   # the only line that changes
```

**Reference sinks shipped:** `StdoutJSONLSink`, `FileJSONLSink` (date-rotated), `MultiSink` (fan-out), `RetryQueueSink` (bounded in-process retry queue) in the stdlib core; `KafkaSink`, `SQSSink`, `S3AppendSink` (date-hour-partitioned), `PubSubSink` behind optional extras. Define-your-own via the `ReceiptSink` Protocol.

**Error semantics — load-bearing.** Sink failures are swallowed and logged via `warnings.warn`. **Provenex never breaks the agent's hot path because export is degraded.** A misconfigured Kafka cluster writes a warning to stderr; the receipt is still returned through the function value; the agent keeps running. See [`docs/streaming_export.md`](https://github.com/provenex/provenex-core/blob/main/docs/streaming_export.md) for the full reference including retry queue semantics and custom-sink implementation.

### OCSF export — receipts as cross-vendor security events (0.6.7+)

Provenex maps signed receipts to **OCSF v1.3** events — the emerging cross-vendor schema (Splunk, Datadog, Elastic, Microsoft Sentinel) for security events. One function transforms; one adapter streams.

```python
from provenex import OCSFAdapter, MultiSink, FileJSONLSink, receipt_to_ocsf
from provenex.export.kafka import KafkaSink

# Stream-and-fan-out: OCSF events to the SIEM, raw receipts to archive.
sink = MultiSink([
    OCSFAdapter(
        downstream=KafkaSink(bootstrap_servers="...", topic="ocsf-security-events"),
        extra_metadata={"organization_uid": "acme-corp", "environment": "prod"},
    ),
    FileJSONLSink("/var/log/provenex/raw"),
])
result = admission_check(..., sink=sink)

# Or convert ad-hoc:
events = receipt_to_ocsf(result.receipt.to_dict())
# → [{class_uid: 6003, ...}]  (API Activity for allowed admissions)
```

| Provenex event | OCSF class | UID | Severity |
|---|---|---|---|
| Allowed retrieval / memory_read | Application Activity | **6005** | Informational |
| Allowed tool_call / memory_write / model_inference | API Activity | **6003** | Informational |
| Verification block (TAMPERED, UNAUTHORIZED, etc.) | Detection Finding | **2004** | **Critical** |
| Policy deny (access_control or tool_call_control) | Detection Finding | **2004** | **High** |

Correlation fields land where SIEMs expect them: `caller_hash` → `actor.user.uid`, `trajectory_id` → `metadata.correlation_uid`, `session_id` → `metadata.session_uid`, `step_kind` → `metadata.labels[]`. The full field-by-field spec is in [`docs/ocsf_mapping.md`](https://github.com/provenex/provenex-core/blob/main/docs/ocsf_mapping.md) — the public artifact for SIEM vendors and enterprise security architects.

### Provenex is the firewall. Your detector is the SIEM.

Provenex enforces per-decision admission and emits signed receipts. Your anomaly detector / UEBA / SIEM reads the receipt stream and does sequence / pattern detection. Two categories, two budgets, two vendors — by design.

- **Provenex side:** deterministic, per-decision-pure, side-effect-free, sub-millisecond. `inputs_hash` is reproducible by a regulator years later from the recorded inputs + the original policy bundle.
- **Detector side:** stateful, cross-decision, external-data-aware. Reads receipts via `ReceiptSink` (or OCSF events via `OCSFAdapter`), groups by `caller_hash` / `trajectory_id` / `session_id` / `step_kind`, baselines normal behaviour, alerts on drift.

The native YAML DSL **deliberately refuses** trajectory-level rules, cross-decision aggregations, and external-data lookups during evaluation. Putting those inside a per-decision admission engine breaks the audit-anchor guarantees and the latency budget. They belong downstream — in your detector reading the receipt stream. Customers who need trajectory rules in-engine use the commercial Rego adapter; the trade-off is explicit. See [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md#what-the-native-dsl-deliberately-doesnt-do-and-why) for the design rationale.

**The canonical positioning doc, including worked detection patterns:** [`docs/anomaly_detection.md`](https://github.com/provenex/provenex-core/blob/main/docs/anomaly_detection.md) — what fields a detector reads, five worked patterns (per-caller rate, trajectory shape drift, policy near-miss, cross-trajectory correlation, content-source anomaly), trust model, and the operational reasoning for the firewall / SIEM split.

### Per-deployment unlinkability for `caller_hash` (0.6.5+)

By default, `caller_hash` is a plain SHA-256 over the canonical caller dict (`sha256:<hex>` prefix) — anyone with the verbatim caller dict can reproduce the hash. For multi-tenant deployments that want two of their customers' detectors to NOT be able to cross-correlate users via shared `caller_hash` buckets, pass `caller_hash_salt=b"..."` to `verify_chunks` / `admission_check` / `verify_memory` / `admit_memory_write` / `admit_model_inference`. The hash becomes HMAC-SHA256 keyed by the salt (`hmac-sha256:<hex>` prefix); two deployments with different salts produce different `caller_hash` for the same caller. Same algorithm family (SHA-256), same wire format — the prefix tells consumers which mode produced the hash. Salting is **opt-in**; no caller-side migration needed for the bare-SHA-256 default.

## Agentic and multi-step flows

Modern RAG isn't always one retrieve-then-answer cycle. Agents reason, retrieve, reflect, retrieve again. Multiple agents collaborate. Tools fetch live data. Provenex is built for these flows alongside the simple one-shot case:

| Framework | Retrieval | Tool calls (Phase 2) |
| --- | --- | --- |
| **LangChain** | `ProvenexRetriever` wraps any retriever. Accepts an optional `trajectory=`. | `ProvenexToolWrapper` wraps any LangChain tool; same receipt shape as MCP. |
| **LangGraph** | `provenex_retrieval_node(...)` factory + state helpers. Drops into any state-graph DAG; the trajectory threads through the shared state. | Call `admission_check(...)` from a graph node; pass `trajectory=` to thread admissions into the same DAG. |
| **CrewAI** | `ProvenexCrewSession.wrap_tool(tool)` wraps any retrieval / tool / memory callable; `session.verify_chunks(...)` runs Phase 1 verification on tool output. | `session.wrap_tool_admission(tool, name=..., request_factory=...)` runs Phase 2 admission **before** the tool fires (denials raise `ToolCallDenied`). `session.admission_check(tool_ctx, request)` is the lower-level variant; both thread the session's trajectory automatically. |
| **LlamaIndex** | `ProvenexRetriever` middleware (same pattern as LangChain). | Use the framework-agnostic `admission_check(...)` directly. |
| **MCP** | n/a (retrieval is upstream of MCP) | `provenex_mcp_admission(...)` decorator wraps a `tools/call` handler. Standard JSON-RPC error code on deny. |
| **Anything else** | `provenex.verify_chunks(chunks, index=..., policy=..., request_context=..., trajectory=...)` | `provenex.admission_check(tool=..., request=..., policy=..., signer=..., trajectory=...)` |

Every retrieval, tool-call admission, **memory read, memory write, and model-inference** step emits its own signed receipt with a `trajectory` block linking it to its parents in a DAG. After the agent finishes, `provenex audit --trajectory <dir>` validates the entire trajectory end-to-end: signatures, inclusion proofs, no dangling parents, no cycles, shared trajectory id, at least one root step. **Mixed step kinds — `retrieval` / `tool_call` / `memory_read` / `memory_write` / `model_inference` — are first-class** under one signed audit trail. One CLI invocation covers the whole agent run.

Receipts also carry two optional per-chunk fields useful in agent flows:

- **`claims[]`** — self-attribution claims from the agent ("I used this chunk", "this supports the answer", "this is relevant"). Cryptographically bound to the receipt so the agent cannot deny what it asserted. Provenex does not verify the claim itself — that is the agent operator's compliance burden, made auditable by the signature.
- **`content_source`** — origin classifier (`indexed_corpus`, `live_tool_output`, `memory_store`, `compiled_artifact`). Lets an auditor reading an `UNVERIFIED` outcome distinguish "this chunk was supposed to be in the index and wasn't" (alarm) from "this came from a live web search" (expected).

See [`docs/quickstart.md`](https://github.com/provenex/provenex-core/blob/main/docs/quickstart.md) for a runnable agentic example.

## How it works

Four components:

**1. Ingestion.** Documents are normalized (Unicode NFC, whitespace collapse, optional case folding, zero-width stripping) and run through a sliding window. Each window gets a Rabin-Karp rolling hash (base `1_000_003`, modulo Mersenne prime `2^61 - 1`) for cheap O(1) updates, strengthened with SHA-256 for collision-resistant identity. The fingerprints (not the document content) are written to the provenance index along with `document_id`, `document_version`, timestamp, authorization state, and customer-supplied tags. The index never stores document text.

**2. Verification.** When your retriever returns chunks, Provenex re-fingerprints each one using the same normalization and hash pipeline, checks the fingerprint against the index, and assigns one of five outcomes (`VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`). A configurable `policy.verification` decides which outcomes are blocked before the next stage.

**3. Policy evaluation.** Each chunk that survived the verification gate goes through the configured policy evaluator (native YAML in the open-source core; Rego and OPA service commercial). The evaluator returns allow or deny plus the names of the rules that fired. The chunk reaches the LLM only if both gates allow it.

**4. Receipt.** After verification and policy evaluation, a JSON receipt is issued that records the chunks, their verification outcomes, the policy that was in effect (both halves), the per-chunk decisions and rules fired, a SHA-256 of the LLM output, and a signature over the whole thing.

For iterative agentic flows, each retrieval step emits its own receipt with a `trajectory` block linking it to its parents — see [Agentic and multi-step flows](#agentic-and-multi-step-flows). The five verification outcomes and the policy framework are unchanged; the trajectory metadata sits alongside them.

See [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md) for the full algorithm, including the architectural distinction between fingerprint-based identity and embedding-based similarity. See [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md) for the schema spec.

## How this fits alongside vector databases (and OPA)

Vector databases store **semantic similarity**: dense embeddings that let you find content similar to a query. Provenex stores **cryptographic identity**: SHA-256 fingerprints that prove bit-exact match against a signed reference, plus a policy evaluation layer over operator-declared rules. These solve different problems and compose cleanly.

| | Vector DBs | Provenex |
| --- | --- | --- |
| Primary storage | Dense embeddings (semantic similarity) | SHA-256 fingerprints (cryptographic identity) + signed metadata |
| Retrieval | Approximate nearest neighbor over vectors | Bit-exact match against signed index |
| Tampering | Not detectable. Embeddings are lossy by design | Detectable. Any modification produces a different SHA-256 |
| Policy enforcement | Tag-based filters at query construction | Evaluator-agnostic rule engine + signed decision record |
| Audit artifact | Vendor dashboard, internal logs | Signed JSON receipt, verifiable offline |
| Trust root | Vendor's SOC 2 attestation | HMAC (or Ed25519) signature, verifiable by anyone with the key |
| Vendor lock-in | Yes (per database) | None. Works alongside any retriever |

The expected enterprise deployment is **both**: vector DB for retrieval performance, Provenex for the policy enforcement record.

### Composing with OPA and existing data governance tools

Provenex sits **above** your existing governance plumbing, not in place of it. PII detection happens in your data pipeline; classification happens in your data catalog; identity is owned by your IdP; authorization rules are authored in OPA / Rego if that's your house language. Provenex consumes the tags and identity those systems produce, applies the policy at retrieval time, and emits the signed record. The Rego adapter (commercial) lets you reuse Rego policies you already have; the OPA service adapter (commercial) lets you delegate decisions to a running OPA instance. The native YAML DSL exists for teams who don't already run OPA — it covers the common retrieval policies without forcing a new platform commitment.

### Why vendor-agnostic matters

If you run more than one vector DB across the enterprise — common for cost or latency reasons — you have separate audit stories with separate vendor trust roots, and no way to produce a single signed record that says "this chunk, wherever it came from, was bit-exact identical to the one we authorized AND passed the policy in effect for this caller."

Provenex works the same way against all of them, because it never talks to the vector DB. It re-fingerprints the chunks the retriever returns, runs the same unified policy across every retrieval path, and emits the same receipt schema. One signed index, one policy engine, one verifiable artifact across every retrieval path in the enterprise. **Migration risk between vector DBs goes to zero.**

## Install

```bash
pip install provenex-core                  # core only (pure stdlib, SQLite backend)
pip install "provenex-core[postgres]"      # + Postgres backend for production
pip install "provenex-core[policy]"        # + native YAML policy DSL (PyYAML)
pip install "provenex-core[langchain]"     # + LangChain integration
pip install "provenex-core[langgraph]"     # + LangGraph integration
pip install "provenex-core[llamaindex]"    # + LlamaIndex integration
pip install "provenex-core[crewai]"        # + CrewAI integration
pip install "provenex-core[ed25519]"       # + Ed25519 asymmetric signing
pip install "provenex-core[export-kafka]"  # + KafkaSink (kafka-python)
pip install "provenex-core[export-aws]"    # + SQSSink / S3AppendSink (boto3)
pip install "provenex-core[export-gcp]"    # + PubSubSink (google-cloud-pubsub)
```

Python 3.10+. The core has zero third-party dependencies; it's pure stdlib. The Postgres backend, framework integrations, the native YAML DSL, and the Ed25519 signer are optional extras.

### Try it in 30 seconds

```bash
pip install "provenex-core[policy]"
git clone https://github.com/provenex/provenex-core.git
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python provenex-core/examples/standalone_demo.py
```

For the integration-pattern story, run [`examples/rag_with_provenance.py`](https://github.com/provenex/provenex-core/blob/main/examples/rag_with_provenance.py). Watch a poisoned chunk that was added directly to the vector store, bypassing Provenex ingest, get caught at the retrieval boundary and blocked from reaching the LLM.

For the **Phase 2** headline demo — a mixed `retrieve → call_tool(allowed) → call_tool(denied) → retrieve` agent flow producing four signed receipts validated end-to-end in one CLI invocation — run [`examples/agentic_admission_demo.py`](https://github.com/provenex/provenex-core/blob/main/examples/agentic_admission_demo.py).

For **MCP** servers: [`examples/mcp_admission_demo.py`](https://github.com/provenex/provenex-core/blob/main/examples/mcp_admission_demo.py) — the `provenex_mcp_admission` decorator on a JSON-RPC `tools/call` handler. Three live requests (allow + deny + allow), the `on_deny` callback pattern emitting a structured JSON-RPC error response, plus the lower-level `wrap_mcp_request` for routers. Pure stdlib — no MCP server library needed.

For **LangGraph** state graphs: [`examples/langgraph_admission_node_demo.py`](https://github.com/provenex/provenex-core/blob/main/examples/langgraph_admission_node_demo.py) — the conditional-edge pattern (`admit_jira → execute_jira` on allow vs `admit_jira → denied_handler` on deny). Two scenarios (engineer-allowed + viewer-denied), both audited end-to-end. Pure stdlib — the integration imports nothing from langgraph, so the demo runs without `[langgraph]` installed.

## CLI

```bash
provenex ingest  --index prov.db --doc-id policy_v4 policy.txt
provenex verify  --index prov.db retrieved_chunk.txt
provenex receipt --index prov.db --output llm_output.txt chunk1.txt chunk2.txt
provenex audit   receipt.json
provenex audit   receipt.json --show-policy          # render the unified policy block (both halves + tool calls)
provenex audit   --trajectory ./receipts/            # validate a whole agentic trajectory at once (mixed step kinds)
provenex policy  validate hr_policy.yaml             # parse + validate a policy file (chunk + tool-call rules)
provenex policy  hash     hr_policy.yaml             # print canonical policy_version_hash(es)
```

`provenex policy validate` is the CI-time check for policy files: a typo or a reserved-but-unimplemented feature fails the build instead of silently allowing at runtime. `provenex policy hash` prints the canonical `policy_version_hash` that will appear on every receipt produced under that policy.

For receipts signed with **Ed25519** (asymmetric), pass `--public-key audit.pub` instead of relying on `PROVENEX_SIGNING_SECRET`. An auditor with only the public key can verify but cannot forge: the strongest version of the "verifiable by anyone" guarantee, suitable for handing receipts to external regulators.

## Why open source?

Security teams won't trust a black box. If a regulator asks how your access-policy enforcement system works, "it's proprietary" is not an answer. The whole algorithm needs to be auditable end to end: normalization, rolling hash, sliding window, SHA-256 strengthening, policy evaluator semantics, receipt schema, signature payload. So it is.

### Open source (this repo, MIT)

- Fingerprinting engine (normalizer + Rabin-Karp + SHA-256)
- **Postgres** provenance index for multi-node production (HMAC-signed rows, row-locked concurrent ingest)
- **SQLite** provenance index for single-node development (HMAC-signed rows, stdlib-only)
- RFC 6962 Merkle transparency log (optional, on top of either index)
- Receipt generation, HMAC + Ed25519 signing, offline inclusion-proof verification
- **Unified policy** (schema 2.3.0): single top-level `policy` block with `verification`, `access_control`, and `tool_call_control` halves
- **Native YAML policy DSL** for both chunk decisions and tool-call admission: pluggable `PolicyEvaluator` and `ToolCallPolicyEvaluator` protocols with the YAML evaluators as the reference backends; operators include `in` / `not_in` / `not_older_than` / `matches_pattern` / `not_matches_pattern` / `length_at_most`
- **`metadata_binding`** per decision: each `chunk_metadata` block on the receipt declares whether it was tag-at-ingest (signed by the index row) or tag-at-evaluate (looked up at decision time). Lets an auditor see the trust class of every input at a glance.
- **Bloom-filter interface** (`BloomFilterIndex` ABC + `NoopBloomFilter` + `BloomAcceleratedIndex` wrapper). The interface is OSS so commercial deployments are drop-in; the actual high-throughput Bloom implementation ships commercially.
- **Tool-call admission primitive** (Phase 2, schema 2.2.0+): `provenex.admission_check(...)` returns a signed receipt with `actions[]` + `policy.tool_call_control`. Reference MCP middleware (`provenex.tool_call.integrations.mcp`) and LangChain wrapper (`ProvenexToolWrapper`). Decision and proof, not execution — the wrapper never holds tokens or proxies the call.
- **Source-of-record correlation fields** (schema 2.3.0): top-level `caller_hash` (SHA-256 over the canonical caller dict; or HMAC-SHA256 with an opt-in deployment salt for per-deployment unlinkability) and optional `trajectory.session_id` (multi-trajectory correlation key). Decision-and-proof artifacts — they don't influence policy decisions, just make receipts joinable downstream by a SIEM / anomaly detector.
- **Step-kind coverage entrypoints** (0.6.5+): `verify_memory(...)`, `admit_memory_write(...)`, `admit_model_inference(...)` — convenience wrappers that produce admission-shaped receipts for the full agent surface (`memory_read` / `memory_write` / `model_inference` step kinds). Default `redact_value=True` / `redact_prompt=True` so verbatim values stay off the receipt by default; the hash anchor (`value_hash` / `prompt_hash`) is always recorded.
- **Streaming export sinks** (0.6.6+): `ReceiptSink` Protocol + reference sinks for `StdoutJSONLSink` / `FileJSONLSink` (date-rotated) / `MultiSink` (fan-out) / `RetryQueueSink` (bounded in-process retry) in the stdlib core. `KafkaSink` / `SQSSink` / `S3AppendSink` (date-hour-partitioned) / `PubSubSink` behind optional `[export-kafka]` / `[export-aws]` / `[export-gcp]` extras. Every emission entrypoint accepts `sink=`; failures are swallowed-and-logged so the agent's hot path is never broken by export degradation.
- **OCSF v1.3 mapping** (0.6.7+, stdlib core): `provenex.receipt_to_ocsf(receipt_dict)` transforms one signed receipt into one or more OCSF events (Application Activity / API Activity / Detection Finding). `OCSFAdapter` wraps any `ReceiptSink` so the stream emits OCSF events instead of raw receipts — instantly compatible with Splunk / Datadog / Elastic / Microsoft Sentinel. Full mapping spec in [`docs/ocsf_mapping.md`](https://github.com/provenex/provenex-core/blob/main/docs/ocsf_mapping.md).
- **Source-of-record positioning + detection patterns** (0.6.8+): [`docs/anomaly_detection.md`](https://github.com/provenex/provenex-core/blob/main/docs/anomaly_detection.md) — the canonical reference for how receipts integrate with downstream anomaly detectors / UEBA / SIEM. Schema field reference for detectors, five worked detection patterns, trust model, and the operational reasoning for the firewall / SIEM split. **The native DSL deliberately refuses** trajectory-level rules so per-decision purity (and the audit-anchor guarantees that depend on it) stays intact — see [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md#what-the-native-dsl-deliberately-doesnt-do-and-why).
- Trajectory receipts (schema 1.3.0+): per-step receipts linked into a DAG for agentic / multi-step flows, mixing retrieval, tool-call, memory, and model-inference steps
- Self-attribution claims (schema 1.4.0+): signed but unverified records of what the agent said it used
- Content-source classifier (schema 1.4.0+): distinguish indexed-corpus chunks from live-tool / memory-store chunks
- LangChain / LangGraph / LlamaIndex / CrewAI / MCP integrations
- Framework-agnostic `verify_chunks` / `verify_memory` / `admission_check` / `admit_memory_write` / `admit_model_inference` for everything else
- Public hash helpers: `compute_caller_hash(caller, salt=...)` and `compute_value_hash(value)` so downstream consumers can independently re-derive the hashes embedded on receipts
- CLI: `provenex ingest / verify / receipt / audit / policy`
- Python SDK: `pip install provenex-core`

### Commercial (at provenex.ai)

- **Rego adapter** — load Rego bundles into the same `PolicyEvaluator` protocol; emit the same receipt shape
- **OPA service adapter** — delegate evaluation to a running OPA instance over HTTP
- Hosted provenance index with distributed signed append-only storage
- Transparency-log-backed policy bundle records (so `policy_in_transparency_log: true` lights up)
- **Bloom-filter implementation** for high-throughput verification at 10M+ chunk scale (the OSS ships the interface; commercial ships the working filter)
- Compliance-grade export formats (PDF, CSV, JSON-LD for regulator-side / semantic-web consumers)
- Identity-provider integration (RequestContext auto-populated from Okta / Azure AD)
- Inference attribution and temporal decay scoring
- Enterprise SSO / RBAC, HSM-backed Ed25519, dedicated support, SLA

The interfaces (`ProvenanceIndex`, `PolicyEvaluator`, `BloomFilterIndex`) are the same across open source and commercial. Moving from one to the other is one line of code: the class you instantiate.

## Privacy and data sovereignty

The index stores fingerprints (one-way SHA-256 hashes) and metadata. **No document content, no PII, no chunk text is ever written.** Anyone with the index can verify retrieval, but no one can recover document content from it. The `policy.access_control.decisions[].inputs` field on the receipt records the metadata the evaluator looked at (residency tags, classification, caller role) — operators who want to redact those can set `inputs: null` while keeping the `inputs_hash` for offline verification.

## License

MIT. See [LICENSE](https://github.com/provenex/provenex-core/blob/main/LICENSE).

## Links

**Reading:**

- [Five Things People Mean by "AI Provenance" (And Which One Is For You)](https://provenex.ai/blog/five-things-ai-provenance): the category map, and where Provenex sits
- [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md): unified policy reference (verification + access control), DSL, worked examples, commercial roadmap
- [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md): full algorithm, threat model, and architectural comparison to embedding-based systems
- [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md): receipt schema 2.0.0 specification
- [`docs/quickstart.md`](https://github.com/provenex/provenex-core/blob/main/docs/quickstart.md): 5-minute getting-started, including a policy-driven retrieval path
- [`docs/threat_model.md`](https://github.com/provenex/provenex-core/blob/main/docs/threat_model.md): attacker model, defended/undefended threats, trust model for policy decisions
- [`docs/scaling.md`](https://github.com/provenex/provenex-core/blob/main/docs/scaling.md): 1M-chunk benchmark numbers and policy-evaluation latency profile

**Project:**

- Homepage: [provenex.ai](https://provenex.ai)
- Issues and discussion: GitHub Issues on this repo
- Commercial features: contact via provenex.ai
