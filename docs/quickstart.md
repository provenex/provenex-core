# Quickstart

Get a working provenance receipt in five minutes. Several paths below — drop in alongside a LangChain pipeline, run standalone, layer in a transparency log, swap to Ed25519, thread receipts through an agentic / multi-step flow, or enforce policy on agentic tool calls (Phase 2, schema 2.2.0).

## Install

```bash
pip install "provenex-core[langchain]"   # or [langgraph] / [crewai] / [llamaindex] / [ed25519]
```

For the core SDK with no framework integration, drop the extras. Pure stdlib core; everything else is opt-in. Python 3.10+.

## Set a signing secret

The provenance index and receipt signer both need an HMAC key. In production this lives in your secrets manager. For local development, export it:

```bash
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

Anything calling Provenex in this shell will pick it up automatically. You can also pass `signing_secret=b"..."` explicitly to `SQLiteProvenanceIndex` and `HmacSha256Signer`.

## Path A: drop into an existing LangChain pipeline

```python
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor, ProvenexRetriever
from provenex.core.receipt import HmacSha256Signer

# One-time setup.
index = SQLiteProvenanceIndex("provenance.db")

# Ingest documents whenever they're added or updated. `documents` can be
# LangChain Documents or any object with a `page_content` attribute.
ingestor = ProvenexIngestor(index=index)
ingestor.ingest(documents, doc_id="policy_v4", authorized=True)

# Wrap your existing retriever. `your_existing_retriever` is the
# Chroma/FAISS/Pinecone/etc. retriever you already use.
retriever = ProvenexRetriever(
    base_retriever=your_existing_retriever,
    index=index,
    signer=HmacSha256Signer(),
)

# At inference time:
result = retriever.get_relevant_documents_with_receipt(
    query="What is the encryption policy?",
    output_text=llm_output,  # pass the LLM's answer so its hash goes on the receipt
)

print(result.receipt.to_json())
for doc in result.documents:       # the chunks that survived policy filtering
    ...
for doc in result.blocked:         # the chunks policy removed
    ...
```

That's it. Your vector store is untouched. The receipt is signed, JSON-serializable, and self-describing.

## Path B: standalone, no LangChain

The core SDK works without any framework integration:

```python
from provenex.core.fingerprinter import Fingerprinter
from provenex.core.receipt import HmacSha256Signer, ReceiptBuilder
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.policy.policy import VerificationPolicy

index = SQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()

# Ingestion.
result = fp.fingerprint(document_text)
for f in result.fingerprints:
    index.add(
        fingerprint=f.fingerprint,
        document_id="policy_v4",
        document_version=result.document_version,
        chunk_offset=f.offset,
        chunk_length=f.length,
        authorized=True,
    )

# Retrieval-time verification.
builder = ReceiptBuilder(policy=VerificationPolicy())
for chunk_text in retrieved_chunks:
    chunk_fp = fp.fingerprint_chunk(chunk_text)
    outcome = index.verify(chunk_fp)
    entry = index.lookup(chunk_fp)
    builder.add_source(fingerprint=chunk_fp, outcome=outcome, entry=entry)

receipt = builder.finalize(output_text=llm_output, signer=HmacSha256Signer())
print(receipt.to_json())
```

## Path C: with transparency log (offline verification)

The `SQLiteProvenanceIndex` above protects each row with an HMAC. For an additional layer that lets an auditor verify a receipt with no access to the index, no signing key, and no network, swap in `MerkleSQLiteProvenanceIndex`. Same `ProvenanceIndex` interface, plus a tree root and inclusion proofs.

```python
from provenex.core.fingerprinter import Fingerprinter
from provenex.core.merkle import verify_inclusion_proof
from provenex.core.receipt import HmacSha256Signer, ReceiptBuilder
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex
from provenex.policy.policy import VerificationPolicy

# Producer side: ingest as before, then publish the tree root.
index = MerkleSQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()
result = fp.fingerprint(document_text)
for f in result.fingerprints:
    index.add(
        fingerprint=f.fingerprint,
        document_id="policy_v4",
        document_version=result.document_version,
        chunk_offset=f.offset,
        chunk_length=f.length,
        authorized=True,
    )
published_tree_root = index.tree_root()  # share this; sign it; gossip it

# Per-retrieval: pull the inclusion proof out alongside the verify outcome.
chunk_fp = fp.fingerprint_chunk(retrieved_chunk)
leaf_bytes, leaf_index, proof = index.inclusion_proof(chunk_fp)

builder = ReceiptBuilder(policy=VerificationPolicy())
builder.add_source(
    fingerprint=chunk_fp,
    outcome=index.verify(chunk_fp),
    entry=index.lookup(chunk_fp),
    leaf_index=leaf_index,
    inclusion_proof=proof,
)
receipt = builder.finalize(
    output_text=llm_output,
    signer=HmacSha256Signer(),
    transparency_log={"tree_size": index.tree_size(), "tree_root": index.tree_root()},
)
```

An auditor with the receipt JSON and the previously-published tree root can verify offline, no database needed:

```python
# Auditor side: receipt.sources[i] carries leaf_index + inclusion_proof,
# receipt.transparency_log carries tree_size + tree_root. That's everything.
ok = verify_inclusion_proof(
    leaf=leaf_bytes,                                # canonical row bytes
    leaf_index=leaf_index,
    tree_size=tree_size,
    proof=[bytes.fromhex(p.split(":", 1)[1]) for p in proof],
    root=bytes.fromhex(published_tree_root.split(":", 1)[1]),
)
assert ok
```

See [`../examples/standalone_demo.py`](../examples/standalone_demo.py) for a runnable end-to-end version that also demonstrates the HMAC layer catching a tampered row.

## Path D: Ed25519 asymmetric signing (external auditors)

HMAC-SHA256 receipts are fine when the verifier and the signer are inside the same organisation: anyone with the secret can verify *and* forge, so the secret has to stay private. If you want an auditor who can verify but cannot forge (regulator, external compliance, cross-org provenance), swap in Ed25519.

```bash
pip install "provenex-core[ed25519]"
```

```python
from provenex.core.ed25519 import Ed25519Signer
from provenex.core.fingerprinter import Fingerprinter
from provenex.core.receipt import ReceiptBuilder, verify_receipt_signature
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex
from provenex.policy.policy import VerificationPolicy

# One-time setup: generate a keypair. Keep the private PEM in your
# secrets manager. Distribute the public PEM to auditors.
signer = Ed25519Signer.generate()
private_pem = signer.private_key_pem(password=b"...")   # encrypt at rest
public_pem  = signer.public_key_pem()                   # public artifact

# Producer side: sign receipts with the private key.
index = MerkleSQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()
# ... ingest as usual ...
builder = ReceiptBuilder(policy=VerificationPolicy())
# ... add sources ...
receipt = builder.finalize(output_text=llm_output, signer=signer)

# Auditor side (different machine, different team, no private key):
verifier = Ed25519Signer.from_public_key_pem(public_pem)
ok = verify_receipt_signature(json.loads(receipt.to_json()), verifier)
assert ok
```

The auditor cannot sign. `verifier.sign(...)` raises a `RuntimeError`. That's the whole point: receipts are now end-to-end provably authentic against your public key alone.

From the command line:

```bash
provenex audit receipt.json --public-key audit.pub
```

## Path E: agentic / multi-step flows

When an agent retrieves more than once per answer — Self-RAG, RAT, LangGraph DAGs, CrewAI multi-agent crews — each retrieval emits its own receipt, and Provenex links them into a verifiable trajectory. Pick whichever fits your stack:

**Framework-agnostic** (works anywhere):

```python
import provenex

# session_id (schema 2.3.0+) is a multi-trajectory correlation key for
# downstream anomaly detectors / SIEMs. Set once at start_trajectory
# and every receipt in the trajectory carries it.
traj = provenex.start_trajectory(
    agent_id="research_agent",
    session_id="research-session-2026-05-14-001",
)
r1 = provenex.verify_chunks(chunks_step_a, index=index, trajectory=traj)
r2 = provenex.verify_chunks(chunks_step_b, index=index, trajectory=r1.next_trajectory)
r3 = provenex.verify_chunks(
    chunks_step_c, index=index, trajectory=r2.next_trajectory, output_text=llm_answer
)

# After the flow, audit the whole trajectory:
audit = provenex.audit_trajectory_dag([r.receipt.to_dict() for r in (r1, r2, r3)])
assert audit.ok
```

**LangGraph** (drop-in node):

```python
from provenex.integrations.langgraph import provenex_retrieval_node, start_trajectory_state

retrieve = provenex_retrieval_node(base_retriever=your_retriever, index=index)

# Initialise state once at the start of the graph:
initial_state = {**start_trajectory_state(agent_id="my_agent"), "query": "..."}
# Then add `retrieve` as a node; LangGraph calls it like any other.
```

**CrewAI** (session wraps tools):

```python
from provenex.integrations.crewai import ProvenexCrewSession

session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(), agent_id="research_agent")
search_tool = session.wrap_tool(your_search_callable, step_kind="retrieval")
memory_read = session.wrap_tool(your_memory_callable, step_kind="memory_read")
# ... pass these to your CrewAI Agents as tools; receipts accumulate in session.receipts ...
```

End-to-end audit from the shell:

```bash
provenex audit --trajectory ./receipts/   # validates the whole DAG, incl. tool-call steps
```

The trajectory audit now emits an aggregate summary alongside the per-receipt detail — total chunks (verified / stale / unauthorized / unverified / tampered), total actions (allowed / denied), and a breakdown by step kind. Both human-readable and `--json` output include it.

## Path F: policy-driven retrieval

When you want every retrieval to clear a unified policy (verification + access control) and emit a signed decision record.

```bash
pip install "provenex-core[policy]"   # adds PyYAML for the native DSL
```

Write a unified policy YAML. Save as `provenex_policy.yaml`:

```yaml
version: 1
policy_id: hr-corpus-retrieval-v3

verification:
  block_unauthorized: true
  block_tampered: true

access_control:
  rules:
    - name: jurisdiction_eu_only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency:
          in: [EU, EEA]
      on_violation: deny
  defaults:
    unknown_metadata: deny
```

Validate it at build time so a typo fails fast:

```bash
provenex policy validate provenex_policy.yaml
provenex policy hash provenex_policy.yaml
```

Wire it into retrieval:

```python
from provenex import (
    verify_chunks, Policy, RequestContext,
    HmacSha256Signer, SQLiteProvenanceIndex,
)

index = SQLiteProvenanceIndex("provenance.db")
policy = Policy.from_yaml("provenex_policy.yaml")

# At query time, build the request context for the caller and surface
# the per-chunk metadata your upstream PII / classification / residency
# tools have tagged.
request = RequestContext(
    caller={"role": "hr_admin", "id": "u_4218"},
    jurisdiction="EU",
    purpose="customer_support",
    timestamp="2026-05-13T14:32:07Z",
)
chunks = [doc.page_content for doc in retrieved_documents]
metadata = [doc.metadata for doc in retrieved_documents]

result = verify_chunks(
    chunks=chunks,
    index=index,
    signer=HmacSha256Signer(),
    policy=policy,
    request_context=request,
    chunk_metadata=metadata,
)

# Only chunks that passed BOTH gates appear in result.kept. The receipt
# records both verdicts on every chunk under the unified `policy` block.
feed_to_llm(result.kept)
save_receipt(result.receipt)
```

Inspect the receipt with the unified policy block rendered:

```bash
provenex audit receipt.json --show-policy
```

A `VERIFIED` chunk can still be policy-denied (wrong jurisdiction, missing role); a `STALE` chunk can still be policy-allowed if the policy explicitly accepts stale chunks. The two gates are independent. See [`docs/policy.md`](policy.md) for the DSL reference and worked examples; see [`docs/threat_model.md`](threat_model.md#trust-model-for-policy-decisions) for the trust model.

## Path G: agentic tool-call admission (Phase 2)

For enforcing what an agent is allowed to **do**, not just what it can read. Same unified policy file, second half lit up.

```bash
pip install "provenex-core[policy]"   # PyYAML for the DSL; same extra as access_control
```

Extend the unified YAML with a `tool_call_control:` section:

```yaml
version: 1
policy_id: incident-response-agent-v1

# ... verification + access_control as before ...

tool_call_control:
  rules:
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system: { in: [google_custom_search, bing_v7] }
      on_violation: deny

    - name: no_secrets_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*(api[_-]?key|password|secret)*"
        tool.parameters.q:
          length_at_most: 500
      on_violation: deny

    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue, update_issue, delete_issue] }
      require:
        request.caller.role: { in: [engineer, manager, admin] }
      on_violation: deny

  defaults:
    unknown_metadata: deny
```

**Framework-agnostic** — `admission_check` is the Phase 2 sibling of `verify_chunks`:

```python
from provenex import (
    HmacSha256Signer, Policy, RequestContext,
    ToolCallContext, admission_check,
)

policy = Policy.from_yaml("agent_policy.yaml")
request = RequestContext(
    caller={"id": "u_42", "role": "engineer"},
    jurisdiction="US",
    purpose="incident_response",
    timestamp="2026-05-14T11:30:00Z",
    # Optional schema-2.3.0 correlation tag. Stamped onto the emitted
    # receipt's trajectory.session_id field (when a trajectory is in
    # scope); silently dropped on single-shot calls.
    session_id="incident-2026-05-14-customer-success-001",
)

result = admission_check(
    tool=ToolCallContext(
        name="jira", operation="create_issue",
        parameters={"project": "INC", "summary": "..."},
        target_system="acme.atlassian.net",
    ),
    request=request,
    policy=policy,
    signer=HmacSha256Signer(),
)
if result.allowed:
    jira_client.create_issue(...)        # YOUR code, YOUR credentials
save_receipt(result.receipt)             # signed; denials are auditable too
```

**Decision and proof, not execution.** Provenex returns a decision and emits a signed receipt; the caller makes the actual call. Provenex never holds OAuth tokens, never proxies traffic, and never sits on the response-data path.

**Per-decision, not cross-decision.** The native DSL rules above are pure functions of `(tool, request)` — no trajectory state, no aggregations, no external lookups. That's by design: it's what makes `inputs_hash` an audit anchor a regulator can reproduce years later. Trajectory-level rules ("deny if > N web_search calls in this trajectory") and sequence-pattern detection belong **downstream** — in your anomaly detector reading the receipt stream. See [`anomaly_detection.md`](anomaly_detection.md) for the positioning and worked patterns, or [`policy.md`](policy.md#what-the-native-dsl-deliberately-doesnt-do-and-why) for the design rationale.

**LangChain** — wrap any tool with admission semantics:

```python
from provenex.tool_call.integrations.langchain import ProvenexToolWrapper

wrapped = ProvenexToolWrapper(
    base_tool=jira_tool,                 # any object with .name + .invoke(input)
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    request_factory=lambda inv: RequestContext(...),   # host owns identity
)
agent.tools = [wrapped]                  # rest of the agent code unchanged
```

**CrewAI** — the session wraps tool callables; receipts accumulate in `session.receipts`:

```python
from provenex.integrations.crewai import ProvenexCrewSession

session = ProvenexCrewSession(
    index=SQLiteProvenanceIndex("provenance.db"),
    signer=HmacSha256Signer(),
    policy=Policy.from_yaml("agent_policy.yaml"),
    agent_id="incident_agent",
)
wrapped_web_search = session.wrap_tool_admission(
    web_search_tool,
    name="web_search", operation="query",
    target_system="google_custom_search",
    request_factory=lambda *a, **kw: RequestContext(...),
)
# Pass wrapped_web_search to CrewAI Agents as a tool. Denials raise
# ToolCallDenied; the receipt is still appended for audit.
```

**LangGraph** — admission node writes the decision into state so a conditional edge routes execution:

```python
from provenex.integrations.langgraph import provenex_admission_node

admit_jira = provenex_admission_node(
    name="jira",
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    operation="create_issue",
    target_system="acme.atlassian.net",
    request_factory=lambda state: RequestContext(
        caller=state["caller"], jurisdiction=state["jurisdiction"],
        purpose=state["purpose"], timestamp=state["timestamp"],
    ),
)
# graph.add_node("admit_jira", admit_jira)
# graph.add_conditional_edges(
#     "admit_jira",
#     lambda s: "execute_jira" if s["tool_admitted"] else "denied_handler",
# )
```

**MCP** — decorate a `tools/call` handler:

```python
from provenex.tool_call.integrations.mcp import provenex_mcp_admission

@provenex_mcp_admission(
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    request_factory=build_request_context_from_mcp_request,
)
def handle_tools_call(request):
    # On allow: this handler runs as normal.
    # On deny: ToolCallDenied is raised (or your on_deny callback fires).
    return your_existing_tool_handler(request)
```

Every wrapper emits the same receipt shape. A receipt produced via the LangChain wrapper validates the same way as one via MCP middleware. That's the standard — and it does not fragment by framework.

Runnable end-to-end demos for the framework integrations:

- [`../examples/agentic_admission_demo.py`](../examples/agentic_admission_demo.py) — the headline four-step `retrieve → call_tool(allowed) → call_tool(denied) → retrieve` trajectory, audited end-to-end in one CLI invocation.
- [`../examples/mcp_admission_demo.py`](../examples/mcp_admission_demo.py) — full MCP integration. Three live `tools/call` requests through a decorated handler (allow + deny + allow), the `on_deny` callback pattern producing a structured JSON-RPC error response, and `wrap_mcp_request` for routers that don't decorate. Pure stdlib — no actual MCP server library needed.
- [`../examples/langgraph_admission_node_demo.py`](../examples/langgraph_admission_node_demo.py) — full LangGraph integration. Conditional-edge pattern: `admit_jira → if allowed → execute_jira → END` vs `→ if denied → denied_handler → END`. Two scenarios (engineer-allowed + viewer-denied), both audited. Pure stdlib — the integration imports nothing from langgraph, so the demo runs without the optional `[langgraph]` extra.

See [`docs/policy.md`](policy.md) for the full DSL reference including the new `matches_pattern` / `not_matches_pattern` / `length_at_most` operators and the `tool.*` path roots; see [`docs/receipt_format.md`](receipt_format.md) for the schema 2.2.0 `actions[]` and `policy.tool_call_control` field reference.

## Path H: memory reads, memory writes, and model-inference (0.6.5+)

When you want every action class an agent takes — not just retrieve and tool-call — to land on a signed receipt under the right `step_kind`. Three thin convenience entrypoints over the existing primitives.

```python
from provenex import (
    HmacSha256Signer, Policy, RequestContext, SQLiteProvenanceIndex,
    admit_memory_write, admit_model_inference, start_trajectory,
    verify_memory,
)

index = SQLiteProvenanceIndex("memory.db")    # the memory store as a ProvenanceIndex
signer = HmacSha256Signer()
trj = start_trajectory(agent_id="incident_agent",
                       session_id="incident-2026-05-14-001")
request = RequestContext(
    caller={"id": "u_42", "role": "engineer"}, jurisdiction="US",
    purpose="incident_response", timestamp="2026-05-14T11:30:00Z",
    session_id="incident-2026-05-14-001",
)

# Memory read — same five outcomes as retrieval. Source records carry
# content_source="memory_store" so an UNVERIFIED outcome reads as
# "memory miss" rather than "corpus miss" to an auditor.
r1 = verify_memory(["last user msg: where is the runbook?"], index=index,
                   signer=signer, request_context=request, trajectory=trj)

# Memory write — admission-shaped. name="memory.write",
# operation=<memory_key>. value_hash always recorded; verbatim value
# REDACTED by default (memory values often contain PII).
r2 = admit_memory_write(
    memory_key="user_profile",
    value={"prefers": "dark_mode", "tz": "America/Los_Angeles"},
    request=request, store_id="crewai_memory",
    signer=signer, trajectory=r1.next_trajectory,
)

# Model inference — admission-shaped. name=<model>, operation="complete"
# (or "stream" / "embed" / "chat"), target_system=<provider>.
# prompt_hash always recorded; verbatim prompt REDACTED by default.
r3 = admit_model_inference(
    model_name="claude-opus-4-7",
    prompt=[{"role": "user", "content": "Summarize INC-2026-05-001"}],
    request=request, target_provider="anthropic",
    extra_parameters={"max_tokens": 4000, "temperature": 0.2},
    signer=signer, trajectory=r2.next_trajectory,
)

# All three are linked under one trajectory. End-of-flow audit shows
# the mixed-step-kind distribution.
```

```bash
provenex audit --trajectory ./receipts/   # one CLI pass; mixed kinds
```

**Why this matters.** Every class of agent action — read corpus, read memory, write memory, call a model, call a tool — produces one signed receipt under one trajectory. A downstream anomaly detector / SIEM sees the full event stream classified by `step_kind`, not a hodgepodge of "tool_call" entries it has to disambiguate. `caller_hash` and `session_id` (schema 2.3.0+) make per-caller / per-session grouping trivial without crawling per-decision input blobs.

**Redaction defaults.** Memory values and LLM prompts are recorded as **hashes only** by default (`value_hash`, `prompt_hash`) — both fields often contain PII or customer data, and Provenex stays decision-and-proof, never on the data path. The hash anchor stays on the receipt for audit; an operator who needs verbatim recording for debugging passes `redact_value=False` or `redact_prompt=False`.

**Per-deployment unlinkability.** Pass `caller_hash_salt=b"..."` on any of the entrypoints above (or on `verify_chunks` / `admission_check`) to switch `caller_hash` from bare SHA-256 to HMAC-SHA256 keyed by the salt. Two deployments with different salts produce different `caller_hash` values for the same caller — useful when you don't want third-party detectors to cross-correlate users across your tenants. Same algorithm family, same wire format; the prefix (`sha256:` vs `hmac-sha256:`) tells consumers which mode was used.

See [`../examples/memory_and_model_inference_demo.py`](../examples/memory_and_model_inference_demo.py) for a runnable end-to-end demo.

## Streaming receipts to a SIEM / firehose (0.6.6+)

Every receipt-emitting entrypoint accepts an optional `sink=` parameter. Provenex publishes after the receipt is finalised. The hot path is unchanged; the firehose runs alongside.

```python
from provenex import (
    HmacSha256Signer, RequestContext, ToolCallContext,
    admission_check, MultiSink, FileJSONLSink, StdoutJSONLSink,
)
from provenex.export.kafka import KafkaSink   # extra: [export-kafka]

# Three destinations: real-time firehose + local archive + dev stdout.
sink = MultiSink([
    KafkaSink(bootstrap_servers="kafka.internal:9092", topic="provenex-receipts"),
    FileJSONLSink("/var/log/provenex"),
    StdoutJSONLSink(),
])

result = admission_check(
    tool=ToolCallContext(name="jira", operation="create_issue", parameters={...}),
    request=RequestContext(...),
    signer=HmacSha256Signer(),
    sink=sink,
)
```

**Error semantics.** Sink failures are swallowed and logged via `warnings.warn` — the agent's hot path is never broken by export degradation. Wrap with `RetryQueueSink(downstream, maxlen=...)` to buffer through transient broker hiccups.

**Reference sinks.** `StdoutJSONLSink`, `FileJSONLSink` (daily-rotated), `MultiSink` (fan-out), `RetryQueueSink` (bounded retry) in the stdlib core. `KafkaSink`, `SQSSink`, `S3AppendSink` (date-hour-partitioned), `PubSubSink` behind optional extras. Define your own via the `ReceiptSink` Protocol. See [`streaming_export.md`](streaming_export.md) for the full reference; see [`../examples/streaming_export_demo.py`](../examples/streaming_export_demo.py) for a runnable end-to-end demo.

## OCSF export — feeding receipts into your SIEM (0.6.7+)

Provenex maps receipts to OCSF v1.3 events so they're instantly readable by Splunk / Datadog / Elastic / Microsoft Sentinel. Two surfaces — a pure transformation function and a streaming-sink adapter.

```python
# Pure transformation: convert a receipt to OCSF events for batch pipelines
from provenex import receipt_to_ocsf

events = receipt_to_ocsf(result.receipt.to_dict())
# → [{"class_uid": 6003, "class_name": "API Activity", ...}]

# Streaming adapter: wraps any ReceiptSink so it ships OCSF events instead
from provenex import OCSFAdapter, MultiSink, FileJSONLSink
from provenex.export.kafka import KafkaSink

sink = MultiSink([
    OCSFAdapter(
        downstream=KafkaSink(bootstrap_servers="kafka:9092", topic="security-events"),
        extra_metadata={"organization_uid": "acme-corp", "environment": "prod"},
    ),
    FileJSONLSink("/var/log/provenex/raw"),   # raw archive in parallel
])
admission_check(..., sink=sink)
```

The OCSF event classes Provenex emits:

| Provenex condition | OCSF class | UID | Severity |
| --- | --- | --- | --- |
| Allowed retrieval / `memory_read` | Application Activity | 6005 | Informational |
| Allowed `tool_call` / `memory_write` / `model_inference` | API Activity | 6003 | Informational |
| Verification block (TAMPERED, UNAUTHORIZED, etc.) | Detection Finding | 2004 | Critical |
| Policy deny | Detection Finding | 2004 | High |

Correlation fields land where SIEMs expect them: `caller_hash` → `actor.user.uid`; `trajectory_id` → `metadata.correlation_uid`; `session_id` → `metadata.session_uid`; `step_kind` → `metadata.labels[]`. See [`ocsf_mapping.md`](ocsf_mapping.md) for the full field-by-field spec, and [`../examples/ocsf_export_demo.py`](../examples/ocsf_export_demo.py) for a runnable demo.

## Verify a receipt independently

Anyone with the receipt JSON and the signing secret can confirm the receipt hasn't been altered:

```python
import json
from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature

receipt = json.loads(receipt_json)
ok = verify_receipt_signature(receipt, HmacSha256Signer(secret=b"..."))
assert ok, "receipt signature invalid; receipt has been tampered with"
```

For asymmetric verification (so an auditor can verify without holding the signing key), implement the `ReceiptSigner` interface with Ed25519 or similar and swap it in. The receipt structure does not change.

## Reading receipts as an anomaly-detection event stream

Schema 2.3.0 adds two correlation fields that make Provenex receipts the source-of-record an AI-agent anomaly detector or SIEM consumes:

- **`caller_hash`** (top-level) — a stable SHA-256 over `request_context.caller`. `GROUP BY caller_hash` to baseline a single user's activity across all their receipts without crawling per-decision input blobs.
- **`trajectory.session_id`** (optional) — a caller-chosen opaque string that correlates receipts across multiple trajectories under one logical session.

```python
# Read your receipts dir as a downstream consumer would. Bucket by
# caller, then by session, to surface per-caller / per-session shape.
import json
from collections import Counter
from pathlib import Path

caller_actions = Counter()
session_step_kinds = Counter()
for path in Path("./receipts").glob("*.json"):
    r = json.loads(path.read_text())
    caller_actions[r.get("caller_hash", "anonymous")] += len(r.get("actions", []))
    sess = r.get("trajectory", {}).get("session_id")
    sk = r.get("trajectory", {}).get("step_kind")
    if sess and sk:
        session_step_kinds[(sess, sk)] += 1
```

Provenex emits the source-of-record. The detector / SIEM that reads it is the detector. We don't compete with the detector — we're the substrate that makes detection possible. See [`../examples/anomaly_correlation_demo.py`](../examples/anomaly_correlation_demo.py) for a runnable demo (stdlib only) and [`../examples/anomaly_correlation_with_policy_demo.py`](../examples/anomaly_correlation_with_policy_demo.py) for the same demo running against a unified YAML policy.

## Next steps

- [`how_it_works.md`](how_it_works.md): the algorithm, end to end
- [`policy.md`](policy.md): native YAML DSL reference, evaluator protocol, worked examples, roadmap
- [`receipt_format.md`](receipt_format.md): schema reference for the receipt JSON
- [`langchain_integration.md`](langchain_integration.md): deeper LangChain integration notes
- [`../examples/standalone_demo.py`](../examples/standalone_demo.py): end-to-end Merkle demo. Ingest, verify, tamper-detection, offline proof verification. Pure stdlib, no LangChain.
- [`../examples/rag_with_provenance.py`](../examples/rag_with_provenance.py): RAG integration pattern. Ingest into both vector store and Provenex, verify at retrieval, watch the policy block a chunk that bypassed Provenex ingest.
- [`../examples/basic_langchain_rag.py`](../examples/basic_langchain_rag.py): full runnable end-to-end demo against a LangChain retriever
- [`../examples/policy_configuration.py`](../examples/policy_configuration.py): dev / prod / high-assurance policy presets
- [`../examples/agentic_admission_demo.py`](../examples/agentic_admission_demo.py): the Phase 2 headline demo. Mixed `retrieve → call_tool(allowed) → call_tool(denied) → retrieve` trajectory; one CLI audit pass over four signed receipts.
- [`scaling.md`](scaling.md): 1M-chunk benchmark numbers (verify p50 371 µs, offline proof verify 47 µs) and honest discussion of how they move on enterprise hardware
