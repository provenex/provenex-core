# provenex-core

[![test](https://github.com/provenex/provenex-core/actions/workflows/test.yml/badge.svg)](https://github.com/provenex/provenex-core/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/provenex-core.svg?cacheSeconds=300&v=0.9.0)](https://pypi.org/project/provenex-core/)
[![Downloads](https://img.shields.io/pypi/dm/provenex-core.svg?cacheSeconds=3600)](https://pypistats.org/packages/provenex-core)
[![Python](https://img.shields.io/pypi/pyversions/provenex-core.svg?cacheSeconds=300&v=0.9.0)](https://pypi.org/project/provenex-core/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/provenex/provenex-core/blob/main/LICENSE)

**Policy enforcement for AI data access, with cryptographic proof.**

You don't know which retrieval, tool call, or memory write your AI agents are doing right now, and you can't prove what they did to a regulator. Provenex is the access-control layer for AI agents that emits cryptographically signed evidence of every decision.

One CISO question this answers in plain English: **Can this agent access Jira, Salesforce, or this connector under the policy in effect at the time?** Provenex says yes or no per call, and emits a signed receipt that an auditor can verify offline without your infrastructure.

**What you get.** Governance, regulator-survivable audit, insider-risk reduction. CloudTrail and IAM for AI agents, with cryptographic proof.

**What it is.** Decision and proof, not execution. Library, not service. The OSS Python core wraps any retrieval, tool call, memory write, or model inference with a unified YAML policy decision and a signed receipt. Your code keeps the credentials; Provenex never holds OAuth tokens, never proxies traffic, never sits on the response-data path.

### Read this if you are...

| You are | Jump to |
| --- | --- |
| **VP of Engineering** evaluating whether to add this to a roadmap | [Where Provenex fits in your stack](#where-provenex-fits-in-your-stack) |
| **Security Architect** wanting to greenlight procurement | [Built for security architects](#built-for-security-architects) |
| **Compliance Lead** asking what evidence ends up on the receipt | [What you declare. What you get back.](#what-you-declare-what-you-get-back) |
| **Staff Engineer** writing the integration | [Easy integration](#easy-integration) |

## What you declare. What you get back.

A unified policy file gates retrieval (what the AI reads) and tool-call admission (what the AI is allowed to do, including MCP-shaped tool calls and the "can this agent access Jira / Salesforce / this connector" question) in one place.

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

# Tool-call admission rules
tool_call_control:
  rules:
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny

    # fnmatch is glob, not regex - one rule per pattern. The DSL
    # deliberately refuses regex; globs are auditable.
    - name: no_api_key_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*api_key=*"
      on_violation: deny
    - name: no_password_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*password=*"
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

One signed receipt per retrieval or per tool call. Retrieval receipts carry `sources[]` and `policy.access_control`; tool-call receipts carry `actions[]` and `policy.tool_call_control`; mixed agentic flows link both into one trajectory.

```json
{
  "receipt_id": "prx_f2de431dc125ccfc6b57e6ca327fa504",
  "schema_version": "2.4.0",
  "issuer": "provenex-core/0.9.0",
  "caller_hash": "sha256:7a2bf01571c43f...",
  "request_binding": {
    "algorithm": "sha256",
    "query_hash": "sha256:b7a1e09c...",
    "request_context_hash": "sha256:31d8e94c...",
    "request_hash": "sha256:c2f6a18d..."
  },
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
          "rules_fired": ["web_search_provider_allowlist", "no_api_key_in_query", "no_password_in_query"],
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
                  "session_id": "session-2026-001" },
  "signature": { "algorithm": "ed25519", "value": "fc5d40895ca2..." }
}
```

A chunk or action passes only if it clears both gates. The receipt records both verdicts per item so an auditor can reason about them independently, and the signature covers everything, including the `request_binding` that ties the receipt cryptographically to the triggering query. Full field reference: [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md).

## Where Provenex fits in your stack

```
Standard RAG:
  documents --> chunker --> embedder --> vector DB
                                              |
  user query --> embedder --> vector DB.search() --> retriever --> LLM --> answer


Same pipeline with Provenex:
  documents -+--> chunker --> embedder --> vector DB
             |
             +--> provenex.add(entry_kind=whole_chunk)   (parallel signed write)

  user query --> embedder --> vector DB.search() --> retriever ---+
       |                                                          v
       |                       +---------------------------------------+
       |                       |  policy.verification (5-outcome gate) |
       |                       |  policy.access_control (rule engine)  |
       |                       |  whole-chunk match only -> VERIFIED   |
       |                       |      BOTH must allow                  |
       |                       +-------------+-------------------------+
       |                                     v
       |                            surviving chunks --> LLM --> answer
       |                                     |
       +------- request_text -->  signed receipt + request_binding
                                  v
                       audit / compliance / SIEM
```

### The pieces

| Piece | What it does |
| --- | --- |
| **Provenex index** | Stores **cryptographic fingerprints** of every ingested chunk plus metadata: document ID, version, ingestion timestamp, authorization state, residency / classification / PII tags. Not the embeddings, not the chunk text. SHA-256 hashes and metadata only. Ships with **Postgres** for multi-node production and **SQLite** for single-node development; same `ProvenanceIndex` interface, identical canonical signing payload, receipts verify bit-identically across backends. |
| **Ingester** | At document-write time, alongside the code that writes embeddings to your vector DB, writes fingerprints to the Provenex index. Two writes, both committed before ingest is done. |
| **Policy evaluator** | At query time, after your retriever pulls chunks from the vector DB, re-fingerprints each chunk and runs it through both gates: verification (origin, freshness, tampering) and access-control (jurisdiction, classification, PII tags, freshness windows, caller role). The tool-call admission engine evaluates `actions[]` the same way. |
| **Receipt** | A signed JSON record of the whole transaction: chunks or actions, verification outcomes, the unified policy, per-item decisions, the rules that fired, a hash of the LLM output, the request binding, and a signature over the whole thing. |

### Where does your code change?

**Not in your vector DB.** Provenex doesn't talk to Pinecone, Weaviate, Milvus, or any vector store directly. There's no plugin to install, no schema migration. Your vector DB stays exactly as it is.

The integration lives in your **application code**, the same RAG glue layer that already calls your vector DB. Two spots:

1. **In your ingest pipeline.** Wherever your code writes chunks into the vector DB, add a parallel call to `provenex.add(...)` for each chunk.
2. **In your retrieval path.** Wherever you get chunks back from the vector DB and hand them to the LLM, run them through `provenex.verify_chunks(..., policy=Policy.from_yaml("hr_policy.yaml"), request_context=...)` first.

For agent tool calls, wrap any LangChain tool with `ProvenexToolWrapper` or decorate an MCP `tools/call` handler with `provenex_mcp_admission`. For framework-agnostic code, call `admission_check(...)` directly.

## Easy integration

### Production (Postgres, multi-node)

```python
from provenex import (
    verify_chunks, Policy, RequestContext,
    Ed25519Signer, PostgresProvenanceIndex,
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
    signer=Ed25519Signer.from_private_key_file("audit-signing.pem"),
    policy=policy, request_context=request,
    request_text=query,           # binds the receipt to this specific query
    chunk_metadata=[doc.metadata for doc in retrieved_documents],
)
feed_to_llm(result.kept)            # only chunks that cleared BOTH gates
save_receipt(result.receipt)        # signed, verifiable offline by anyone
                                    # with the public key
```

The OSS core ships both `HmacSha256Signer` (symmetric, fast, for internal-only producers and verifiers) and `Ed25519Signer` (asymmetric, the right default for any receipt that may be handed to a regulator or external auditor). Both implement the same `ReceiptSigner` interface; receipts are structurally identical. Pick HMAC if simplicity matters more than non-forgeability by the verifier; pick Ed25519 the moment a receipt crosses an org boundary. See [`docs/threat_model.md`](https://github.com/provenex/provenex-core/blob/main/docs/threat_model.md) for the trust model.

Many verify pods plus one ingester pod is the recommended deployment shape. Verify scales horizontally via Postgres read replicas; multi-writer ingest into the same index is supported and serialized at the document-row level. Bring your own Postgres (RDS, Aurora, Cloud SQL, Crunchy, Supabase, or self-managed). See [`docs/scaling.md`](https://github.com/provenex/provenex-core/blob/main/docs/scaling.md) for topology recommendations and benchmark numbers.

> **Default for `block_unverified` is `False`.** Chunks whose fingerprint isn't in the Provenex index (`UNVERIFIED` outcome) pass through to the LLM by default; the receipt records the outcome, but the chunk is not removed. For strict enforcement set `block_unverified=True` in your `VerificationPolicy`. The default will flip to `True` in a future major release; the current default emits a `DeprecationWarning` so the choice is visible.

### Development (SQLite, single-node)

```python
from provenex import SQLiteProvenanceIndex
index = SQLiteProvenanceIndex("provenance.db")
# ... rest is identical to the Postgres example
```

Stdlib-only, no service to stand up. Same interface, same canonical signing payload, same receipt format. A receipt produced against SQLite verifies bit-identically against Postgres and vice versa.

Your existing vector store is untouched. Provenex runs alongside as a parallel signed index plus a policy gate. **Pinecone, Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector, MongoDB Atlas Vector Search, Elasticsearch with vectors, Vespa, or a Postgres table you wrote yourself**: Provenex doesn't know and doesn't care.

### Tool-call admission

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
save_receipt(result.receipt)             # signed, verifiable offline; denies too
```

**Decision and proof, not execution.** Provenex returns a decision and emits a signed receipt; the caller makes the actual call against the target system using its own credentials. Use [`ProvenexToolWrapper`](https://github.com/provenex/provenex-core/blob/main/provenex/tool_call/integrations/langchain.py) to wrap any LangChain tool; the MCP integration is its own subsection below.

### MCP (Model Context Protocol)

```python
from provenex.tool_call.integrations.mcp import provenex_mcp_admission

@provenex_mcp_admission(
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=Ed25519Signer.from_private_key_file("audit-signing.pem"),
    request_factory=lambda req: RequestContext(
        caller=read_caller_from_session(req["params"]),   # your auth glue
        jurisdiction="US",
        purpose="tool_call",
        timestamp=req["params"].get("timestamp"),
    ),
)
def tools_call(request: dict) -> dict:
    # Your existing JSON-RPC tools/call handler body is untouched.
    return invoke_tool(request["params"])
```

One decorator, zero changes to the handler body. Every call passes through admission first: allow runs the handler normally; deny raises `ToolCallDenied` (or emits a structured JSON-RPC error via the `on_deny` callback, code [`-32099`](https://github.com/provenex/provenex-core/blob/main/provenex/tool_call/integrations/mcp.py)). **Every allow and every deny produces a signed receipt** under `trajectory.step_kind="tool_call"`.

The integration imports nothing from any MCP SDK. The intercept shape works with the official Python MCP SDK, with any other Python MCP implementation, and with a hand-rolled JSON-RPC handler. The receipt format is identical to what the LangChain wrapper emits; one policy DSL covers both.

- **Runnable demo**: [`examples/mcp_admission_demo.py`](https://github.com/provenex/provenex-core/blob/main/examples/mcp_admission_demo.py) - toy MCP handler before-and-after, three live `tools/call` requests showing allow + deny, the on-deny callback pattern, and signed-receipt drain.
- **Operational deep-dive**: [`docs/mcp_integration.md`](https://github.com/provenex/provenex-core/blob/main/docs/mcp_integration.md) - JSON-RPC error contract, router-level interception via `wrap_mcp_request`, the `RequestContext` factory pattern for session / JWT / mTLS identity, and the receipt fields an MCP-aware auditor reads.
- **Tests**: [`tests/test_tool_call_mcp.py`](https://github.com/provenex/provenex-core/blob/main/tests/test_tool_call_mcp.py).

### Memory reads, memory writes, and model inference

The same primitive covers every class of action an agent takes. Convenience entrypoints produce admission-shaped receipts under the right `trajectory.step_kind`:

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

# Memory read - same five outcomes apply to memory_store sources.
r1 = verify_memory(["last user message: ..."], index=index, signer=signer,
                   request_context=request)

# Memory write - verbatim value redacted by default; value_hash always recorded.
r2 = admit_memory_write(memory_key="user_profile", value={"prefers": "dark_mode"},
                        request=request, store_id="crewai_memory", signer=signer)

# Model inference - target_provider + prompt_hash on every receipt.
r3 = admit_model_inference(model_name="claude-opus-4-7",
                           prompt="Summarize TICKET-001",
                           request=request, target_provider="anthropic",
                           extra_parameters={"max_tokens": 4000}, signer=signer)
```

All five step kinds (`retrieval`, `tool_call`, `memory_read`, `memory_write`, `model_inference`) reuse the existing receipt schema, gate against the unified YAML policy the same way, and link into the same trajectory DAG. One CLI invocation (`provenex audit --trajectory <dir>`) validates the whole agent run end-to-end.

### Framework integrations

| Framework | Retrieval | Tool calls |
| --- | --- | --- |
| **LangChain** | `ProvenexRetriever` wraps any retriever. | `ProvenexToolWrapper` wraps any LangChain tool. |
| **LangGraph** | `provenex_retrieval_node(...)` factory + state helpers. | Call `admission_check(...)` from a graph node. |
| **CrewAI** | `ProvenexCrewSession.wrap_tool(tool)`; `session.verify_chunks(...)`. | `session.wrap_tool_admission(...)` runs admission before the tool fires. |
| **LlamaIndex** | `ProvenexRetriever` middleware (same pattern as LangChain). | Use framework-agnostic `admission_check(...)`. |
| **MCP** | n/a (retrieval is upstream of MCP) | `provenex_mcp_admission(...)` decorator on a `tools/call` handler. |
| **Anything else** | `provenex.verify_chunks(...)` | `provenex.admission_check(...)` |

### Streaming receipts to a SIEM

Every receipt-emitting entrypoint accepts an optional `sink=`. Provenex publishes after the receipt is finalised; the hot path is unchanged.

```python
from provenex import MultiSink, FileJSONLSink
from provenex.export.kafka import KafkaSink   # extra: [export-kafka]
from provenex.export.aws import S3AppendSink  # extra: [export-aws]

sink = MultiSink([
    KafkaSink(bootstrap_servers="kafka.internal:9092", topic="provenex-receipts"),
    S3AppendSink(bucket="audit-archive", prefix="provenex"),
    FileJSONLSink("/var/log/provenex"),
])
result = admission_check(..., sink=sink)   # the only line that changes
```

Sink failures are swallowed and logged via `warnings.warn`. Provenex never breaks the agent's hot path because export is degraded. Receipts also map to **OCSF v1.3** events for cross-vendor SIEM compatibility via `receipt_to_ocsf(...)` and `OCSFAdapter`. Full reference: [`docs/streaming_export.md`](https://github.com/provenex/provenex-core/blob/main/docs/streaming_export.md) and [`docs/ocsf_mapping.md`](https://github.com/provenex/provenex-core/blob/main/docs/ocsf_mapping.md).

## What this looks like for a buyer

[`examples/attack_thwarted_demo.py`](https://github.com/provenex/provenex-core/blob/main/examples/attack_thwarted_demo.py) is the in-repo headline demo. It runs end-to-end with real LangChain (`InMemoryVectorStore` + `@tool`, no mocks) and walks four common attack shapes:

1. **Unauthorized tool call.** A viewer-role insider tries `jira.delete_issue` and the wrapped tool denies before the underlying function runs.
2. **Poisoned RAG.** Two variants land in the vector store, a never-indexed chunk and a window-aligned splice of an authorized doc, and both return `UNVERIFIED`.
3. **Audit replay.** An attacker tries to re-present a valid signed receipt as evidence for a different regulator query, and `request_binding` catches the replay.
4. **Insider misuse.** A low-privilege insider attempts a restricted memory write and a secret-in-prompt model call; both denied via the policy.

The demo prints the **regulator's seven questions** at the start, runs the four acts, then prints the seven questions again with the specific receipt field that proves each one. Run it:

```bash
pip install langchain-core numpy
export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export PROVENEX_RECEIPT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python examples/attack_thwarted_demo.py --fast
```

Three denies + 3 UNVERIFIED + 1 forged signature, every attempt captured on a signed audit anchor the regulator can re-verify offline.

## Built for security architects

The core is small on purpose: pure-stdlib Python, HMAC-SHA256 default, optional Ed25519 for cross-org receipts, optional Postgres for multi-node deployments. A reviewer can read every load-bearing function in one sitting.

The five verification outcomes (`VERIFIED / STALE / UNAUTHORIZED / UNVERIFIED / TAMPERED`) are the discrete cryptographic states. They are not graded scores. The receipt records the verification outcome and the policy decision independently for every item, so an auditor can reason about them separately. The fixed precedence (`TAMPERED > UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED`) is codified as `OUTCOME_PRECEDENCE` in code so callers reason about it the same way the engine does.

The receipt commits cryptographically to the request that produced it. The top-level `request_binding` block hashes the triggering query and the canonical request context into the signed payload, so a valid receipt cannot be presented as evidence for a different query. The verbatim query is never recorded; only its hash.

The optional Merkle transparency log (`MerkleSQLiteProvenanceIndex`) layers an RFC 6962 tree over the same HMAC-signed rows so insertion or removal of rows by a key-holder is detectable by anyone holding a previous tree head. The OSS `WitnessLog` is the hash-chained, signed checkpoint log operators publish to a store they cannot retroactively edit, closing split-view resistance against a key-holding operator.

For dive-deep reading:

- [`docs/architecture.md`](https://github.com/provenex/provenex-core/blob/main/docs/architecture.md): the entry point. Points at every other doc and the source map.
- [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md): the algorithm end-to-end. Normalization, Rabin-Karp recurrence over Mersenne prime `2^61 - 1`, sliding-window construction, `entry_kind` promotion rule, Merkle leaf hash `SHA256(0x00 || leaf)`, canonical signing payload, peppered fingerprint mode.
- [`docs/threat_model.md`](https://github.com/provenex/provenex-core/blob/main/docs/threat_model.md): attacker model, defended and undefended threats, the witness log for split-view resistance.
- [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md): the receipt schema 2.4.0 wire spec and the full schema-history table.
- [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md): the YAML DSL, supported operators, worked examples, and the per-decision purity rationale (why the DSL refuses trajectory-level rules, cross-decision aggregation, and external-data lookups).
- [`docs/scaling.md`](https://github.com/provenex/provenex-core/blob/main/docs/scaling.md): Postgres topology, 1M-chunk benchmark numbers, policy-evaluation latency profile.
- [`docs/anomaly_detection.md`](https://github.com/provenex/provenex-core/blob/main/docs/anomaly_detection.md): how receipts compose with downstream UEBA / SIEM. Provenex is the firewall, your detector is the SIEM. Five worked detection patterns.

### Conformance

`provenex selftest` runs an in-process set of checks that re-derive every property the docs claim against the installed binary. Exits 0 on every check passing; 1 on any failure. Suitable for CI and pre-deploy gates on a signing key rotation or a corpus migration.

```bash
provenex selftest
```

### Why open source?

Security teams won't trust a black box. If a regulator asks how your access-policy enforcement system works, "it's proprietary" is not an answer. The whole algorithm needs to be auditable end to end: normalization, rolling hash, sliding window, SHA-256 strengthening, policy evaluator semantics, receipt schema, signature payload. So it is.

## Open source vs commercial

The interfaces (`ProvenanceIndex`, `PolicyEvaluator`, `ReceiptSigner`, `BloomFilterIndex`) are the same across OSS and commercial. Moving between them is one line of code: the class you instantiate.

| Layer | Open source (this repo, MIT) | Commercial ([provenex.ai](https://provenex.ai)) |
| --- | --- | --- |
| **Fingerprinting engine** | Normalizer, Rabin-Karp, SHA-256 strengthening, peppered mode | High-throughput Bloom-filter acceleration for 10M+ chunk scale |
| **Provenance index** | Postgres (multi-node production, sync + async API) and SQLite (single-node), HMAC-signed rows, optional RFC 6962 Merkle transparency log, batched `verify_batch` | Hosted index with distributed signed append-only storage, transparency-log-backed policy bundle records |
| **Policy evaluator** | Unified policy with `verification` + `access_control` + `tool_call_control` halves, native YAML DSL, **`provenex policy simulate`** for SR-11-7 / Model Risk replay | **Rego adapter** (load Rego bundles into the same `PolicyEvaluator` protocol), **OPA service adapter** (delegate decisions to a running OPA instance) |
| **Receipts** | HMAC + Ed25519 signing, request binding, trajectory DAG, self-attribution claims, content-source classifier, witness / checkpoint log, **KMS / HSM signer adapters (AWS, GCP, Azure, PKCS#11)**, **multi-tenant signer registry** | Compliance-grade exports (PDF, CSV, JSON-LD), managed HSM hosting, inference attribution and temporal decay scoring |
| **Server / deployment** | **`provenex-server`** FastAPI app (`pip install "provenex-core[server]"`), **Helm chart + raw manifests**, **Policy CRD + operator**, **Dockerfile.server** | Managed control plane, multi-region failover, vendor-managed upgrades |
| **Integrations** | LangChain, LangGraph, LlamaIndex, CrewAI, MCP, framework-agnostic SDK, **JWT → RequestContext recipe** (Okta + Azure AD examples) | Identity-provider integration suite, enterprise SSO / RBAC |
| **Observability** | `ReceiptSink` Protocol, stdlib sinks, OCSF v1.3 mapping (`receipt_to_ocsf` + `OCSFAdapter`), Kafka / SQS / S3 / PubSub sinks behind extras, **`/metrics` Prometheus endpoint**, **drift webhook detector**, **Splunk app + Sentinel KQL pack** | Dedicated support, SLA |
| **Compliance** | **Receipt-retention Terraform module** (S3 Object Lock + Glacier + Athena, 7-year), 5 runbooks under `docs/runbooks/` | Vendor-managed retention service, regulator-facing audit portal |
| **CLI** | `provenex ingest / verify / receipt / audit / policy / selftest / index audit` | |

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
pip install "provenex-core[server]"        # + FastAPI HTTP server (Patterns B/C)
pip install "provenex-core[operator]"      # + Policy CRD operator (kopf + k8s client)
pip install "provenex-core[kms-aws]"       # + AWS KMS signer adapter
pip install "provenex-core[kms-gcp]"       # + GCP KMS signer adapter
pip install "provenex-core[kms-azure]"     # + Azure Key Vault signer adapter
pip install "provenex-core[pkcs11]"        # + PKCS#11 HSM signer adapter
pip install "provenex-core[identity]"      # + JWT -> RequestContext recipe (PyJWT)
```

Python 3.10+. The core has zero third-party dependencies; it's pure stdlib. The Postgres backend, framework integrations, the native YAML DSL, and the Ed25519 signer are optional extras.

### Try it in 30 seconds

```bash
pip install "provenex-core[policy]"
git clone https://github.com/provenex/provenex-core.git
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python provenex-core/examples/standalone_demo.py
```

For the integration-pattern story (a poisoned chunk added directly to the vector store, bypassing Provenex ingest, gets caught and blocked at the retrieval boundary), run [`examples/rag_with_provenance.py`](https://github.com/provenex/provenex-core/blob/main/examples/rag_with_provenance.py). For the tool-call admission tour, run [`examples/agentic_admission_demo.py`](https://github.com/provenex/provenex-core/blob/main/examples/agentic_admission_demo.py). For the four-attack regulator demo, see [What this looks like for a buyer](#what-this-looks-like-for-a-buyer).

## CLI

```bash
provenex ingest  --index prov.db --doc-id policy_v4 policy.txt
provenex verify  --index prov.db retrieved_chunk.txt
provenex receipt --index prov.db --output llm_output.txt chunk1.txt chunk2.txt
provenex audit   receipt.json
provenex audit   receipt.json --show-policy          # render the unified policy block
provenex audit   --trajectory ./receipts/            # validate a whole agentic trajectory (mixed step kinds)
provenex policy  validate hr_policy.yaml             # parse + validate a policy file
provenex policy  hash     hr_policy.yaml             # print canonical policy_version_hash(es)
provenex index   audit --index prov.db --threshold-days 180   # supersession lint
provenex selftest                                              # conformance check
```

`provenex policy validate` is the CI-time check for policy files. `provenex policy hash` prints the canonical `policy_version_hash` that will appear on every receipt produced under that policy. `provenex index audit` is the cron-style check that catches a re-ingest path that skipped Provenex (and would otherwise leave stale chunks marked VERIFIED). `provenex selftest` is the one-command conformance check security teams ask for. For receipts signed with Ed25519, pass `--public-key audit.pub` to verify with only the public key.

## Privacy and data sovereignty

The index stores fingerprints (one-way SHA-256 hashes) and metadata. **No document content, no PII, no chunk text is ever written.** Anyone with the index can verify retrieval, but no one can recover document content from it. The `policy.access_control.decisions[].inputs` field on the receipt records the metadata the evaluator looked at (residency tags, classification, caller role); operators who want to redact those can set `inputs: null` while keeping the `inputs_hash` for offline verification.

## License

MIT. See [LICENSE](https://github.com/provenex/provenex-core/blob/main/LICENSE).

## Links

**Reading:**

- [Five Things People Mean by "AI Provenance" (And Which One Is For You)](https://provenex.ai/blog/five-things-ai-provenance): the category map, and where Provenex sits
- [`docs/architecture.md`](https://github.com/provenex/provenex-core/blob/main/docs/architecture.md): the technical documentation entry point and source map
- [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md): unified policy reference (verification + access control + tool-call admission), DSL, worked examples, commercial roadmap
- [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md): full algorithm, threat model, and architectural comparison to embedding-based systems
- [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md): receipt schema 2.4.0 specification (current); full version history table inside
- [`docs/quickstart.md`](https://github.com/provenex/provenex-core/blob/main/docs/quickstart.md): 5-minute getting-started, including a policy-driven retrieval path
- [`docs/threat_model.md`](https://github.com/provenex/provenex-core/blob/main/docs/threat_model.md): attacker model, defended/undefended threats, trust model for policy decisions
- [`docs/scaling.md`](https://github.com/provenex/provenex-core/blob/main/docs/scaling.md): 1M-chunk benchmark numbers and policy-evaluation latency profile

**Project:**

- Homepage: [provenex.ai](https://provenex.ai)
- Issues and discussion: GitHub Issues on this repo
- Security: found something? See [SECURITY.md](https://github.com/provenex/provenex-core/blob/main/SECURITY.md). We acknowledge reports within 2 business days; safe-harbor language and an age public key for encrypted reports are in there.
- Commercial features: contact@provenex.ai
