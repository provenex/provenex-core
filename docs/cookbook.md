# Cookbook

Twenty recipes for common Provenex tasks. Each recipe is a short snippet plus a paragraph explaining the relevant parameters. Runnable end-to-end versions for most recipes are in [examples/](../examples/).

The recipes assume you already have a signing key in `PROVENEX_RECEIPT_SECRET` (or pass `signer=` explicitly) and a provenance index pointed at the right backend. See [quickstart.md](quickstart.md) for the setup walkthrough.

## Retrieval

### 1. Verify a chunk with custom metadata

Provenex's `chunk_metadata` is a flat dict per chunk. The keys are whatever your upstream PII / classification / residency tooling sets; the policy DSL reads them via `chunk.metadata.<key>`.

```python
from provenex import verify_chunks, Policy, RequestContext, HmacSha256Signer

result = verify_chunks(
    chunks=[doc.page_content for doc in retrieved_documents],
    index=index, signer=HmacSha256Signer(),
    policy=Policy.from_yaml("hr_policy.yaml"),
    request_context=RequestContext(
        caller={"role": "hr_admin"}, jurisdiction="EU",
        purpose="customer_support", timestamp="2026-05-13T14:32:07Z",
    ),
    chunk_metadata=[
        {"residency": "EU", "contains_pii": True, "classification": "internal"},
        {"residency": "US", "contains_pii": False, "classification": "public"},
    ],
)
```

Each entry in `chunk_metadata` corresponds positionally to the chunk at the same index in `chunks`. The metadata lands on `policy.access_control.decisions[i].inputs.chunk_metadata` on the receipt; the policy rules read it under `chunk.metadata.<key>`. Add `chunk_metadata_binding="at_ingest"` if the tags are signed alongside the fingerprint in your ingest pipeline; the default is `"at_evaluate"` for safety. See [threat_model.md § Trust model for policy decisions](threat_model.md#trust-model-for-policy-decisions).

### 2. Verify a receipt across backends (SQLite to Postgres)

A receipt produced against `SQLiteProvenanceIndex` verifies identically against `PostgresProvenanceIndex` and vice versa. The canonical signing payload and the row HMAC are backend-agnostic.

```python
from provenex import PostgresProvenanceIndex, HmacSha256Signer
from provenex.core.receipt import verify_receipt_signature
import json

index = PostgresProvenanceIndex(dsn="postgresql://...")  # production
receipt = json.loads(open("receipt-from-sqlite-dev.json").read())
assert verify_receipt_signature(receipt, HmacSha256Signer())  # passes
```

Useful for development workflows where you build with SQLite locally and ship to Postgres in production. A receipt cached from a dev run continues to verify after the index migrates. The signature check is independent of the index entirely; it only needs the receipt JSON and the matching signer.

### 3. Skip binary attachments in a mixed corpus

Provenex fingerprints text. A corpus with binary attachments (PDFs, images) should extract the text first and fingerprint only the extracted text; the binary itself stays in your document store untouched.

```python
import pathlib
from provenex import Fingerprinter
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.index.base import ENTRY_KIND_WHOLE_CHUNK

index = SQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()

for path in pathlib.Path("./corpus").rglob("*"):
    if path.suffix.lower() in {".pdf", ".png", ".jpg", ".docx"}:
        text = extract_text_from_binary(path)  # your extractor
    elif path.suffix.lower() in {".txt", ".md", ".html"}:
        text = path.read_text(encoding="utf-8")
    else:
        continue  # skip unknown binary; do not fingerprint
    result = fp.fingerprint(text)
    whole_fp = fp.fingerprint_chunk(text)
    index.add(fingerprint=whole_fp, document_id=str(path), document_version=result.document_version,
              chunk_offset=0, chunk_length=len(text), authorized=True,
              entry_kind=ENTRY_KIND_WHOLE_CHUNK)
```

The decision of which binary types to extract is yours; Provenex never sees the original bytes. Use the same extraction at retrieval time so the chunk text re-fingerprints identically.

### 4. Wrap a custom LangChain retriever

`ProvenexRetriever` wraps anything that exposes `.get_relevant_documents(query)` or `.invoke(query)`. Your custom retriever does not need to subclass LangChain's base class.

```python
from langchain_core.documents import Document
from provenex.integrations.langchain import ProvenexRetriever
from provenex.index.sqlite_index import SQLiteProvenanceIndex

class MyRetriever:
    def get_relevant_documents(self, query: str) -> list[Document]:
        # your retrieval logic
        return [Document(page_content="...", metadata={"residency": "EU"})]

provenex_wrapped = ProvenexRetriever(
    base_retriever=MyRetriever(),
    index=SQLiteProvenanceIndex("provenance.db"),
)
result = provenex_wrapped.get_relevant_documents_with_receipt(
    query="What is the encryption policy?",
)
```

The wrapper duck-types against the retriever; no inheritance needed. `result.documents` are the chunks that survived policy filtering; `result.blocked` are the ones removed; `result.receipt` is the signed audit record. See [examples/basic_langchain_rag.py](../examples/basic_langchain_rag.py) for a full runnable version.

### 5. Switch from SQLite to Postgres

The `ProvenanceIndex` interface is identical across backends. Migration is one line.

```python
# Development
from provenex import SQLiteProvenanceIndex
index = SQLiteProvenanceIndex("provenance.db")

# Production
from provenex import PostgresProvenanceIndex
index = PostgresProvenanceIndex(dsn="postgresql://provenex:secret@db.internal:5432/provenex")
```

Everything downstream is unchanged: `verify_chunks(..., index=index, ...)` does not care which backend. Receipts produced under SQLite verify identically against Postgres for the same content. The HMAC signing key is the same secret stored in your secrets manager. See [runbooks/postgres_operations.md](runbooks/postgres_operations.md) for production deployment.

## Policy

### 6. EU-strict, non-EU-permissive policy

Different jurisdictions get different rules. The `when` clause filters the rule's scope; per-jurisdiction logic comes from multiple rules, not a conditional inside one rule.

```yaml
version: 1
policy_id: jurisdiction-tiered-v1

verification:
  block_unauthorized: true
  block_tampered: true
  block_unverified: false  # non-EU may see UNVERIFIED chunks

access_control:
  rules:
    - name: eu_strict_whole_chunk_only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency: { in: [EU, EEA] }
      on_violation: deny
    - name: non_eu_permissive
      when:
        request.jurisdiction: { in: [US, UK, APAC] }
      require:
        chunk.metadata.classification: { in: [public, internal, confidential] }
      on_violation: deny
  defaults:
    unknown_metadata: deny
```

The `eu_strict_whole_chunk_only` rule fires only when the request is from the EU; the `non_eu_permissive` rule fires for other jurisdictions. A request from outside both jurisdictions hits the `unknown_metadata: deny` default. Validate this with `provenex policy validate jurisdiction-tiered-v1.yaml` in CI.

### 7. Validate a policy in CI

Catch typos before deployment. Add to your CI pipeline:

```bash
provenex policy validate config/policies/*.yaml
echo "Exit $?"
```

Exit 0 on every file valid; exit 1 with a clear error on the first invalid one. The validator catches unknown top-level keys, unknown DSL operators, reserved-but-unimplemented features, and cross-domain references (a `tool_call_control` rule writing `chunk.*` or vice versa).

For a Python-based CI runner:

```python
from provenex.policy.yaml_evaluator import validate_policy_file

for path in glob.glob("config/policies/*.yaml"):
    ok, err = validate_policy_file(path)
    if not ok:
        raise SystemExit(f"{path}: {err}")
```

The validator is fast; running it on every commit is cheap.

### 8. Print the canonical policy hash

The `policy_version_hash` on every receipt is the SHA-256 of the canonical policy bundle. Two policies that differ only in formatting hash to the same value.

```bash
provenex policy hash hr_policy.yaml
# sha256:e10b1df5...

# For unified files with both halves:
provenex policy hash agent_policy.yaml
# access_control      sha256:e10b1df5...
# tool_call_control   sha256:d9fdce46...

# Filter to one half:
provenex policy hash agent_policy.yaml --section tool_call_control
# sha256:d9fdce46...
```

The hash printed here is exactly what appears on receipts produced under this policy. Cross-check before deploying.

### 9. Detect a policy file silently changed

Read the `policy_version_hash` off a known-good receipt; compare against the live policy hash. A mismatch means the policy file changed since that receipt was issued.

```python
import json, subprocess

receipt = json.loads(open("known_good_receipt.json").read())
recorded_hash = receipt["policy"]["access_control"]["policy_version_hash"]

current_hash = subprocess.check_output(
    ["provenex", "policy", "hash", "config/hr_policy.yaml", "--section", "access_control"]
).decode().strip()

if current_hash != recorded_hash:
    print(f"POLICY CHANGED: was {recorded_hash}, now {current_hash}")
```

Useful as a watchdog or a smoke check at deploy time. The hash is canonical so reformatting the policy YAML alone does not trigger a mismatch; only semantic changes do.

### 10. Different verification gates per environment

The `verification` half is a flat map of booleans; build it in code rather than YAML when it varies by environment.

```python
import os
from provenex import Policy, VerificationPolicy, NativeYamlEvaluator

is_prod = os.environ.get("DEPLOY_ENV") == "prod"

policy = Policy(
    verification=VerificationPolicy(
        block_unauthorized=True,
        block_tampered=True,
        block_unverified=is_prod,   # strict in prod, advisory in dev
        block_stale=is_prod,
    ),
    access_control=NativeYamlEvaluator.from_path("config/access_control.yaml"),
)
```

The access-control half stays in YAML where the rules live; the verification gate's strictness becomes an environment toggle. The receipt records the exact `verification` block in effect, so an auditor reading a prod receipt sees `block_unverified: true` even if the dev receipts at the same `policy_id` recorded `false`.

## Tool-call admission

### 11. Wrap a LangChain tool

`ProvenexToolWrapper` admission-checks every tool invocation. The wrapper is duck-typed against `.name` and `.invoke(input)`; any LangChain tool works.

```python
from provenex import HmacSha256Signer, Policy, RequestContext
from provenex.tool_call.integrations.langchain import ProvenexToolWrapper

wrapped_jira = ProvenexToolWrapper(
    base_tool=jira_create_tool,
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    request_factory=lambda invocation: RequestContext(
        caller=current_user.to_dict(), jurisdiction="US",
        purpose="incident_response", timestamp=invocation.timestamp,
    ),
)
agent.tools = [wrapped_jira, ...]  # rest of the agent unchanged
```

`request_factory` is your code: it receives the LangChain invocation object and returns the per-call `RequestContext`. Provenex never owns identity. Denials raise `ToolCallDenied`; the receipt is still emitted to the configured sink. See [examples/agentic_admission_demo.py](../examples/agentic_admission_demo.py).

### 12. Decorate an MCP tools/call handler

`provenex_mcp_admission` wraps any `tools/call` handler. The decorator runs admission before the handler body executes.

```python
from provenex import HmacSha256Signer, Policy
from provenex.tool_call.integrations.mcp import provenex_mcp_admission

@provenex_mcp_admission(
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    request_factory=build_request_context_from_mcp_request,
    on_deny=lambda result: {
        "jsonrpc": "2.0", "id": result.invocation_id,
        "error": {"code": -32099, "message": "tool call denied",
                  "data": {"receipt_id": result.receipt.receipt_id,
                           "rules_fired": result.rules_fired}},
    },
)
def handle_tools_call(request):
    return your_existing_tool_handler(request)
```

`on_deny` translates a Provenex deny into a JSON-RPC error response; without it, `ToolCallDenied` is raised. See [examples/mcp_admission_demo.py](../examples/mcp_admission_demo.py) for the full pattern.

### 13. Add admission to a LangGraph state machine

`provenex_admission_node` produces a LangGraph-compatible node that writes the decision into state for a conditional edge to route on.

```python
from provenex.integrations.langgraph import provenex_admission_node

admit_jira = provenex_admission_node(
    name="jira",
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    operation="create_issue",
    target_system="acme.atlassian.net",
    request_factory=lambda state: RequestContext(**state["request"]),
)

graph.add_node("admit_jira", admit_jira)
graph.add_node("execute_jira", _real_jira_node)
graph.add_node("denied_handler", _denied_node)
graph.add_conditional_edges(
    "admit_jira",
    lambda s: "execute_jira" if s["tool_admitted"] else "denied_handler",
)
```

The admission node never invokes the underlying tool; routing the actual call is the graph's job. See [examples/langgraph_admission_node_demo.py](../examples/langgraph_admission_node_demo.py).

### 14. Gate memory writes by key

Memory writes pass through the same `tool_call_control` rules; the memory key lands in `tool.operation`.

```yaml
tool_call_control:
  rules:
    - name: only_hr_writes_user_profile
      when:
        tool.name: memory.write
        tool.operation: user_profile
      require:
        request.caller.role: { in: [hr_admin, payroll] }
      on_violation: deny
    - name: cache_writes_require_short_ttl
      when:
        tool.name: memory.write
        tool.operation: cache
      require:
        tool.parameters.ttl:
          in: [60, 300, 3600]
      on_violation: deny
```

In the application code, `admit_memory_write(memory_key="user_profile", value=..., ...)` triggers the first rule; a non-HR caller is denied. The verbatim value is redacted by default (`redact_value=True`); `value_hash` is always recorded. See [policy.md § Example 4](policy.md#example-4---memory-writes-and-model-inference-gates-065).

## Trajectory and multi-step

### 15. Stamp session_id across a multi-trajectory session

`session_id` correlates receipts across multiple trajectories under one logical session (a chat conversation, an incident-response engagement). Set it once on the trajectory; it propagates through every receipt the cursor produces.

```python
from provenex import start_trajectory, RequestContext, verify_chunks, admission_check

trj = start_trajectory(
    agent_id="incident_agent",
    session_id="incident-2026-001",
)
request = RequestContext(..., session_id="incident-2026-001")

r1 = verify_chunks(..., request_context=request, trajectory=trj)
r2 = admission_check(..., request=request, trajectory=r1.next_trajectory)
r3 = verify_chunks(..., request_context=request, trajectory=r2.next_trajectory)

# Every receipt's `trajectory.session_id` is "incident-2026-001".
```

A downstream anomaly detector groups by `session_id` to reconstruct multi-step engagements without crawling per-decision inputs. See [anomaly_detection.md § Pattern 4](anomaly_detection.md#pattern-4-cross-trajectory-correlation-memory-write--external-tool-call).

### 16. Audit a multi-step agent run end-to-end

After a trajectory finishes, run one CLI pass over all the receipts to validate the DAG.

```bash
provenex audit --trajectory ./run_receipts/ --public-key audit.pub
```

The output shows per-receipt PASS / FAIL, the trajectory-level DAG checks (shared `trajectory_id`, acyclic parent links, no dangling parents), and an aggregate summary block (total chunks, total actions, per-step-kind breakdown, aggregate `PASS` / `PARTIAL` / `FAIL`).

Pair with `--json` for machine-readable output suitable for a CI gate:

```bash
provenex audit --trajectory ./run_receipts/ --public-key audit.pub --json | jq '.overall'
# "PASS"
```

### 17. Correlate memory writes with subsequent tool calls

Read the receipt stream as a downstream consumer. Detect a memory write followed within K seconds by an external tool call (a possible data-exfiltration sequence).

```python
import json
from pathlib import Path

receipts = sorted((json.loads(p.read_text()) for p in Path("./receipts").glob("*.json")),
                  key=lambda r: r["issued_at"])

for prev, curr in zip(receipts, receipts[1:]):
    prev_kind = prev.get("trajectory", {}).get("step_kind")
    curr_kind = curr.get("trajectory", {}).get("step_kind")
    if prev_kind == "memory_write" and curr_kind == "tool_call":
        if curr["caller_hash"] == prev["caller_hash"]:
            target = curr["actions"][0].get("target_system", "")
            if target.startswith("external"):
                print(f"ALERT: {prev['caller_hash']} memory.write -> {target}")
```

This is detection logic, not policy logic; it lives in your SIEM or detector, not in the Provenex DSL. See [policy.md § What the native DSL deliberately doesn't do](policy.md#what-the-native-dsl-deliberately-doesnt-do-and-why) for why.

## Operational

### 18. Stream receipts to multiple sinks with backpressure

Production deployments want at least two destinations: a real-time firehose plus a long-term archive. Wrap the network sinks in `RetryQueueSink` to absorb transient broker hiccups.

```python
from provenex import MultiSink, FileJSONLSink, RetryQueueSink
from provenex.export.kafka import KafkaSink
from provenex.export.aws import S3AppendSink

sink = MultiSink([
    RetryQueueSink(KafkaSink(bootstrap_servers="kafka:9092", topic="provenex"), maxlen=10_000),
    RetryQueueSink(S3AppendSink(bucket="audit-archive", prefix="provenex"), maxlen=10_000),
    FileJSONLSink("/var/log/provenex"),  # local file rarely fails
])

result = admission_check(..., sink=sink)
```

Sink failures are swallowed and logged via `warnings.warn` so the agent's hot path is never broken by export degradation. `RetryQueueSink` re-emits the queued receipts on the next successful publish. See [streaming_export.md](streaming_export.md).

### 19. Convert receipts to OCSF for the SIEM

The `OCSFAdapter` wraps any `ReceiptSink` and translates each receipt to one or more OCSF v1.3 events before forwarding.

```python
from provenex import MultiSink, FileJSONLSink, OCSFAdapter
from provenex.export.kafka import KafkaSink

sink = MultiSink([
    OCSFAdapter(
        downstream=KafkaSink(bootstrap_servers="kafka:9092", topic="ocsf-events"),
        extra_metadata={"organization_uid": "acme-corp", "environment": "prod"},
    ),
    FileJSONLSink("/var/log/provenex/raw"),  # raw receipts in parallel
])

admission_check(..., sink=sink)
```

The SIEM ingests OCSF directly; the raw archive supports the eventual signature-level audit. See [ocsf_mapping.md](ocsf_mapping.md) for the field-by-field mapping.

### 20. Detect an upstream re-ingest that skipped Provenex

The `provenex index audit` CLI surfaces the two failure modes the supersession contract guards against.

```bash
provenex index audit --index ./provenance.db --threshold-days 180
```

Output:

```
provenex index audit (threshold: documents not re-ingested in 180 days)
  index: ./provenance.db

Stale documents (2):
  policy_v4                                 last ingest: 2025-09-01T...
  product_terms_v3                          last ingest: 2025-10-15T...

Unsuperseded older versions (1):
  customer_contract_v7                      3 row(s) from a non-current version still flagged not-superseded
```

Wire into cron at a cadence matching your re-ingest discipline. Exit 0 on a clean run, 1 on any drift. See [runbooks/postgres_operations.md § Index audit](runbooks/postgres_operations.md#index-audit-provenex-index-audit) for the remediation procedure.

### 21. Verify the witness log's integrity

The `provenex chain verify` CLI confirms that the signed checkpoint log (`WitnessLog`) has not been retroactively rewritten by an operator who holds the signing key.

```bash
# Same-org HMAC verification (env-set secret).
export PROVENEX_RECEIPT_SECRET="<the secret the witness publisher signed with>"
provenex chain verify --log /var/provenex/witness.jsonl
```

Output on a clean log:

```
Witness log: /var/provenex/witness.jsonl
Algorithm:   hmac-sha256
Checkpoints: 1463

  Chain integrity ......... [OK]
    (signatures verify, previous_checkpoint_hash links match, checkpoint_index runs 0, 1, 2, ...)

  First checkpoint:  #0  tree_size=42
    2026-02-01T00:00:00.000Z
    sha256:...
  Latest checkpoint: #1462  tree_size=982147
    2026-05-22T07:00:00.000Z
    sha256:...

  Overall: PASS
```

For Ed25519-signed logs (recommended when handing the log to an external auditor), pass `--public-key witness.pub` instead of setting the env var. With `--index <db>`, the command additionally cross-checks the latest checkpoint's `tree_size` and `tree_root` against the live Merkle index, so an operator can confirm the published log matches current state. See [runbooks/witness_log.md](runbooks/witness_log.md) for the full publication procedure and threat model.

## Read next

- [examples/](../examples/): runnable end-to-end versions of most of the recipes above.
- [quickstart.md](quickstart.md): the setup walkthrough that the recipes assume.
- [policy.md](policy.md): the full DSL reference.
- [receipt_format.md](receipt_format.md): the wire schema for the receipts the recipes produce.
- [runbooks/](runbooks/): production operations for the patterns above.
