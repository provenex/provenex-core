# Release notes — v0.6.5

**Headline.** Every class of agent action — read corpus, read memory, write memory, call a model, call a tool — now produces a signed receipt under the right `step_kind` classifier. Three new convenience entrypoints close the source-of-record loop; `caller_hash` gets an opt-in per-deployment salt; Postgres backend hardens against non-UTF8 clusters. No schema bump — the wire format stays at 2.3.0.

## What's new since 0.6.4

### Step-kind coverage — every action class becomes a first-class receipt

- **`provenex.verify_memory(memory_chunks, index, ...)`** — convenience wrapper over `verify_chunks` that sets `step_kind="memory_read"` on the trajectory and `content_source="memory_store"` on every source record. The same five verification outcomes (`VERIFIED` / `STALE` / `UNAUTHORIZED` / `UNVERIFIED` / `TAMPERED`) apply. Use it when an agent reads from a memory store you've also indexed via Provenex (CrewAI memory, LangGraph state, custom store).

- **`provenex.admit_memory_write(memory_key, value, request, ...)`** — admission-shaped convenience. Builds a `ToolCallContext` with `name="memory.write"` and `operation=<memory_key>` (so the key is the policy-rule axis), runs `admission_check(..., step_kind="memory_write")`. **Verbatim value redacted by default** (`redact_value=True`); `value_hash` always recorded. Detectors group by `caller_hash + tool.name="memory.write" + tool.operation=<key>` for per-key write-rate baselines.

- **`provenex.admit_model_inference(model_name, prompt, request, ...)`** — admission-shaped convenience for LLM calls. Builds a `ToolCallContext` with `name=<model_name>`, `operation="complete"` (or `"stream"`, `"embed"`, `"chat"`), `target_system=<provider>`, runs `admission_check(..., step_kind="model_inference")`. **Verbatim prompt redacted by default** (`redact_prompt=True`); `prompt_hash` always recorded. Enables anomaly patterns like "this caller is calling claude-opus 100x baseline" or "this caller is using a non-allowlisted provider".

- **`provenex.compute_value_hash(value)`** — public canonicalization-and-SHA-256 helper used by both convenience entrypoints. Strings/bytes hash directly; dicts/lists hash via canonical JSON (same `sort_keys=True, separators=(",", ":"), ensure_ascii=False` rule used elsewhere in the receipt). Always returns `"sha256:<hex>"`. A downstream consumer with the verbatim value can independently re-derive the hash.

- **`model_inference` added to the recognized `trajectory.step_kind` values** in `docs/receipt_format.md`. Joins `retrieval`, `tool_call`, `memory_read`, `memory_write`, `compilation`.

### Per-deployment unlinkability for `caller_hash`

- **`caller_hash_salt`** kwarg now flows through `verify_chunks`, `admission_check`, `verify_memory`, `admit_memory_write`, `admit_model_inference`. When supplied, `caller_hash` switches from bare SHA-256 (`"sha256:<hex>"`) to HMAC-SHA256 keyed by the salt (`"hmac-sha256:<hex>"`). Same canonical-JSON payload, different deployment-keyed digest. Two multi-tenant deployments using different salts produce different `caller_hash` values for the same caller — useful when you don't want third-party detectors to cross-correlate users across tenants. **Opt-in; no default behavior change.** A deployment that doesn't pass a salt sees the exact 0.6.4 bare-SHA-256 output.

- **`compute_caller_hash(caller, salt=...)`** updated to accept the optional salt. The prefix on the returned string is the algorithm identifier — consumers dispatch on it the same way they do for `signature.algorithm`.

### Postgres backend hardening

- `PostgresProvenanceIndex` now forces `client_encoding=UTF8` on every new connection via a pool `configure` callback. On a `SQL_ASCII` cluster (macOS `initdb` default), psycopg3 returns text columns as bytes instead of str — the canonical-payload HMAC then blows up at sign time. The defensive `SET` is a no-op on a UTF8 cluster and load-bearing on any non-UTF8 cluster. No backward-compat concerns: every existing UTF8 production deployment behaves identically.

### Comprehensive doc + example sweep

- `README.md`: new "Memory reads, memory writes, and model-inference" section under tool-call admission; OSS feature list updated; agentic-flows narrative now lists all five step kinds as first-class.
- `docs/quickstart.md`: new Path H ("Memory reads, memory writes, and model-inference").
- `docs/policy.md`: new Example 4 — memory.write + model_inference DSL rules; path-roots table extended to surface that the same `tool.*` paths cover the new step kinds.
- `docs/receipt_format.md`: `model_inference` added to recognized `step_kind` values; `caller_hash` section documents the two modes (bare SHA-256 vs salted HMAC-SHA256); issuer example bumped.
- New example: `examples/memory_and_model_inference_demo.py` — runnable end-to-end, three signed receipts under one trajectory, mixed step kinds, audit passes, out-of-band hash re-derivation demonstrated.

## Compatibility

- **No schema bump.** Wire format stays at `2.3.0`. Every 0.6.5 entrypoint produces a receipt indistinguishable from a hand-built `admission_check` / `verify_chunks` call — these are convenience wrappers, not new shapes.
- **Backward compatible across the board.** Existing `verify_chunks` and `admission_check` callers see no behavior change (new kwargs default to None / False); existing 0.6.4 demos run unchanged against 0.6.5.
- **Postgres encoding hardening is additive** — a UTF8 cluster gets one extra `SET` per connection (microseconds). A non-UTF8 cluster that previously crashed now works correctly.
- **Salting is opt-in.** A deployment that doesn't supply `caller_hash_salt` produces the exact `"sha256:<hex>"` output of 0.6.4. Salting changes the prefix to `"hmac-sha256:<hex>"`; downstream consumers dispatch on the prefix.

## Example

```python
from provenex import (
    HmacSha256Signer, RequestContext, SQLiteProvenanceIndex,
    admit_memory_write, admit_model_inference, start_trajectory,
    verify_memory,
)

index = SQLiteProvenanceIndex("memory.db")
signer = HmacSha256Signer()
trj = start_trajectory(agent_id="incident_agent",
                       session_id="incident-2026-05-14-001")
request = RequestContext(
    caller={"id": "u_42", "role": "engineer"}, jurisdiction="US",
    purpose="incident_response", timestamp="2026-05-14T11:30:00Z",
    session_id="incident-2026-05-14-001",
)

# Memory read — step_kind="memory_read", content_source="memory_store"
r1 = verify_memory(["last message: where is the runbook?"],
                   index=index, signer=signer, request_context=request,
                   trajectory=trj)

# Memory write — admission-shaped; value_hash recorded, value redacted
r2 = admit_memory_write(
    memory_key="user_profile",
    value={"prefers": "dark_mode"},
    request=request, store_id="crewai_memory",
    signer=signer, trajectory=r1.next_trajectory,
)

# Model inference — admission-shaped; prompt_hash recorded, prompt redacted
r3 = admit_model_inference(
    model_name="claude-opus-4-7",
    prompt=[{"role": "user", "content": "Summarize INC-2026-05-001"}],
    request=request, target_provider="anthropic",
    extra_parameters={"max_tokens": 4000, "temperature": 0.2},
    signer=signer, trajectory=r2.next_trajectory,
)

# Per-deployment unlinkability — same caller, different deployment salts
# produce different caller_hash values.
r4 = admit_model_inference(
    model_name="claude-opus-4-7", prompt="...", request=request,
    target_provider="anthropic", signer=signer,
    caller_hash_salt=b"deployment-acme-corp-secret",
)
# r4.receipt.caller_hash → "hmac-sha256:..." (was "sha256:..." without the salt)
```

## Install

```bash
pip install provenex-core==0.6.5
pip install "provenex-core[policy]==0.6.5"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[postgres]==0.6.5"      # Postgres backend (UTF8-hardened)
pip install "provenex-core[langgraph]==0.6.5"     # LangGraph nodes
pip install "provenex-core[crewai]==0.6.5"        # CrewAI session + admission
pip install "provenex-core[langchain]==0.6.5"     # LangChain retriever + admission wrapper
pip install "provenex-core[ed25519]==0.6.5"       # asymmetric receipt signing
```
