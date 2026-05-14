# Release notes — v0.6.0

**Headline.** Phase 2 of Provenex ships: policy enforcement and signed proof for agentic tool calls, on the same spine as Phase 1's retrieval enforcement. One unified policy file, one signed audit trail, one CLI audit pass covering mixed retrieval and tool-call decisions end to end.

## What's new since 0.5.0

- **Tool-call admission primitive.** New `provenex.tool_call` subpackage. `ToolCallContext`, `ToolCallPolicyEvaluator` Protocol, `NullToolCallPolicyEvaluator`, `NativeYamlToolCallEvaluator`, plus the framework-agnostic `provenex.admission_check(tool, request, policy=..., signer=...)` one-shot API and the `enforce_admission(...)` raise-on-deny convenience.
- **DSL extensions (additive).** New path roots for tool-call rules: `tool.name`, `tool.operation`, `tool.parameters.<key>`, `tool.target_system`, `tool.invocation_id`. New `require` operators: `matches_pattern` / `not_matches_pattern` (POSIX `fnmatch` globs — by design, not regex) and `length_at_most` (string-length cap). `when` clauses now also accept `{ in: [...] }` so CRUD-style multi-operation rules don't need duplicates. Cross-domain references (a `tool_call_control` rule writing `chunk.*`, or vice versa) fail at parse time.
- **Unified `Policy` carries three halves.** Adds `tool_call_control: Optional[ToolCallPolicyEvaluator]` alongside the existing `verification` and `access_control`. A unified YAML config file's new `tool_call_control:` subsection lights up the third half. `policy_version_hash` for each half is computed independently — modifying one section does not invalidate audits referencing the other.
- **Receipt schema 2.2.0 (additive).** Optional top-level `actions[]` array parallel to `sources[]`. Optional `policy.tool_call_control` subsection parallel to `policy.access_control`. `summary` gains `total_actions` / `actions_allowed` / `actions_denied` when actions are present. Pure-retrieval receipts produce byte-identical 2.1.0 shape — `actions[]` is omitted entirely when empty. A 2.1.0 verifier that preserves unknown fields validates a 2.2.0 receipt.
- **Mixed-trajectory audit.** The trajectory module already reserved `step_kind="tool_call"` in schema 1.3.0; Phase 2 puts it to use. A `retrieve → call_tool → retrieve` agent flow now produces three signed receipts that link into one DAG. `provenex audit --trajectory <dir>` validates the whole DAG end-to-end across mixed step kinds in a single CLI invocation.
- **Framework integrations.** `provenex.tool_call.integrations.langchain.ProvenexToolWrapper` admission-checks every LangChain tool invocation; the wrapper is duck-typed against `.name` + `.invoke(input)` so it works with any framework that follows that protocol. `provenex.tool_call.integrations.mcp.{wrap_mcp_request, provenex_mcp_admission}` does the same for MCP-shaped JSON-RPC handlers. Same receipt shape, same DSL, same trajectory — across both wrappers.
- **CLI extensions.** `provenex policy validate` now accepts unified files with `tool_call_control:` and the legacy access-control-only layout. `provenex policy hash` prints one bare `sha256:...` hash for single-section files (Phase 1 contract preserved) and a two-line per-section breakdown for unified files; `--section` filters to one half. `provenex audit --show-policy` renders the `tool_call_control` block alongside `access_control`.

## Schema (additive, 2.2.0)

Receipts at 2.2.0 are valid 2.x receipts. Pure-retrieval receipts produced under 2.2.0 are byte-equivalent to 2.1.0 receipts modulo the `schema_version` and `issuer` strings. Receipts that carry tool-call enforcement light up `actions[]` and `policy.tool_call_control`.

| New field | Where | Notes |
| --- | --- | --- |
| `actions[]` | top-level | Action records for tool-call attempts. Emitted only when non-empty. |
| `actions[i].action_index` | inside `actions[]` | Referenced from `policy.tool_call_control.decisions[i].action_index`. |
| `actions[i].parameters_hash` | inside `actions[]` | SHA-256 over the verbatim parameters dict; always present even when `parameters` is redacted. |
| `policy.tool_call_control` | inside `policy` | Evaluator identity, policy_id, policy_version_hash, per-action decisions. |
| `summary.total_actions` / `actions_allowed` / `actions_denied` | inside `summary` | Emitted only when `actions[]` is non-empty. |

The signature continues to cover the canonical-JSON serialisation of the entire receipt minus the signature block — including the new fields.

## Scope discipline

Phase 2 is decision and proof, not execution. The admission API returns `allow` / `deny` and emits a signed receipt; the caller (the MCP middleware, the LangChain wrapper, the agent framework) is responsible for executing the call against the target system using its own credentials. Provenex does not hold OAuth tokens, does not proxy traffic, and does not sit on the per-call response path. The line is enforced in every wrapper.

## Compatibility

- The Python SDK is backward compatible. Existing `provenex.verify_chunks(...)` calls work unchanged; existing `Policy.from_yaml(...)` calls work unchanged; existing receipts produced by 0.5.0 verify identically under 0.6.0.
- A 2.1.0 verifier that preserves unknown fields validates 2.2.0 receipts. (The standard JSON canonicalisation rule is unchanged.)
- All Phase 1 tests pass under 0.6.0 with no modifications beyond the cosmetic `schema_version` string assertions.

## Demo

```bash
PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
    python examples/agentic_admission_demo.py
```

Runs a four-step `retrieve → call_tool(allowed) → call_tool(denied) → retrieve` trajectory, emits four signed receipts to a temp directory, and runs `provenex audit --trajectory` over the whole set. Mixed step kinds, one signed audit trail, one CLI invocation.

## Install

```bash
pip install provenex-core==0.6.0
pip install "provenex-core[policy]==0.6.0"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[langchain]==0.6.0"     # LangChain integration
pip install "provenex-core[ed25519]==0.6.0"       # asymmetric receipt signing
pip install "provenex-core[postgres]==0.6.0"      # Postgres provenance index
```

The core remains pure stdlib. PyYAML, framework SDKs, and asymmetric crypto live behind extras.
