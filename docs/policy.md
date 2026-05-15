# Policy reference

Provenex enforces policy at retrieval time and at tool-call admission time, and emits a cryptographically signed record of every decision. Schema 2.0.0 (Provenex v0.4) unified the verification gate and the data-access gate under a single `Policy` object; schema 2.2.0 (Provenex v0.6) adds a third half for agentic tool-call admission. This document is the reference for all three.

Before reading this, you may want the architectural framing in [`how_it_works.md`](how_it_works.md) and the receipt schema in [`receipt_format.md`](receipt_format.md).

## The unified `Policy`

A Provenex `Policy` has three halves:

- **`verification`** — the five-outcome gate. Decides which of `VERIFIED` / `STALE` / `UNAUTHORIZED` / `UNVERIFIED` / `TAMPERED` block a chunk before the next stage. Applies to retrieved content only.
- **`access_control`** — the data-access policy. A pluggable `PolicyEvaluator` that runs declarative rules over chunk metadata and the request context. Applies to retrieved content only.
- **`tool_call_control`** *(schema 2.2.0+)* — the tool-call admission policy. A pluggable `ToolCallPolicyEvaluator` that runs declarative rules over tool-call parameters and the request context. Applies to agentic tool calls only.

A chunk reaches the LLM only if **both** retrieval-side halves allow it. A tool call is admitted only if the tool-call half allows it. The verification half is always present (with sensible defaults if the caller doesn't override). The access-control and tool-call-control halves are independent — early-stage deployments can ship with verification only.

```python
from provenex import (
    NativeYamlEvaluator, NativeYamlToolCallEvaluator,
    Policy, VerificationPolicy,
)

# Explicit construction — native-DSL only (no tool calls)
policy = Policy(
    verification=VerificationPolicy(block_unauthorized=True, block_tampered=True),
    access_control=NativeYamlEvaluator.from_path("hr_policy.yaml"),
)

# Explicit construction — all three halves (retrieval + tool-call admission)
policy = Policy(
    verification=VerificationPolicy(block_unauthorized=True, block_tampered=True),
    access_control=NativeYamlEvaluator.from_path("agent_policy.yaml"),
    tool_call_control=NativeYamlToolCallEvaluator.from_path("agent_policy.yaml"),
)

# Or from a unified YAML config (single file holds every half present)
policy = Policy.from_yaml("provenex_policy.yaml")
```

## What policy can express

In scope:

- **Origin / provenance** — flows through the existing five-outcome verification policy.
- **Freshness / recency** — `chunk.ingested_at` against a duration window (`not_older_than: 90d`).
- **Access control** — fields under `request.caller.*` against rule expectations. Identity-provider integration is your concern; Provenex consumes the caller dict you supply.
- **Jurisdiction / data residency** — `chunk.metadata.residency` against `request.jurisdiction`.
- **Sensitivity / classification** — `chunk.metadata.classification` against caller role or purpose.
- **PII presence and handling** — `chunk.metadata.contains_pii` (or any tag your upstream PII tool sets) against caller role.
- **Authorization scope** — `request.purpose` and arbitrary combinations.

## What policy cannot express (the refusal list)

Provenex's `PolicyEvaluator` explicitly does **NOT**:

- Assess content quality.
- Detect factual accuracy or hallucinations.
- Detect bias.
- Moderate output content.
- Make cost-based routing decisions.
- Enforce arbitrary business logic.
- **Detect PII** (it enforces tags from upstream PII detectors).
- **Evaluate quality** (it enforces decisions made by upstream data governance).

If a policy rule needs one of these, the right answer is to fix the upstream system that should be producing the tag — not extend Provenex.

## Unified YAML config file

The single file an operator authors and ships. Either subsection can be omitted; a file with neither produces a Policy with defaults.

```yaml
version: 1
policy_id: hr-corpus-retrieval-v3       # appears on every receipt produced under this policy
description: HR corpus access policy    # free-form, ignored by the evaluator

# ---- VERIFICATION HALF ----
# The five-outcome gate. Omitted keys take VerificationPolicy defaults
# (block UNAUTHORIZED + TAMPERED; flag everything else).
verification:
  block_stale: false
  block_unauthorized: true
  block_unverified: false
  block_tampered: true
  flag_stale: true
  flag_unauthorized: true
  flag_unverified: true
  flag_tampered: true

# ---- ACCESS-CONTROL HALF ----
# Pluggable evaluator. The native YAML DSL is shipped in the open-source
# core. Rego and OPA-service evaluators are commercial.
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
    policy_version_mismatch: deny

# ---- TOOL-CALL ADMISSION ----
# Pluggable evaluator. The native YAML DSL is shipped in the open-source
# core. Rego and OPA-service evaluators for tool calls are commercial.
tool_call_control:
  rules:
    - name: web_search_domain_allowlist
      when:
        tool.name: web_search
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny

    - name: no_pii_in_query
      when:
        tool.name: web_search
      require:
        tool.parameters.q:
          not_matches_pattern: "*api*"
      on_violation: deny

    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation:
          in: [create_issue, update_issue, delete_issue]
      require:
        request.caller.role:
          in: [engineer, manager, admin]
      on_violation: deny

  defaults:
    unknown_metadata: deny
```

### Top-level fields

| Field | Required | Notes |
| --- | --- | --- |
| `version` | yes (or omit, defaults to 1) | Must be `1`. Bumps when the unified schema grammar changes. |
| `policy_id` | yes if any rule section is present | Non-empty string. Appears on every receipt produced under this policy. |
| `description` | no | Free-form text. |
| `verification` | no | Verification gate config. Omitting it uses dataclass defaults. |
| `access_control` | no | Chunk-level access-control rules. Omitting it means no chunk evaluator is configured — only the verification gate applies to retrieval. |
| `tool_call_control` *(schema 2.2.0+)* | no | Tool-call admission rules. Omitting it means no tool-call policy is configured — admission defaults to allow. |

Unknown top-level keys raise a parse error. A typo is a load-time failure, not a silent allow.

### `verification` subsection

A flat map of booleans. Recognised keys:

| Key | Default | Meaning |
| --- | --- | --- |
| `block_stale` | `False` | Block chunks whose document version is superseded. |
| `block_unauthorized` | `True` | Block chunks whose document is not authorized. |
| `block_unverified` | `False` | Block chunks not found in the index. |
| `block_tampered` | `True` | Block chunks whose index-row signature failed. |
| `flag_stale` | `True` | Note STALE chunks on the receipt summary, even if not blocked. |
| `flag_unauthorized` | `True` | Note UNAUTHORIZED chunks on the receipt summary. |
| `flag_unverified` | `True` | Note UNVERIFIED chunks on the receipt summary. |
| `flag_tampered` | `True` | Note TAMPERED chunks on the receipt summary. |

Unknown keys raise. Non-boolean values raise.

### `access_control` subsection — Native YAML DSL

The native DSL is intentionally small. Each rule:

| Field | Required | Notes |
| --- | --- | --- |
| `name` | yes | Non-empty string. Appears in `rules_fired` on the receipt. |
| `when` | no | Flat key/value map; rule applies iff every entry matches by direct equality. Omitting `when` makes the rule fire for every chunk. |
| `require` | no | Flat key/value map of constraints. Operators below. |
| `on_violation` | yes | `deny` only. `allow_with_conditions` is reserved. |

#### Path roots

Two domains use distinct roots; cross-domain references fail at parse time.

**`access_control` rules** see chunk and request data:

| Path root | Resolves to |
| --- | --- |
| `chunk.fingerprint` | The chunk's SHA-256 fingerprint string. |
| `chunk.document_id` | The chunk's document identifier from the index. |
| `chunk.document_version` | The chunk's document version from the index. |
| `chunk.ingested_at` | The chunk's ingestion timestamp from the index. |
| `chunk.metadata.<key>` | Customer-defined tag under the chunk's metadata dict. |
| `chunk.content_source` | One of `indexed_corpus`, `live_tool_output`, `memory_store`, `compiled_artifact`. |

**`tool_call_control` rules** *(schema 2.2.0+)* see tool-call and request data:

| Path root | Resolves to |
| --- | --- |
| `tool.name` | Tool identifier (e.g. `"web_search"`, `"jira"`, `"jira/issues"` for MCP). For **memory writes** (0.6.5 `admit_memory_write`) this is the constant `"memory.write"`. For **model-inference calls** (0.6.5 `admit_model_inference`) this is the model identifier (e.g. `"claude-opus-4-7"`). |
| `tool.operation` | The specific operation on the tool (e.g. `"create_issue"`, `"query"`). For memory writes, this is the **memory key being written** — the natural per-key gate axis (`when: { tool.name: "memory.write", tool.operation: "user_profile" }`). For model inference, the verb (`"complete"`, `"stream"`, `"embed"`, `"chat"`). |
| `tool.parameters.<key>` | The caller-supplied parameter value at `<key>`. Memory writes always have `value_hash`; model inferences always have `prompt_hash`. Both classes default to redacting the verbatim value/prompt — write rules against the hash for content-shape gates, against extras like `tool.parameters.max_tokens` for parameter gates. |
| `tool.target_system` | Logical target system the call would reach (e.g. `"google_custom_search"`, `"acme.atlassian.net"`, `"anthropic"`, `"openai"`, `"crewai_memory"`). |
| `tool.invocation_id` | Caller-chosen correlation ID (not load-bearing for the decision). |

**Both domains** see the shared request context:

| Path root | Resolves to |
| --- | --- |
| `request.caller.<key>` | Field on the caller dict supplied with the request. |
| `request.jurisdiction` | Free-form region code (`EU`, `US`, etc.). |
| `request.purpose` | Free-form purpose string. |
| `request.timestamp` | ISO-8601 UTC timestamp of the request. Also the "now" used for freshness comparisons. |

A missing path in a `when` clause means the rule's scope does not apply — the rule does not fire. A missing path in a `require` clause is governed by `defaults.unknown_metadata` (defaults to `deny`).

#### When operators *(schema 2.2.0+ for `in`)*

`when` clauses are quick "does this rule apply" filters. Two shapes:

| Shape | Meaning |
| --- | --- |
| `<path>: <value>` | Direct equality. The path resolves to a value equal to the RHS. |
| `<path>: { in: [a, b, c] }` | Path resolves to a value in the list. Added in schema 2.2.0 so CRUD-style rules don't need three near-identical duplicates. |

No richer operators in `when` — move complex logic into `require`.

#### Require operators

| Operator | Shape | Meaning |
| --- | --- | --- |
| direct equality | `<path>: <value>` | The path resolves to a value equal to the right-hand side. |
| `in` | `<path>: { in: [a, b, c] }` | The path resolves to a value in the list. |
| `not_in` | `<path>: { not_in: [a, b, c] }` | The path resolves to a value NOT in the list. |
| `not_older_than` | `<path>: { not_older_than: 90d }` | The path resolves to an ISO-8601 timestamp whose age (relative to `request.timestamp`) is at most the duration. Supported units: `s`, `m`, `h`, `d`. |
| `matches_pattern` *(2.2.0+)* | `<path>: { matches_pattern: "*.example.com/*" }` | The path resolves to a string matching a POSIX `fnmatch` **glob**. Globs are auditable; regexes are not — by design. |
| `not_matches_pattern` *(2.2.0+)* | `<path>: { not_matches_pattern: "*api*key*" }` | The path resolves to a string NOT matching the glob. |
| `length_at_most` *(2.2.0+)* | `<path>: { length_at_most: 500 }` | The path resolves to a string of at most this length. Cheapest defense against "agent gets prompt-injected into a 50KB query." |

Unknown operators raise at load time.

#### `defaults`

| Key | Values | Behavior |
| --- | --- | --- |
| `unknown_metadata` | `allow` \| `deny` | What to do when a `require` clause references a path the chunk metadata or request context doesn't have. Default `deny`. |
| `policy_version_mismatch` | `allow` \| `deny` | Reserved for a future release. Default `deny`. |

### Reserved-but-unimplemented features

The following raise `UnsupportedPolicyFeature` at load time:

- `any_of`, `all_of`, `not` — boolean composition.
- `nested` — nested rules.
- `on_violation: allow_with_conditions`.
- Custom functions and external data lookups.
- Unknown `require` operators.
- **Trajectory-level rules** — see [What the native DSL deliberately doesn't do](#what-the-native-dsl-deliberately-doesnt-do-and-why) below. The native DSL is per-decision-pure by design; cross-decision rules live in the commercial Rego adapter or in the downstream anomaly detector reading receipts.

The Rego adapter and OPA service adapter are commercial.

## What the native DSL deliberately doesn't do (and why)

Three things you might reach for that the native DSL refuses, **on purpose**:

1. **Trajectory-level rules.** "Deny if this caller has done > N web_search calls in this trajectory." "Block if this agent has read from memory AND called an external tool within K seconds." "Alert if the rules_fired distribution on this trajectory looks anomalous." These are sequence / pattern detections. The native DSL won't evaluate them.

2. **Cross-decision aggregations.** "Deny if more than half of this caller's recent decisions denied." "Alert if the per-step_kind distribution has shifted by > 20% in the last hour." Aggregations over history are out.

3. **External data lookups during evaluation.** "Check the user's current entitlement in Okta before deciding." "Resolve this document's classification from the live catalog service." Calls to external systems at decision time are out.

**Why it's a design choice, not a missing feature.** `PolicyEvaluator.evaluate(chunk_or_tool, request) → PolicyDecision` is contractually pure: same inputs, same decision, same `inputs_hash`. Two regulators, two months apart, with the original `(chunk, request)` inputs and the original policy bundle MUST reproduce the receipt's `inputs_hash` exactly. That property is what makes Provenex receipts auditable years after they were issued. The moment a rule reads hidden state outside `(chunk_or_tool, request)` — trajectory history, aggregations, external lookups — `inputs_hash` becomes path-dependent. The audit story collapses.

**Where the load-bearing reasons go:**

- `policy_version_hash` is canonical: two bundles that parse to the same Python structure produce the same hash. Trajectory rules would require canonicalising trajectory state into the bundle, which is incoherent (trajectories are runtime artifacts, not config).
- `inputs_hash` per decision is the audit anchor. Path-dependent inputs mean an auditor can't reproduce it from the recorded inputs alone — they'd need the entire trajectory state, which is exactly what the receipt was supposed to summarise.
- The five verification outcomes are sacred. Adding a sixth ("denied by trajectory rule") would erode the discrete-cryptographic-states discipline.

**Where to put trajectory rules instead.**

- **Commercial Rego adapter** — the [Rego language](https://www.openpolicyagent.org/docs/latest/policy-language/) is general-purpose and can express trajectory rules cleanly. The Rego adapter is opt-in; operators who use it accept the audit-anchor trade-off explicitly (the `inputs_hash` discipline still applies per decision, but Rego policies can reference trajectory state if the operator authors them that way). Available under the commercial license — see [provenex.ai](https://provenex.ai).

- **Downstream anomaly detector reading receipts** — this is the recommended path for almost every customer. Provenex emits one signed receipt per decision; an anomaly detector / SIEM / UEBA tool reads the receipt stream and does the sequence / pattern detection there. That's the OCSF export's whole purpose (see [`ocsf_mapping.md`](ocsf_mapping.md)) — receipts become the source-of-record events the detector consumes. The detector is a different tool category (SIEM / UEBA), with different budgets and different vendors. Provenex is the firewall; the detector is the SIEM that correlates across firewall events.

The firewall doesn't ship a SIEM. The SIEM doesn't ship a firewall. Each is better-engineered because it doesn't try to be the other. See [`anomaly_detection.md`](anomaly_detection.md) for the canonical positioning, including worked anomaly-detection patterns over the receipt stream.

## Evaluator interface

Two parallel Protocols — one for chunks, one for tool calls. Same shape; the discriminator is the type of the context argument. A single `NativeYamlEvaluator` instance satisfies the chunk Protocol; a single `NativeYamlToolCallEvaluator` instance satisfies the tool-call Protocol. A unified bundle that declares both sections produces both evaluator instances under one `Policy`.

### `PolicyEvaluator` — chunk decisions

Backends implement the `PolicyEvaluator` protocol from `provenex.policy.evaluator`:

```python
from typing import Protocol
from provenex import ChunkContext, RequestContext, PolicyDecision

class PolicyEvaluator(Protocol):
    @property
    def evaluator_name(self) -> str: ...
    @property
    def policy_id(self) -> str: ...
    @property
    def policy_version_hash(self) -> str: ...
    def evaluate(
        self,
        chunk: ChunkContext,
        request: RequestContext,
    ) -> PolicyDecision: ...
```

Contracts every backend must hold:

- **Deterministic.** The same `(chunk, request)` and the same bundle MUST produce the same decision. No clock reads outside `request.timestamp`, no random sampling, no network calls.
- **Side-effect-free per evaluation.** Logging and audit emission are the caller's job.
- **Stable `policy_version_hash`.** Two bundles that parse to equal Python structures produce the same hash. Whitespace and key reordering do not change the hash.

The native YAML backend (`provenex.NativeYamlEvaluator`) is the reference implementation. Rego and OPA-service implementations of the same protocol ship commercially and emit the same receipt shape — the `evaluator` field on the receipt distinguishes them.

### `ToolCallPolicyEvaluator` — tool-call decisions *(schema 2.2.0+)*

```python
from typing import Protocol
from provenex import RequestContext, ToolCallContext
from provenex.policy.evaluator import PolicyDecision

class ToolCallPolicyEvaluator(Protocol):
    @property
    def evaluator_name(self) -> str: ...
    @property
    def policy_id(self) -> str: ...
    @property
    def policy_version_hash(self) -> str: ...
    def evaluate(
        self,
        tool: ToolCallContext,
        request: RequestContext,
    ) -> PolicyDecision: ...
```

Same contracts as `PolicyEvaluator` (deterministic, side-effect-free, stable hash). The native YAML backend (`provenex.NativeYamlToolCallEvaluator`) is the reference implementation. The Rego and OPA-service adapters for tool-call rules are commercial.

`policy_version_hash` covers only the tool-call subset — the two halves of a unified file version independently, the same way `access_control` does. An auditor reading a chunk receipt and a tool-call receipt produced under the same unified file will see two different hashes; modifying one half does not invalidate prior receipts that referenced the other half.

## Receipt block reference

When a Policy is configured, every receipt carries the unified `policy` block:

```json
{
  "policy": {
    "verification": {
      "block_unauthorized": true,
      "block_tampered": true,
      "...": "..."
    },
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
    }
  }
}
```

Full field reference is in [`receipt_format.md`](receipt_format.md#policy).

Key points:

- The `verification` half is **always present**.
- The `access_control` half is **optional** — receipts produced without a configured evaluator omit it.
- `policy_version_hash` is canonical: two policies that differ only in formatting hash to the same value. Use `provenex policy hash <policy.yaml>` to print the hash a policy will produce.
- `inputs_hash` is computed over the canonical inputs object regardless of whether `inputs` itself is recorded. An operator can redact `inputs: null` while keeping the hash, so an auditor with the original inputs can verify them independently.
- **`metadata_binding`** (schema 2.1.0+) records the trust class of each input. `chunk_metadata` is `"at_ingest"` (signed by the index row) or `"at_evaluate"` (looked up at decision time). `request_context` is always `"at_evaluate"`. Declare via `verify_chunks(..., chunk_metadata_binding=...)`; default is `"at_evaluate"` for safety. See [`threat_model.md`](threat_model.md#trust-model-for-policy-decisions) for the trust model.
- **`caller_hash` (top-level) and `trajectory.session_id` (schema 2.3.0+) are correlation fields, NOT policy inputs.** They appear on the receipt for downstream anomaly detectors / SIEMs to group events by caller and session. Neither field resolves under `request.*` in a rule's `when` or `require` clause. `session_id` is excluded from `inputs_hash` by design — two otherwise-identical requests differing only in `session_id` produce identical decisions and identical input hashes. This preserves the deterministic-per-evaluation contract: per-decision purity stays intact, and sequence / pattern detection is the downstream detector's job. See [`receipt_format.md`](receipt_format.md#top-level-caller_hash-schema-230) for the full reference.

## Worked examples

### Example 1 — HR corpus with PII gating and EU residency

See the file at the top of this document. EU jurisdiction only sees EU-resident chunks; PII-tagged chunks are gated to HR roles; policy-documents corpus has a 90-day freshness window.

### Example 2 — Classification-by-role for a research assistant

A simpler policy that gates a research-assistant retriever on classification level.

```yaml
version: 1
policy_id: research-assistant-v1

verification:
  block_unauthorized: true
  block_tampered: true

access_control:
  rules:
    - name: confidential_to_senior_only
      when:
        chunk.metadata.classification: confidential
      require:
        request.caller.seniority:
          in: [senior, staff, principal]
      on_violation: deny

    - name: secret_blocked_entirely
      when:
        chunk.metadata.classification: secret
      require:
        chunk.metadata.classification: public   # never satisfiable; always denies
      on_violation: deny

  defaults:
    unknown_metadata: allow   # default-allow during initial rollout
```

The `secret_blocked_entirely` rule shows a pattern for "absolute denylist" with the v0.4 operator set: the `require` clause is intentionally unsatisfiable so the rule always denies for chunks where the `when` clause matches.

### Example 3 — Tool-call admission for an agentic flow *(schema 2.2.0+)*

A policy authored for an agent that uses `web_search` and `jira`. Note how the same unified file expresses chunk policy *and* tool-call policy under one `policy_id` and one canonical document.

```yaml
version: 1
policy_id: incident-response-agent-v2

verification:
  block_unauthorized: true
  block_tampered: true

access_control:
  rules:
    - name: classification_gate
      when:
        chunk.metadata.classification: confidential
      require:
        request.caller.role: { in: [engineer, manager, admin] }
      on_violation: deny

tool_call_control:
  rules:
    # Domain allowlist for the search tool. Anyone trying to call
    # web_search against an unapproved provider is denied.
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system: { in: [google_custom_search, bing_v7] }
      on_violation: deny

    # PII / secrets pattern check on the query string.
    - name: no_secrets_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*(api[_-]?key|password|secret)*"
      on_violation: deny

    # Length cap. Cheapest defense against prompt-injection-via-long-query.
    - name: query_length_cap
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          length_at_most: 500
      on_violation: deny

    # Role gate on Jira writes. CRUD-style multi-operation rule uses
    # `in:` in the when clause (added in schema 2.2.0).
    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation:
          in: [create_issue, update_issue, delete_issue]
      require:
        request.caller.role: { in: [engineer, manager, admin] }
      on_violation: deny

  defaults:
    unknown_metadata: deny
```

### Example 4 — Memory writes and model-inference gates *(0.6.5+)*

The same `tool_call_control` DSL handles memory writes (admission shape with `name="memory.write"` and the memory key carried in `tool.operation`) and model-inference calls (admission shape with `name=<model_name>` and the provider in `tool.target_system`). Same grammar, same operators, same receipt shape — no new DSL surface to learn.

```yaml
version: 1
policy_id: agent-memory-and-models-v1

tool_call_control:
  rules:
    # Memory-write gate by key — only HR roles can write to user_profile.
    - name: hr_only_for_user_profile_writes
      when:
        tool.name: memory.write
        tool.operation: user_profile
      require:
        request.caller.role:
          in: [hr_admin, payroll]
      on_violation: deny

    # Bound write size by checking the value_hash field shape. (Memory
    # values themselves are redacted from the receipt by default; the
    # hash is always present and policy can constrain other parameters
    # like ``ttl`` or ``store_id``.)
    - name: cache_writes_require_ttl
      when:
        tool.name: memory.write
        tool.operation: cache
      require:
        tool.parameters.ttl:
          in: [60, 300, 3600]
      on_violation: deny

    # Model-inference allowlist — only allow these two providers.
    - name: model_provider_allowlist
      when:
        tool.operation: { in: [complete, stream, chat] }
      require:
        tool.target_system:
          in: [anthropic, openai]
      on_violation: deny

    # Token-count cap on Claude Opus — protects budget.
    - name: claude_opus_token_cap
      when:
        tool.name: claude-opus-4-7
      require:
        tool.parameters.max_tokens:
          in: [1000, 2000, 4000, 8000]
      on_violation: deny

  defaults:
    unknown_metadata: deny
```

Detectors can group by `caller_hash + tool.name="memory.write" + tool.operation=<key>` for per-key write rate baselines, and by `caller_hash + tool.name=<model>` for per-model usage baselines. Anomalies — a caller writing to a key 100× their normal rate, or calling Claude Opus 100× the baseline — fall out of standard SIEM aggregations.

### Example 5 — Verification-only, no access control

For early-stage deployments. The access_control section is omitted entirely; only the verification gate applies. This is `verify_chunks` behaviour from v0.1 through v0.3.

```yaml
version: 1
policy_id: verification-only-v1

verification:
  block_unauthorized: true
  block_unverified: true
  block_tampered: true
  block_stale: false
```

## Wiring

### Retrieval — `verify_chunks`

A complete retrieval call with policy enforcement:

```python
from provenex import (
    verify_chunks, Policy, RequestContext,
    HmacSha256Signer, SQLiteProvenanceIndex,
)

index = SQLiteProvenanceIndex("provenance.db")
policy = Policy.from_yaml("hr_policy.yaml")
request = RequestContext(
    caller={"role": "hr_admin", "id": "u_4218"},
    jurisdiction="EU",
    purpose="customer_support",
    timestamp="2026-05-13T14:32:07Z",
)

result = verify_chunks(
    chunks=retrieved_chunks,
    index=index,
    signer=HmacSha256Signer(),
    policy=policy,
    request_context=request,
    chunk_metadata=[
        {"residency": "EU", "corpus": "policy_documents", "contains_pii": False},
        {"residency": "US", "corpus": "policy_documents", "contains_pii": True},
    ],
)
feed_to_llm(result.kept)   # only chunks that passed BOTH gates
save_receipt(result.receipt)
```

The verification gate and the access-control gate are independent. A chunk reaches `result.kept` only if **both** allow it. `result.receipt.to_dict()["policy"]` carries both halves.

For v0.4, `RequestContext` is constructed explicitly by the caller. Identity-provider integration (so the caller dict comes from your IdP rather than your code) is commercial.

### Tool-call admission — `admission_check` *(schema 2.2.0+)*

The tool-call admission analog of `verify_chunks`. Same policy object, same request context, same trajectory cursor. Same receipt format — the receipt carries an `actions[]` block instead of (or alongside) `sources[]`.

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
)

result = admission_check(
    tool=ToolCallContext(
        name="jira",
        operation="create_issue",
        parameters={"project": "INC", "summary": "..."},
        target_system="acme.atlassian.net",
    ),
    request=request,
    policy=policy,
    signer=HmacSha256Signer(),
)
if result.allowed:
    jira_client.create_issue(...)        # caller's own credentials
save_receipt(result.receipt)             # signed, verifiable offline
```

The receipt records the action AND the decision — denials are auditable too. The actual tool call is the caller's responsibility; Provenex returns a decision, not an execution. This is the load-bearing "decision and proof, not execution" line: the moment Provenex starts holding tokens or proxying calls it has become a different product.

**Convenience.** For callers that want "raise on deny, return on allow," use `provenex.enforce_admission(...)` — same signature, raises `ToolCallDenied` (which carries the receipt) instead of returning a deny result.

### Multi-step flows — trajectory composition

A mixed retrieve → tool-call → retrieve trajectory produces three signed receipts that link into one DAG:

```python
from provenex import start_trajectory

trj = start_trajectory(agent_id="incident_agent")

# Step 0: retrieval
r0 = verify_chunks(..., trajectory=trj)

# Step 1: tool call (advances cursor via r0.next_trajectory)
r1 = admission_check(..., trajectory=r0.next_trajectory)
if r1.allowed:
    jira_client.create_issue(...)

# Step 2: another retrieval
r2 = verify_chunks(..., trajectory=r1.next_trajectory)
```

`provenex audit --trajectory <dir>` validates the full DAG in one pass — shared `trajectory_id`, no dangling parents, every signature verifies, mixed `step_kind` values (retrieval / tool_call) accepted natively. See [`receipt_format.md`](receipt_format.md) for the trajectory block schema.

## CLI

```bash
provenex policy validate hr_policy.yaml   # parse + validate, non-zero on error
provenex policy hash     hr_policy.yaml   # print canonical policy_version_hash(es)
provenex audit receipt.json --show-policy # render the unified policy block in audit output
provenex audit --trajectory ./receipts/   # validate a whole agentic trajectory at once
```

Use `provenex policy validate` in CI to catch typos before a broken policy is deployed.

`provenex policy hash` on a single-section file prints one bare `sha256:...` hash (the original contract — pipeline scripts that grep for that prefix continue working). On a unified file with both `access_control` and `tool_call_control`, it prints two lines, one per section, so the auditor can see at a glance which half changed. The `--section` flag filters to one half if needed.

## Commercial evaluators (Rego, OPA service)

The `PolicyEvaluator` protocol is the integration point. Two backends ship commercially:

- **Rego adapter.** Loads a Rego policy and routes evaluation to an embedded OPA engine. Targets teams who author authorization in Rego elsewhere and want one language across the stack.
- **OPA service adapter.** Delegates each decision to a running OPA instance over HTTP. Targets teams who run OPA as a service.

Both produce the same `policy.access_control` block shape on the receipt. The `evaluator` field distinguishes them (`rego`, `opa_service`). The decision semantics — allow / deny / `rules_fired` — are evaluator-agnostic by design, so an auditor reading a receipt does not need to know which backend was in use.

The transparency-log integration for policy bundles (`policy_in_transparency_log: true`) is also commercial.

## Threat model and trust boundaries

See [`threat_model.md`](threat_model.md#trust-model-for-policy-decisions) for the trust model for policy decisions specifically. Two important boundaries:

1. **A policy decision is only as trustworthy as the metadata feeding it.** Tag-at-ingest (the tag is signed alongside the fingerprint) and tag-at-evaluate (the tag is read from an external system at decision time) have different trust properties.
2. **The operator who controls the signing key and the policy file can produce any decision they want.** The commercial transparency-log integration is the mitigation — it forces the operator to commit to the policy publicly.

These are limits an honest deployment should understand.
