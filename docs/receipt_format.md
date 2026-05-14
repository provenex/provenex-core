# Receipt format

The provenance receipt is the public-facing artifact Provenex emits. It's what compliance teams hold onto, what auditors verify independently, and what downstream systems consume to decide whether to trust an AI output.

This document specifies the schema. The current schema version is **`2.2.0`**. Receipts at 2.x carry a unified top-level `policy` block with `verification`, optional `access_control`, and (in 2.2.0+) optional `tool_call_control` subsections. Schema 2.2.0 also adds an optional top-level `actions[]` array parallel to `sources[]`.

Schema history:

| Version | What it added |
| --- | --- |
| `1.0.0` | Original receipt format. |
| `1.1.0` | `transparency_log` block + per-source `leaf_index` / `inclusion_proof`. |
| `1.2.0` | *Reserved* for a future coverage block (chunk-identity-under-drift). |
| `1.3.0` | Optional `trajectory` block (multi-step agentic linkage). |
| `1.4.0` | Per-source `claims[]` (self-attribution) + per-source `content_source` (origin classifier). |
| `1.5.0` | (Skipped.) Interim shape that put `access_policy` as a separate top-level block. Never released. |
| `2.0.0` | **Breaking.** Unified `policy` block with `verification` and optional `access_control` subsections. The 1.x top-level `policy` (which held only the verification config) is replaced by `policy.verification`. |
| `2.1.0` | Per-decision `metadata_binding` field on `policy.access_control.decisions[]` recording whether `chunk_metadata` was tag-at-ingest (signed by the index row) or tag-at-evaluate (looked up at decision time). Additive: receipts without the field are valid 2.0.0 subsets. |
| `2.2.0` | **Phase 2.** Optional top-level `actions[]` array (tool-call records, parallel to `sources[]`); optional `policy.tool_call_control` subsection (admission decision record, parallel to `policy.access_control`); `summary` gains `total_actions` / `actions_allowed` / `actions_denied` when actions are present. Additive: a 2.1.0 receipt with no actions is a valid 2.2.0 receipt; a 2.1.0 verifier that ignores unknown fields validates a 2.2.0 receipt with actions. |

Minor bumps within 2.x are additive (new optional fields, ignored by older verifiers). The next major bump would be 3.0.0.

### Migrating from 1.x receipts

If your code reads a 1.x receipt:

| 1.x access path | 2.0.0 access path |
| --- | --- |
| `receipt["policy"]["block_stale"]` | `receipt["policy"]["verification"]["block_stale"]` |
| `receipt["policy"]["block_unauthorized"]` | `receipt["policy"]["verification"]["block_unauthorized"]` |
| *(no equivalent)* | `receipt["policy"]["access_control"]["evaluator"]` |
| *(no equivalent)* | `receipt["policy"]["access_control"]["policy_id"]` |
| *(no equivalent)* | `receipt["policy"]["access_control"]["decisions"][i]` |

The Provenex SDK only emits 2.0.0 receipts. Historical 1.x receipts remain valid artifacts — keep an older SDK around if you need to re-verify them.

## Design properties

The schema is intentionally:

- **Self-describing.** `schema_version` is at the top. `issuer` identifies the software that produced the receipt.
- **Independently verifiable.** Everything needed to verify the receipt without contacting the issuer is in the receipt itself.
- **Stable.** `schema_version` exists so this schema can evolve without breaking older receipts. Breaking changes bump the major version.
- **Privacy-preserving.** No document content. No PII. Only hashes, IDs, metadata.

## Top-level fields

```json
{
  "receipt_id": "prx_<32 hex chars>",
  "schema_version": "2.2.0",
  "issued_at": "2026-05-13T14:32:07.441Z",
  "issuer": "provenex-core/0.6.0",
  "output": { ... },
  "sources": [ ... ],
  "actions": [ ... ],            // optional (schema 2.2.0+)
  "policy": {
    "verification": { ... },
    "access_control": { ... },    // optional
    "tool_call_control": { ... }  // optional (schema 2.2.0+)
  },
  "summary": { ... },
  "transparency_log": { ... },
  "trajectory": { ... },
  "signature": { ... }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `receipt_id` | string | Globally unique. Prefix `prx_` plus 32 hex characters (16 random bytes). |
| `schema_version` | string | Semver. Always `2.2.0` for receipts produced by this SDK. |
| `issued_at` | string | ISO-8601 UTC with millisecond precision, `Z` suffix. |
| `issuer` | string | Software identifier, e.g. `provenex-core/0.6.0`. |
| `output` | object | See below. |
| `sources` | array | One entry per retrieved chunk. See below. |
| `actions` | array | Optional (2.2.0+). One entry per tool-call attempt. Present only when the receipt covers tool-call admissions; absent for pure-retrieval receipts. See below. |
| `policy` | object | The unified policy in effect. Always present. `policy.verification` is always there; `policy.access_control` appears iff a chunk evaluator was configured; `policy.tool_call_control` appears iff a tool-call evaluator was configured (2.2.0+). See below. |
| `summary` | object | Aggregate counts and overall status. See below. |
| `transparency_log` | object | Optional. Present iff the receipt was produced against a Merkle transparency log (1.1.0+). See below. |
| `trajectory` | object | Optional. Present iff the receipt is part of a multi-step agent trajectory (1.3.0+). See below. |
| `signature` | object | Optional. Present iff the receipt was signed. |

The unified `policy` block carries **every gate present**:

- `policy.verification` (always present): the per-outcome blocking and flagging configuration for the five verification outcomes (`VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`). Applies to retrieval only.
- `policy.access_control` (optional): the data-access policy decision record — which evaluator was used, the canonical policy version hash, and the per-chunk allow / deny verdict with the rules that fired.
- `policy.tool_call_control` *(schema 2.2.0+, optional)*: the tool-call admission decision record — same shape as `access_control`, but the decisions reference `actions[i].action_index` rather than `sources[i].fingerprint`. Present iff a tool-call evaluator was configured at admission time.

All gates are evaluated independently. A chunk reaches the LLM only if it clears both retrieval-side gates. A tool call is admitted only if it clears the tool-call-control gate.

## `output`

```json
{
  "output": {
    "hash": "sha256:<64 hex chars>",
    "hash_algorithm": "sha256"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `output.hash` | string | SHA-256 over the LLM output text, encoded as UTF-8. Prefixed with `sha256:`. |
| `output.hash_algorithm` | string | Always `sha256` in this schema version. |

The output text itself is **never** stored on the receipt. Only its hash.

## `sources[]`

One entry per chunk that was retrieved, in retrieval order. Both kept and policy-blocked chunks appear, so the receipt is a complete record.

```json
{
  "chunk_index": 0,
  "fingerprint": "sha256:<64 hex chars>",
  "document_id": "policy_v4",
  "document_version": "sha256:<64 hex chars>",
  "ingested_at": "2026-04-01T09:00:00.000Z",
  "chunk_offset": 0,
  "chunk_length": 936,
  "authorized": true,
  "verification_outcome": "VERIFIED",
  "normalization_applied": ["unicode_nfc", "strip_zero_width", "whitespace_collapse"],
  "leaf_index": 4217,
  "inclusion_proof": ["sha256:<hex>", "sha256:<hex>", "..."]
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `chunk_index` | integer | 0-based position in the retrieval result. |
| `fingerprint` | string | SHA-256 of the normalized chunk text. `sha256:` prefix. |
| `document_id` | string \| null | Caller-chosen stable document identifier. `null` if outcome is `UNVERIFIED`. |
| `document_version` | string \| null | SHA-256 of the normalized full document. `null` if `UNVERIFIED`. |
| `ingested_at` | string \| null | ISO-8601 UTC when the fingerprint was written to the index. `null` if `UNVERIFIED`. |
| `chunk_offset` | integer \| null | Character offset of the chunk in the normalized document. `null` if `UNVERIFIED`. |
| `chunk_length` | integer \| null | Chunk length in characters. `null` if `UNVERIFIED`. |
| `authorized` | boolean \| null | Authorization state at retrieval time. `null` if `UNVERIFIED`. |
| `verification_outcome` | string | One of `VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`. |
| `normalization_applied` | array of string | Ordered list of normalization steps applied. Used to reproduce the pipeline byte-for-byte. |
| `leaf_index` | integer | Optional (1.1.0+). Position of this fingerprint in the transparency log. Omitted on receipts produced without a log. |
| `inclusion_proof` | array of string | Optional (1.1.0+). RFC 6962 audit path as `sha256:<hex>` strings. Verifiable offline against `transparency_log.tree_root`. |
| `claims` | array of object | Optional (1.4.0+). Self-attribution claims from the calling agent about this chunk. See **`claims[]`** below. |
| `content_source` | string | Optional (1.4.0+). Origin classifier. See **`content_source`** below. |

### Verification outcomes

| Outcome | Meaning |
| --- | --- |
| `VERIFIED` | Fingerprint in index, signature OK, document authorized, version current. |
| `STALE` | Fingerprint in index, signature OK, document authorized, but version is superseded. |
| `UNAUTHORIZED` | Fingerprint in index, signature OK, but document is not currently authorized. |
| `UNVERIFIED` | Fingerprint not in index. The chunk was not ingested through Provenex. |
| `TAMPERED` | Fingerprint in index but the stored row's HMAC signature failed verification. |

### `claims[]`

Optional (schema 1.4.0+). A list of self-attribution claims from the calling agent or model about this specific source chunk. Designed for Self-RAG-style architectures where the model emits reflective tokens (`[Relevant]`, `[Supported]`, `[No Support]`) that classify retrieved content, and for any flow where the agent asserts something about the chunks (used / supported / relevant / cited).

```json
{
  "claims": [
    {
      "type": "model_used_in_answer",
      "asserted_by": "self_rag_agent",
      "value": true
    },
    {
      "type": "supports_answer",
      "asserted_by": "self_rag_agent",
      "value": "partial",
      "reason": "supports the first sub-claim, not the second"
    }
  ]
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `claims[].type` | string | Free-form classifier. Provenex-defined values: `"model_used_in_answer"`, `"supports_answer"`, `"relevant"`. Unknown values are valid for forward compatibility. |
| `claims[].asserted_by` | string | Caller-chosen opaque identifier for the agent / model that emitted the claim. Do not encode PII. |
| `claims[].value` | boolean \| string \| null | Optional value the assertion carries (e.g. `true`, `"partial"`). |
| `claims[].reason` | string | Optional short rationale supplied by the agent. |

**Trust model — load-bearing:** Provenex binds claims into the receipt's signature so the asserting agent cannot deny what it said, but **does not verify** that a claim is correct. A claim is **signed evidence of what was asserted**, not a verified fact. The trust root for the *content* of a claim is the agent operator; the trust root for the *integrity* of the record is Provenex's signature. Compliance teams reading a receipt should treat claims as the agent's word, not a Provenex attestation.

### `content_source`

Optional (schema 1.4.0+). Classifies the *origin* of this chunk's bytes. Useful when an `UNVERIFIED` outcome is present: an auditor reading the receipt needs to know whether to alarm (chunk was *supposed* to be in the indexed corpus and wasn't) or to expect the outcome (chunk was a live tool output that the corpus never claimed to cover).

```json
{ "content_source": "live_tool_output" }
```

Provenex-defined values (callers can use any string for forward compatibility):

| Value | Meaning |
| --- | --- |
| `"indexed_corpus"` | Default semantic. Chunk is expected to be in the Provenex index. Implicit when the field is absent. |
| `"live_tool_output"` | Chunk came from a live tool (web search, live DB query) and was never ingested. `UNVERIFIED` for this kind of chunk is expected, not an alarm. |
| `"memory_store"` | Chunk came from an agent's memory store (CrewAI memory, LangGraph state, custom store). |
| `"compiled_artifact"` | Chunk is a derived artifact from a compilation pipeline. Reserved for future use with the compilation-manifest model. |

Combined with `verification_outcome`, this lets auditors distinguish "expected miss" from "alarm condition" without needing application-level context. The field is covered by the receipt signature so an attacker cannot retroactively change the origin classifier to dampen an alarm.

## `actions[]` *(schema 2.2.0+)*

One entry per tool-call attempt. Phase 2 parallel of `sources[]`. Present only when the receipt covers tool-call admissions; absent on pure-retrieval receipts so the 2.1.0 shape is preserved exactly for backward compatibility.

```json
{
  "action_index": 0,
  "name": "web_search",
  "operation": "query",
  "parameters_hash": "sha256:7a2bf015...",
  "parameters": { "q": "weather today", "num": 10 },
  "target_system": "google_custom_search",
  "invocation_id": "inv_8e2c"
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `action_index` | integer | 0-based position in `actions[]`. Referenced from `policy.tool_call_control.decisions[i].action_index`. |
| `name` | string | Tool identifier (e.g. `"web_search"`, `"jira"`). For MCP, the server-and-tool path. |
| `operation` | string | The specific operation on the tool (e.g. `"create_issue"`, `"query"`). |
| `parameters_hash` | string | SHA-256 over the canonicalised verbatim parameter dict. `sha256:` prefix. Always present, regardless of whether `parameters` itself is recorded. |
| `parameters` | object \| null | Verbatim parameter dict, or `null` if the operator opted in to redaction via `admission_check(..., redact_parameters=True)`. `parameters_hash` remains verifiable against the original values either way. |
| `target_system` | string | Optional. Logical target system the call would reach. Omitted (not emitted as `null`) when absent. |
| `invocation_id` | string | Optional. Caller-chosen correlation ID. Omitted when absent. |

The `parameters` field is the only redactable element of an action record. The hash anchors the audit; the verbatim values are stored at the operator's discretion. This mirrors the `inputs` / `inputs_hash` convention on policy decisions.

## `policy`

The unified policy in effect when the receipt was issued. Always present; carries both gates in two subsections.

```json
{
  "policy": {
    "verification": {
      "block_stale": false,
      "block_unauthorized": true,
      "block_unverified": false,
      "block_tampered": true,
      "flag_stale": true,
      "flag_unauthorized": true,
      "flag_unverified": true,
      "flag_tampered": true
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
          "inputs": {
            "chunk_metadata": {"residency": "EU", "corpus": "policy_documents", "ingested_at": "2026-04-01T09:00:00Z"},
            "request_context": {"caller": {"role": "hr_admin"}, "jurisdiction": "EU", "purpose": "customer_support", "timestamp": "2026-05-13T14:32:07Z"}
          }
        },
        {
          "chunk_fingerprint": "sha256:7a2bf015...",
          "decision": "deny",
          "rules_fired": ["pii_classification_gate"],
          "inputs_hash": "sha256:b8e441f7...",
          "inputs": null
        }
      ]
    }
  }
}
```

### `policy.verification`

The verification gate config. Always present.

| Field | Type | Notes |
| --- | --- | --- |
| `block_*` | boolean | If true, chunks with this outcome are removed before the next stage. |
| `flag_*` | boolean | If true, chunks with this outcome are reflected in the summary even when not blocked. |

Recording the verification config on the receipt means an auditor can reason about what happened *and* what would have happened under a stricter policy.

### `policy.access_control`

The data-access policy decision record. Optional — present iff a `PolicyEvaluator` was configured at retrieval time.

| Field | Type | Notes |
| --- | --- | --- |
| `evaluator` | string | Backend identifier. Enum: `native_yaml` (open-source core), `rego` (commercial), `opa_service` (commercial), `custom`, `none`. |
| `policy_id` | string | The `policy_id` from the policy bundle. The literal string `"none"` when no policy was configured. |
| `policy_version_hash` | string | SHA-256 over the canonicalized policy bundle (`sha256:` prefix). Two policies that differ only in formatting hash to the same value. This is the field that would be published to the transparency log in the commercial transparency-log integration. |
| `policy_in_transparency_log` | boolean | Whether `policy_version_hash` is recorded in the transparency log. Always `false` in the open-source core; the commercial transparency-log integration lights this up. |
| `decisions` | array | Per-chunk decisions in retrieval order. One entry per chunk in `sources[]`. |
| `decisions[].chunk_fingerprint` | string | The chunk's fingerprint. Matches `sources[i].fingerprint`. |
| `decisions[].decision` | string | Enum: `allow`, `deny`, `allow_with_conditions`. v0.4 emits `allow` and `deny`; `allow_with_conditions` is reserved. |
| `decisions[].rules_fired` | array of string | Names of the rules whose `when` clause matched. The trace of rules that participated in the decision (regardless of pass / fail). Empty when no rules fired. |
| `decisions[].inputs_hash` | string | SHA-256 over the canonical `inputs` object. Always present — even when `inputs` is redacted, the hash lets an auditor with the original inputs independently verify. |
| `decisions[].inputs` | object \| null | The canonical inputs the evaluator looked at, or `null` if the operator chose to redact. Shape: `{"chunk_metadata": {...}, "request_context": {...}}`. |
| `decisions[].metadata_binding` | object | **Schema 2.1.0+.** Per-section trust class of the inputs. Shape: `{"chunk_metadata": "at_ingest"|"at_evaluate", "request_context": "at_evaluate"}`. `request_context` is always `at_evaluate` (the caller dict is built freshly at retrieval). `chunk_metadata` is operator-declared via `verify_chunks(..., chunk_metadata_binding=...)` — default `"at_evaluate"` for safety. See [`threat_model.md`](threat_model.md#trust-model-for-policy-decisions). |

The whole `policy` block is covered by the receipt signature using the canonical-JSON rule. Tampering with any field — including reordering decisions, rewriting `rules_fired`, or flipping a `metadata_binding` value — invalidates the signature.

### `policy.tool_call_control` *(schema 2.2.0+)*

The tool-call admission decision record. Optional — present iff a `ToolCallPolicyEvaluator` was configured at admission time.

```json
{
  "policy": {
    "tool_call_control": {
      "evaluator": "native_yaml",
      "policy_id": "agent-policy-v2",
      "policy_version_hash": "sha256:e10b1df5...",
      "policy_in_transparency_log": false,
      "decisions": [
        {
          "action_index": 0,
          "decision": "allow",
          "rules_fired": ["web_search_provider_allowlist", "no_secrets_in_query"],
          "inputs_hash": "sha256:b8e441f7...",
          "inputs": {
            "tool_parameters": {
              "name": "web_search",
              "operation": "query",
              "parameters": {"q": "weather today", "num": 10},
              "target_system": "google_custom_search"
            },
            "request_context": {"caller": {"role": "engineer"}, "jurisdiction": "US", "purpose": "incident_response", "timestamp": "2026-05-14T11:30:00Z"}
          },
          "metadata_binding": {
            "tool_parameters": "at_evaluate",
            "request_context": "at_evaluate"
          }
        }
      ]
    }
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `evaluator` | string | Backend identifier. Enum values overlap with `access_control.evaluator`: `native_yaml`, `rego` (commercial), `opa_service` (commercial), `custom`, `none`. |
| `policy_id` | string | The `policy_id` from the tool-call rule subset of the policy bundle. |
| `policy_version_hash` | string | SHA-256 over the canonicalised tool-call rule subset. Versioned independently of `access_control.policy_version_hash` — the two halves of a unified file change independently. |
| `policy_in_transparency_log` | boolean | Always `false` in the open-source core; lit up by the commercial transparency-log integration. |
| `decisions` | array | Per-action decisions in `actions[]` order. One entry per action in `actions[]`. |
| `decisions[].action_index` | integer | References `actions[action_index]`. Parallel to `access_control.decisions[i].chunk_fingerprint`. |
| `decisions[].decision` | string | Enum: `allow`, `deny`, `allow_with_conditions`. v0.6 emits `allow` and `deny`; `allow_with_conditions` is reserved for v1. |
| `decisions[].rules_fired` | array of string | Names of the rules whose `when` clauses matched. |
| `decisions[].inputs_hash` | string | SHA-256 over the canonical inputs object. Always present, even when `inputs` is redacted. |
| `decisions[].inputs` | object \| null | The canonical inputs the evaluator looked at, or `null` if redacted. Shape: `{"tool_parameters": {...}, "request_context": {...}}`. |
| `decisions[].metadata_binding` | object | Per-section trust class of the inputs. For tool calls, `tool_parameters` is always `"at_evaluate"` (parameters are caller-supplied per-request; there is no "at_ingest" analog for an ephemeral action). `request_context` is also always `"at_evaluate"`. |


## `summary`

```json
{
  "summary": {
    "total_chunks": 3,
    "verified": 2,
    "stale": 0,
    "unauthorized": 0,
    "unverified": 1,
    "tampered": 0,
    "total_actions": 1,
    "actions_allowed": 1,
    "actions_denied": 0,
    "overall_status": "PARTIAL"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `total_chunks` | integer | Number of source records on this receipt. |
| `verified` / `stale` / `unauthorized` / `unverified` / `tampered` | integer | Counts per outcome. Sum equals `total_chunks`. |
| `total_actions` | integer | Schema 2.2.0+. Number of action records on this receipt. **Emitted only when `actions[]` is non-empty** — pure-retrieval receipts produce the exact 2.1.0 summary shape with no action keys. |
| `actions_allowed` | integer | Schema 2.2.0+. Count of admitted tool calls. Emitted alongside `total_actions`. |
| `actions_denied` | integer | Schema 2.2.0+. Count of denied tool calls. Emitted alongside `total_actions`. |
| `overall_status` | string | One of `PASS`, `PARTIAL`, `FAIL`. See below. |

### `overall_status`

| Value | Meaning |
| --- | --- |
| `PASS` | Every chunk is `VERIFIED` AND every action is allowed. |
| `PARTIAL` | At least one non-`VERIFIED` outcome on the retrieval side, but no chunks would be blocked AND no actions denied under the policy in effect. |
| `FAIL` | At least one chunk would be blocked under verification policy, OR at least one tool-call action was denied by admission policy. Either failure suffices. |

## `transparency_log`

Optional. Present iff the receipt was produced against a Merkle transparency log (schema 1.1.0+). Records the log head at issuance time. Combined with the per-source `leaf_index` and `inclusion_proof` fields, anyone holding the receipt can verify offline that each fingerprint was committed to the log at its claimed position.

```json
{
  "transparency_log": {
    "tree_size": 4218,
    "tree_root": "sha256:<64 hex chars>"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `transparency_log.tree_size` | integer | Number of leaves in the log at issuance. |
| `transparency_log.tree_root` | string | RFC 6962 tree head as `sha256:<hex>`. |

The format follows [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) (the Certificate Transparency tree hash construction): `leaf_hash = SHA256(0x00 || leaf_bytes)`, `node_hash = SHA256(0x01 || left || right)`, with the recursion splitting at the largest power of two less than the subtree size for non-power-of-two trees. The leaf bytes for each row are the canonical payload that the index HMAC also signs, so a verified inclusion proof shows that an authentic row was committed to the log at the claimed position.

Verification:

```python
from provenex.core.merkle import verify_inclusion_proof

leaf = build_canonical_payload_from_source(source)  # same bytes the HMAC signs
proof = [bytes.fromhex(h.removeprefix("sha256:")) for h in source["inclusion_proof"]]
root = bytes.fromhex(receipt["transparency_log"]["tree_root"].removeprefix("sha256:"))
ok = verify_inclusion_proof(
    leaf=leaf,
    leaf_index=source["leaf_index"],
    tree_size=receipt["transparency_log"]["tree_size"],
    proof=proof,
    root=root,
)
```

## `trajectory`

Optional. Present iff the receipt is part of a multi-step agent trajectory (schema 1.3.0+). Links per-step receipts into a verifiable DAG so an auditor handed the full receipt set can reconstruct an iterative agent's retrieval trail. Designed for Agentic RAG, Self-RAG, RAT, multi-hop retrieval, LangGraph DAGs, CrewAI multi-agent flows, and any future iterative pattern.

```json
{
  "trajectory": {
    "trajectory_id": "trj_a3f1c0d2e419bf48a8b7d54f9c01ea73",
    "step_index": 2,
    "parent_step_ids": ["prx_c5d8e1f203a497bd5a6e0c2b48f7d519"],
    "step_kind": "retrieval",
    "agent_id": "research_agent",
    "trajectory_started_at": "2026-05-13T10:00:00.000Z"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `trajectory.trajectory_id` | string | Globally unique. Prefix `trj_` plus 32 hex characters (16 random bytes). Shared by every receipt in the trajectory. |
| `trajectory.step_index` | integer | 0-based ordinal within the trajectory. In DAG shapes, sibling branches may share an index; uniqueness is along the parent chain. |
| `trajectory.parent_step_ids` | array of string | `receipt_id` values of parent steps. Empty array for the root step. **List** (not scalar) so DAG shapes round-trip (LangGraph branches, CrewAI parallel agents). |
| `trajectory.step_kind` | string | Optional. Free-form classifier. Provenex-defined values: `retrieval`, `tool_call`, `memory_read`, `memory_write`, `compilation`. Unknown values are valid for forward compatibility. |
| `trajectory.agent_id` | string | Optional. Caller-chosen opaque identifier for the emitting agent. Useful in multi-agent flows. Do not encode PII here. |
| `trajectory.trajectory_started_at` | string | ISO-8601 UTC with millisecond precision. Same value across every step in the trajectory; lets a single step locate itself in time without the whole set. |

The trajectory block is covered by the receipt signature using the same canonical-JSON rule as every other field. Tampering with any trajectory field invalidates the signature.

Verification semantics:

- **Per-step verification** is unchanged — each receipt verifies its own signature, sources, and inclusion proofs exactly as a single-step receipt would.
- **Trajectory verification** is additional. `provenex audit --trajectory <dir_or_glob>` takes a set of receipt files and validates: all share the same `trajectory_id`; the DAG formed by `parent_step_ids` is acyclic; every referenced parent resolves to a receipt in the set; at least one root step exists.
- **Trust model.** Provenex binds parent-step claims cryptographically (the signature) but does not verify that the agent's claim about parent steps is causally correct — that is a verifiable-claim property, not a verifiable-computation property. The signature ensures the claim is non-repudiable.

Backward compatibility: receipts without a `trajectory` block behave identically to schema 1.1.0 / 1.2.0 receipts. Verifiers that do not understand 1.3.0 should ignore unknown fields per the minor-version additive rule.

## `signature`

Optional. Present iff the receipt was signed.

```json
{
  "signature": {
    "algorithm": "hmac-sha256",
    "value": "<hex or base64>"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `signature.algorithm` | string | Identifier of the signing algorithm. Shipped values: `hmac-sha256` (default; symmetric) and `ed25519` (asymmetric; requires the `[ed25519]` extra). Pluggable. |
| `signature.value` | string | The signature itself, hex-encoded. 64 hex chars for HMAC-SHA256; 128 hex chars for Ed25519. |

### What is signed

The signature covers the canonical byte serialization of the receipt with the `signature` block omitted:

```python
payload = json.dumps(receipt_dict_without_signature, sort_keys=True, separators=(",", ":")).encode("utf-8")
signature = sign(payload)
```

Key properties:

- **`sort_keys=True`** so any JSON encoder produces the same bytes.
- **No whitespace** so encoder defaults don't change the payload.
- **Signature block omitted** from the payload so it can be added afterward.

This makes signatures portable across implementations: any verifier in any language that serializes JSON with these rules will recompute the same payload bytes.

## Verifying a receipt

```python
import json
from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature

with open("receipt.json") as f:
    receipt = json.load(f)

signer = HmacSha256Signer(secret=b"<the shared HMAC key>")
ok = verify_receipt_signature(receipt, signer)
assert ok, "receipt signature invalid"
```

For asymmetric verification, use `Ed25519Signer` from the optional `[ed25519]` extra. The auditor only needs the public key:

```python
from provenex.core.ed25519 import Ed25519Signer

verifier = Ed25519Signer.from_public_key_pem(open("audit.pub", "rb").read())
ok = verify_receipt_signature(receipt, verifier)
```

The receipt structure does not change; only the signer changes. The CLI exposes this directly: `provenex audit receipt.json --public-key audit.pub`.

## Versioning

Breaking changes to this schema increment the major version of `schema_version`. Verifiers should reject receipts whose major `schema_version` they don't understand. Non-breaking additive changes (new optional fields) increment the minor version; verifiers may safely ignore unknown fields they don't recognize.
