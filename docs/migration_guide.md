# Migration guide

How to upgrade Provenex from one version to the next, what stays stable across upgrades, and the deprecation timeline. The companion artefact is [CHANGELOG.md](../CHANGELOG.md), which records every customer-facing change; this doc tells you what the changes mean operationally.

## Stability commitments

Three surfaces, three guarantees.

**Receipt schema.** `SCHEMA_VERSION` in [provenex/core/receipt.py](../provenex/core/receipt.py) is the single source of truth. Minor bumps are additive on the wire: a verifier built against an earlier minor validates a later minor unchanged when it ignores unknown fields. Within one major, every receipt verifies under every binary. Major bumps may change the top-level shape (2.0.0 did); a verifier built against an older major must reject receipts at a newer major's `schema_version`. The schema-history table below records what each bump added.

**SDK API.** Within one minor, the public Python API on the `provenex` package is stable. Arguments do not move, kwargs do not rename, return shapes do not change. Deprecations land with a `DeprecationWarning` one minor version (and at least one major version) before removal. The integration packages (`provenex.integrations.*`, `provenex.tool_call.integrations.*`, `provenex.export.*`) follow the same rule.

**CLI surface.** Subcommand names and existing flag names are stable across minor versions. New flags are added; existing flags are not removed without a deprecation period. Human-readable output may evolve cosmetically (added context lines, colour); `--json` output is stable per the schema rule.

## Schema-history table

The authoritative table lives in [receipt_format.md § Schema history](receipt_format.md). Mirrored here for upgrade convenience; if the two diverge, `receipt_format.md` wins.

| Schema | What it added | Provenex version |
| --- | --- | --- |
| `1.0.0` | Original receipt format. | 0.1.0 |
| `1.1.0` | `transparency_log` block + per-source `leaf_index` and `inclusion_proof`. | |
| `1.3.0` | Optional `trajectory` block (multi-step agentic linkage). | |
| `1.4.0` | Per-source `claims[]` (self-attribution) + per-source `content_source` (origin classifier). | |
| `2.0.0` | **Breaking.** Unified `policy` block with `verification` and optional `access_control`. The 1.x top-level `policy` (verification-only) is replaced by `policy.verification`. | 0.4.0 |
| `2.1.0` | Per-decision `metadata_binding` field recording whether `chunk_metadata` was tag-at-ingest or tag-at-evaluate. | |
| `2.2.0` | Tool-call admission. Optional top-level `actions[]`; optional `policy.tool_call_control`; `summary` gains action counters. | 0.6.0 |
| `2.3.0` | Source-of-record fields for SIEMs. Top-level `caller_hash`; optional `trajectory.session_id`. | 0.6.4 |
| `2.4.0` | Window-aligned splice control + request-to-receipt binding. Optional top-level `request_binding`; optional per-source `entry_kind`. | 0.8.0 |

Schema version is sourced from [provenex/core/receipt.py](../provenex/core/receipt.py); the docs-consistency lint catches any drift.

## Per-version upgrade notes

Order: oldest first. If you are upgrading across multiple versions, apply each note in order and the final operational state is the same as one big-bang upgrade.

### 0.4.x → 0.5.0

Postgres backend lands. Drop-in: existing SQLite deployments are unaffected. To adopt the new backend:

```python
from provenex import PostgresProvenanceIndex
index = PostgresProvenanceIndex(dsn="postgresql://...")
```

The interface is identical to `SQLiteProvenanceIndex`. Receipts produced against either backend verify identically under either backend. See [runbooks/postgres_operations.md](runbooks/postgres_operations.md) for the production procedure and the schema-creation behaviour.

### 0.5.0 → 0.6.0

Tool-call admission lands; schema bumps to 2.2.0 (additive). Pure-retrieval receipts produced under 0.6.0 are byte-equivalent to 2.1.0 receipts modulo the `schema_version` and `issuer` strings. To adopt tool-call admission:

- Add a `tool_call_control:` section to your unified policy YAML.
- Call `provenex.admission_check(tool, request, policy=..., signer=...)` at the admission point in your agent.
- Or use one of the framework wrappers: `ProvenexToolWrapper` (LangChain), `provenex_mcp_admission` (MCP), `provenex_admission_node` (LangGraph), `ProvenexCrewSession.wrap_tool_admission` (CrewAI).

A retrieval-only deployment upgrades to 0.6.0 with no code changes.

### 0.6.0 → 0.6.1 → 0.6.2 → 0.6.3

Framework integrations land (CrewAI session admission, LangGraph admission node, trajectory aggregate summary). No code changes for existing callers; new APIs are additive.

The `provenex audit --trajectory` output gains an aggregate summary block; consumers that parse the `--json` output keep working unchanged because the summary is an additional key.

### 0.6.3 → 0.6.4

Schema bumps to 2.3.0 (additive). Top-level `caller_hash` and optional `trajectory.session_id` appear on receipts produced with a `RequestContext` in scope. No code changes are required; existing callers see the new fields appear automatically.

If you have a downstream consumer that strictly validates the receipt schema, point it at 2.3.0 (it reads any earlier 2.x receipt unchanged).

### 0.6.4 → 0.6.5

Three new convenience entrypoints land:

- `provenex.verify_memory(...)`: memory-read variant of `verify_chunks`.
- `provenex.admit_memory_write(...)`: admission for memory writes; verbatim value redacted by default.
- `provenex.admit_model_inference(...)`: admission for LLM calls; verbatim prompt redacted by default.

`caller_hash_salt` opt-in lands on every emission entrypoint. Without it, `caller_hash` remains bare SHA-256 (the 0.6.4 default).

Postgres-backed deployments on `SQL_ASCII` clusters (macOS `initdb` default) start working correctly without explicit operator action; UTF8 clusters are unaffected. No code changes for existing callers.

### 0.6.5 → 0.6.6

Streaming export sinks land. Receipts continue to flow through the function return value; the `sink=` parameter is additive on every emission entrypoint. Existing callers that do not pass `sink=` see no behaviour change.

To adopt:

```python
from provenex import MultiSink, FileJSONLSink
sink = MultiSink([FileJSONLSink("/var/log/provenex"), ...])
verify_chunks(..., sink=sink)
```

See [streaming_export.md](streaming_export.md).

### 0.6.6 → 0.6.7

OCSF v1.3 mapping lands. `receipt_to_ocsf(receipt_dict)` is pure transformation; `OCSFAdapter(downstream=sink)` is the streaming wrapper. No schema change; OCSF reads existing receipts unchanged. To adopt, point your SIEM-bound sink at an `OCSFAdapter` wrapper.

### 0.6.7 → 0.6.8 → 0.6.9

Documentation and examples land. No code changes.

### 0.6.9 → 0.7.0

The most material upgrade in the 0.x series after 0.5.0 (Postgres) and 0.8.0 (storage layer). Four changes to think about:

**Canonicalisation pin.** `ensure_ascii=False` is now pinned in receipt canonicalisation. ASCII-only receipts produce byte-identical output. **Receipts with non-ASCII content (smart quotes, CJK characters in caller dicts, emoji in `rules_fired`) signed under 0.6.x will not verify under 0.7.0.** If you have historical non-ASCII receipts to re-verify, hold the verifier at 0.6.9 for those receipts, or re-sign under 0.7.0.

**Audit refuses unsigned by default.** `provenex audit receipt.json` used to default to PASS when no key material was available; it now defaults to FAIL with a clear message. Add `--unsigned` to opt back into the prior behavior. CI scripts that audited unsigned receipts must update.

**DeprecationWarnings start firing.** Three things now warn:

- Bare `VerificationPolicy()` (no explicit `block_unverified=`) warns; the default will flip to `True` in a future major. Pass `block_unverified=True` for strict, `block_unverified=False` to silence and keep current behaviour.
- Unsalted `compute_caller_hash(caller)` warns; pass `caller_hash_salt=b"..."` on the emission entrypoint.
- Falling back to `PROVENEX_SIGNING_SECRET` (the legacy shared secret) warns; set `PROVENEX_RECEIPT_SECRET` and `PROVENEX_INDEX_SECRET` instead.

Deprecation warnings are one-per-process; they will not flood your logs.

**Sink errors no longer leak.** `_safe_publish` and `RetryQueueSink` only log the exception class name via `warnings.warn`, not the body. If you were grepping warning bodies for diagnostic detail, switch to a dedicated logger.

### 0.7.0 → 0.7.1

Patch release. Postgres `add()` race fix lands transparently. `matches_pattern` / `not_matches_pattern` cap string inputs at 64 KiB; oversized inputs now fail-closed (the rule fires, the decision is deny). If you had a deployment that was relying on glob-matching multi-MB strings without a length bound, add a companion `length_at_most` rule.

### 0.7.1 → 0.7.2

Patch release. `DECISION_ALLOW_WITH_CONDITIONS` is removed from the public API. The value was never returned by any code path; no caller breakage is expected.

### 0.7.2 → 0.8.0

The most material upgrade in the project's history. **Breaking at the index storage layer.**

**Re-ingest required.** The 0.8.0 storage layer adds an `entry_kind` column inside the canonical row signing payload. Pre-0.8.0 indexes lack the column and refuse to open with a clear error message. The recovery path is to re-ingest the corpus against a fresh 0.8.0 index:

1. Stand up a fresh database (Postgres or a fresh SQLite file).
2. Point a fresh `ProvenanceIndex` at it.
3. Run your existing ingest pipeline against the corpus; `provenex ingest` writes the right `entry_kind` automatically, and the SDK's `index.add(...)` accepts the new `entry_kind=` kwarg with a sensible default.

Old receipts (produced before the upgrade) continue to verify under their signature; the receipts themselves do not change. The index migration is independent of the receipt history.

**Schema bumps to 2.4.0 (additive on the wire).** A 2.3.0 receipt with no `request_binding` and no `entry_kind` on sources is a valid 2.4.0 receipt. A 2.3.0 verifier that ignores unknown fields validates a 2.4.0 receipt unchanged. To produce 2.4.0 receipts, pass `request_text=` to your emission entrypoints; the `request_binding` block lands automatically.

**New CLI subcommands.** `provenex selftest` runs the in-process conformance check (suitable for CI gates). `provenex index audit` lints for supersession-skip and stale documents. Neither breaks existing scripts.

**OSS witness log lands.** `provenex.WitnessLog` is available for operators running the Merkle-backed index who want to close split-view resistance against a key-holder. The operational procedure is in [runbooks/witness_log.md](runbooks/witness_log.md). Optional; non-Merkle deployments are unaffected.

### 0.8.0 → 0.8.1

Patch release. The native YAML evaluator refuses `fnmatch` patterns containing regex-only characters at parse time. A policy that used a regex-shaped pattern by mistake (which would have matched literally rather than as intended) now fails at `provenex policy validate` with a clear error. Fix the pattern; redeploy.

### 0.8.1 → 0.8.2

Patch release. `Ed25519Signer` is now exported from the top-level `provenex` package. Code that imported it as `from provenex.core.ed25519 import Ed25519Signer` continues to work; the top-level import is the recommended form going forward.

## Deprecation policy

How deprecations land and how long they live.

**Warning channel:** `warnings.warn(..., DeprecationWarning, stacklevel=2)`. Warnings fire **once per process** unless the caller has configured `warnings.simplefilter("always")` or similar. Most production deployments see each deprecation once in the application logs and once in CI.

**Timeline.** A deprecation introduced in minor `N.M.0` will be removed at the earliest in major `(N+1).0.0`. We commit to at least one major-version warning window before removal. In practice, deprecations often live longer; the removals happen when a deliberate major bump is otherwise warranted.

**Recommended posture for operators:**

- Treat `DeprecationWarning` as advisory in the short term and operational in the medium term. The warning text names the migration path explicitly; act on it before the next major upgrade.
- In CI, configure `warnings.filterwarnings("error", category=DeprecationWarning)` selectively for test files that exercise the entry points you care about. This surfaces deprecations as test failures rather than buried log lines.
- In production, route `warnings.warn` to your application logger and search for `DeprecationWarning` in log aggregation. One alert per process is enough signal.

**Current active deprecations** (as of 0.8.2):

| Warning | Introduced | Action |
| --- | --- | --- |
| Bare `VerificationPolicy()` with no explicit `block_unverified=` | 0.7.0 | Pass `block_unverified=True` (strict) or `=False` (permissive, explicit). |
| Unsalted `compute_caller_hash(caller)` | 0.7.0 | Pass `caller_hash_salt=b"..."` on the emission entrypoint for per-deployment unlinkability. |
| Fallback to `PROVENEX_SIGNING_SECRET` (legacy shared secret) | 0.7.0 | Set role-specific `PROVENEX_RECEIPT_SECRET` and `PROVENEX_INDEX_SECRET`. |

The warning messages are written to name the migration explicitly; the action column above is the short form.

## Cross-version verification

A receipt produced under any 2.x version verifies under any 2.x binary that holds the same key material. Schema 1.x receipts continue to verify on demand; keep an older SDK around if you have historical 1.x receipts to re-verify (the current SDK only emits 2.x).

For ASCII-only receipts the cross-version verification is unconditional. For receipts with non-ASCII content the 0.6.x to 0.7.0 boundary is meaningful; see the 0.6.9 to 0.7.0 note above.

## Read next

- [CHANGELOG.md](../CHANGELOG.md): every customer-facing change with the version it landed in.
- [receipt_format.md § Schema history](receipt_format.md): the authoritative schema-version table.
- [runbooks/postgres_operations.md](runbooks/postgres_operations.md): the schema-management and rebuild procedures for the 0.8.0 storage-layer change.
- [runbooks/key_rotation.md](runbooks/key_rotation.md): the rotation procedure that pairs with the per-role HMAC env vars introduced in 0.7.0.
