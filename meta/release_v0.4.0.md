# Release notes — v0.4.0 (draft)

**Headline.** Provenex is the policy enforcement layer for AI data access. Declare your security policy once (in our YAML config, or in OPA/Rego via the commercial adapters) and Provenex enforces it on every retrieval, then emits a cryptographically signed receipt proving which chunks were allowed, which were blocked, and under what policy.

**Buyer framing.** Platform engineering champions (a runtime guardrail they don't have to build). Security signs off (cryptographic enforcement, not promises). Compliance consumes the output (a queryable, exportable, regulator-ready record). Three reinforcing budget lines.

## What's new since 0.3.0

- **Unified `Policy`** (schema 2.0.0). A single top-level `policy` block on every receipt with two subsections:
  - `policy.verification` — the five-outcome gate (always present).
  - `policy.access_control` — the data-access policy decision record (optional, present when an evaluator is configured).
- **Single Python `Policy` object** carrying both halves. `Policy.from_yaml(...)` loads a unified config file. `verify_chunks(policy=policy, request_context=req)` is the canonical entry point.
- **Native YAML data-access DSL** with `when` / `require` rules and operators `in`, `not_in`, `not_older_than`, direct equality. Typos and reserved-but-unimplemented features (`any_of`, `allow_with_conditions`, etc.) fail at load time, never silently allow.
- **Unified YAML config file** — operators author ONE YAML with `verification:` and `access_control:` sections. Either section can be omitted; defaults are sensible and fail closed.
- **`metadata_binding`** per decision (schema 2.1.0): each `chunk_metadata` block on the receipt declares whether it was tag-at-ingest (signed by the index row) or tag-at-evaluate (looked up at decision time). Non-load-bearing for the decision itself; load-bearing for audit trust. `request_context` is always `at_evaluate` and recorded that way.
- **Bloom-filter interface stub**: `BloomFilterIndex` ABC + `NoopBloomFilter` + `BloomAcceleratedIndex` wrapper. The OSS ships the interface so commercial deployments are drop-in; the real high-throughput Bloom implementation ships commercially.
- **CLI:** `provenex policy validate <file>` (CI gate for policy files), `provenex policy hash <file>` (print canonical `policy_version_hash`), `provenex audit --show-policy` (render the unified block).
- **Policy-evaluation benchmark** in `bench/`. The native YAML evaluator runs at **p50 22 µs, p99 38 µs** on a 3-rule HR-corpus policy — well under verification latency, never the bottleneck.

## Schema (breaking, 2.0.0)

The top-level `policy` field changed shape:

| 1.x access path | 2.0.0 access path |
| --- | --- |
| `receipt["policy"]["block_stale"]` | `receipt["policy"]["verification"]["block_stale"]` |
| `receipt["policy"]["block_unauthorized"]` | `receipt["policy"]["verification"]["block_unauthorized"]` |
| *(no equivalent)* | `receipt["policy"]["access_control"]["evaluator"]` |
| *(no equivalent)* | `receipt["policy"]["access_control"]["decisions"][i]` |

The v0.4 SDK emits 2.0.0 receipts only. Historical 1.x receipts remain valid artifacts — keep an older SDK around if you need to re-verify them.

Schema history:

| Version | What it added |
| --- | --- |
| `1.0.0` | Original receipt format. |
| `1.1.0` | `transparency_log` block + per-source `leaf_index` / `inclusion_proof`. |
| `1.2.0` | *Reserved* for a coverage block (chunk-identity-under-drift). |
| `1.3.0` | Optional `trajectory` block (multi-step agentic linkage). |
| `1.4.0` | Per-source `claims[]` and `content_source`. |
| `1.5.0` | (Skipped.) Interim shape that put `access_policy` as a separate top-level block. Never released. |
| `2.0.0` | **Breaking.** Unified `policy` block with `verification` and optional `access_control` subsections. |
| `2.1.0` | Per-decision `metadata_binding` field. Additive. |

## Compatibility

- **Python API.** `verify_chunks(policy=Policy(...))` is the canonical signature. Bare `VerificationPolicy(...)` is still accepted (wrapped internally), so framework-integration users that haven't migrated keep working.
- **Receipts.** 1.x receipts must be verified with the SDK version that produced them. The 2.0.0 SDK reads and writes 2.0.0.
- **Tests.** Baseline was 234 tests; now 300 tests and 1 skip. All existing-feature tests are green.

## Open source (this release) vs commercial

**In the open-source core (MIT):**

- Native YAML DSL evaluator
- Unified `Policy` shape and canonical `policy_version_hash`
- HMAC + Ed25519 signing
- SQLite index + RFC 6962 Merkle transparency log for chunks
- **Bloom-filter interface stub** (`BloomFilterIndex` ABC + no-op + wrapper)
- LangChain / LangGraph / LlamaIndex / CrewAI integrations
- `provenex` CLI: `ingest / verify / receipt / audit / policy`

**Commercial (provenex.ai):**

- **Rego adapter** — load existing Rego bundles via the same `PolicyEvaluator` protocol; emit identical receipt shape.
- **OPA service adapter** — delegate evaluation to a running OPA instance.
- Transparency-log-backed policy bundle records (`policy_in_transparency_log` lights up).
- **Bloom-filter implementation** (OSS ships the interface; commercial ships the working filter for 10M+ chunk scale).
- Compliance-grade export formats (PDF, CSV, JSON-LD).
- Identity-provider integration, HSM-backed signing, SSO/RBAC, SLA, dedicated support.

The interfaces (`ProvenanceIndex`, `PolicyEvaluator`) are the same. Moving from one to the other is one line of code: the class you instantiate.

## Install

```bash
pip install provenex-core                  # core only (pure stdlib)
pip install "provenex-core[policy]"        # + native YAML policy DSL (PyYAML)
pip install "provenex-core[langchain]"     # + LangChain integration
pip install "provenex-core[langgraph]"     # + LangGraph integration
pip install "provenex-core[llamaindex]"    # + LlamaIndex integration
pip install "provenex-core[crewai]"        # + CrewAI integration
pip install "provenex-core[ed25519]"       # + Ed25519 asymmetric signing
```

Core stays pure stdlib. PyYAML lives behind the `[policy]` extra.

## Links

- README: [`README.md`](../README.md)
- Unified policy reference: [`docs/policy.md`](../docs/policy.md)
- Receipt schema 2.0.0: [`docs/receipt_format.md`](../docs/receipt_format.md)
- How it works: [`docs/how_it_works.md`](../docs/how_it_works.md)
- Threat model + trust boundaries: [`docs/threat_model.md`](../docs/threat_model.md)
- Quickstart (incl. Path F: policy-driven retrieval): [`docs/quickstart.md`](../docs/quickstart.md)
- Scaling (incl. policy-eval bench): [`docs/scaling.md`](../docs/scaling.md)

## Items to flag for human review before publishing

- **Repo description / tagline.** The GitHub repo description still reads "Cryptographic provenance verification for RAG pipelines." Update to "Policy enforcement for AI data access, with cryptographic proof." (Requires repo admin.)
- **PyPI badge cache.** Bump `?v=0.4.0` and refresh the Camo cache after publish.
- **Breaking schema.** 2.0.0 receipts won't parse with 0.3.x consumers. If any external service is reading receipts today, give it the migration table from `docs/receipt_format.md` ahead of upgrade.
- **Strategic positioning.** README leads with buyer framing; OSS-vs-commercial split clearly marks Rego/OPA-service as commercial. Confirm this matches the locked architectural decisions before publish.
