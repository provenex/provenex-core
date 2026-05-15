# Release notes — v0.6.8

**Headline.** Source-of-record positioning capstone. New canonical doc [`docs/anomaly_detection.md`](docs/anomaly_detection.md) closes the loop on the five-release source-of-record series (0.6.4 → 0.6.8): receipts as the structured event record AI agent anomaly detectors consume. The native YAML DSL's per-decision discipline is now explicitly documented as a load-bearing design choice — trajectory-level rules belong in the commercial Rego adapter or downstream in your detector, not in the per-decision admission engine.

Docs-only release. No code changes, no schema bump, no API change.

## What's new since 0.6.7

### `docs/anomaly_detection.md` — the canonical positioning doc

The capstone document for the source-of-record architecture. ~400 lines. Read this when:

- You're evaluating Provenex alongside a UEBA / SIEM / agent-anomaly-detection tool and want to understand the integration model.
- You're writing detection rules over the receipt stream and need the field reference + worked patterns.
- You're a security architect deciding where the line between "in-engine policy" and "downstream detection" should fall in your stack.

Structure:

1. **What this document is.**
2. **The architecture.** Per-decision admission (Provenex) + sequence/pattern detection (your detector), with the receipt stream as the API between them. ASCII diagram.
3. **Schema field reference for detectors.** Every field a detection rule typically reads, organised into identity/correlation, timing, decision metadata, verification, action identity, and aggregate. Each field has a one-line "what to do with this in detection."
4. **Five worked detection patterns** with receipt-field references and SQL/pseudocode snippets:
    - Pattern 1: Per-caller tool-call rate anomaly
    - Pattern 2: Trajectory shape drift (per-step_kind distribution)
    - Pattern 3: Policy near-miss (rule `when` fires but `require` passes, repeatedly)
    - Pattern 4: Cross-trajectory correlation (memory_write → external tool_call within K seconds)
    - Pattern 5: Content-source anomaly (live_tool_output ratio shifts)
5. **Export shapes.** Raw JSONL vs OCSF v1.3 events, with example SIEM queries for each.
6. **The line we don't cross.** Why per-decision admission and cross-decision detection belong in different engines — operational, audit, and strategic reasoning.
7. **Trust model for the detector.** What the receipt guarantees, what it doesn't, and recommended detector posture (signature verification, at-least-once transport, unsigned-receipt-as-alarm).

### `docs/policy.md` — explicit "deliberately doesn't do" section

The per-decision purity of the native DSL is now documented as a load-bearing design choice, not an unstated implementation property. The new section names exactly what the DSL refuses and the reasons behind each refusal:

- **Trajectory-level rules** — refused because `inputs_hash` would become path-dependent and the audit anchor would collapse.
- **Cross-decision aggregations** — same reason, applied to history.
- **External data lookups during evaluation** — refused because deterministic-per-evaluation requires hermeticity.

Where customers should put those instead:

- Commercial Rego adapter (general-purpose; opt-in audit trade-off).
- Downstream anomaly detector reading the receipt stream (the recommended path for almost every customer; this is what the OCSF export, the streaming sinks, and the new positioning doc all exist to enable).

The "Reserved-but-unimplemented features" list gains a corresponding bullet for trajectory rules, pointing at the design rationale.

### `docs/quickstart.md` Path G — per-decision discipline acknowledgement

A short paragraph at the end of the Phase 2 tool-call admission section clarifies that the DSL's `when` / `require` operators are pure functions of `(tool, request)` by design, and points readers at the new capstone doc when they reach for trajectory-level patterns.

### `README.md` — new positioning section + feature-list bullet

A new top-level subsection ("Provenex is the firewall. Your detector is the SIEM.") makes the architectural split explicit on the front page. The OSS feature list gains a corresponding bullet pointing at the new capstone doc and the policy-design rationale.

## Compatibility

- **No code changes.** Every emission entrypoint, every framework wrapper, every receipt produced by every prior version still behaves identically. Receipts produced under any version since 0.5.0 are usable as detector input under the new positioning.
- **No schema bump.** Wire format stays at 2.3.0.
- **All 7 example demos green** against 0.6.8 (572 tests still passing, including the full Postgres suite).
- **Issuer string bumps** from `provenex-core/0.6.7` to `provenex-core/0.6.8` on new receipts. Older receipts continue to verify.

## The five-release source-of-record series, closed

This is the final release in the series the brief outlined. Recap:

- **0.6.4** — schema 2.3.0: `caller_hash` + `session_id` correlation fields.
- **0.6.5** — step-kind coverage: `verify_memory` / `admit_memory_write` / `admit_model_inference`. `caller_hash` salt for per-deployment unlinkability. Postgres backend UTF8 hardening.
- **0.6.6** — streaming export sinks: `ReceiptSink` Protocol + reference sinks (StdoutJSONLSink / FileJSONLSink / MultiSink / RetryQueueSink in stdlib; KafkaSink / SQSSink / S3AppendSink / PubSubSink behind extras). `sink=` on every emission entrypoint.
- **0.6.7** — OCSF v1.3 mapping: `receipt_to_ocsf()` + `OCSFAdapter`. Public mapping spec in `docs/ocsf_mapping.md`.
- **0.6.8** — positioning capstone: `docs/anomaly_detection.md` + per-decision-discipline rationale in `docs/policy.md`. Source-of-record story complete.

## Install

```bash
pip install provenex-core==0.6.8
pip install "provenex-core[policy]==0.6.8"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[postgres]==0.6.8"      # Postgres backend (UTF8-hardened)
pip install "provenex-core[langgraph]==0.6.8"     # LangGraph nodes
pip install "provenex-core[crewai]==0.6.8"        # CrewAI session + admission
pip install "provenex-core[langchain]==0.6.8"     # LangChain retriever + admission wrapper
pip install "provenex-core[ed25519]==0.6.8"       # asymmetric receipt signing
pip install "provenex-core[export-kafka]==0.6.8"  # KafkaSink (kafka-python)
pip install "provenex-core[export-aws]==0.6.8"    # SQSSink / S3AppendSink (boto3)
pip install "provenex-core[export-gcp]==0.6.8"    # PubSubSink (google-cloud-pubsub)
```
