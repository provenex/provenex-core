# EU AI Act Article 12: record-keeping

**Source:** Regulation (EU) 2024/1689 of the European Parliament and of the Council of 13 June 2024 laying down harmonised rules on artificial intelligence (the AI Act), [Article 12](https://eur-lex.europa.eu/eli/reg/2024/1689/oj). Authoritative text: the EUR-Lex publication of the regulation.

**Scope:** Article 12 applies to high-risk AI systems. It requires automatic recording of events ("logs") over the lifetime of the system, with the recording capabilities sized for traceability appropriate to the intended purpose.

This document maps each paragraph of Article 12 to the Provenex receipt field or operational artifact that produces evidence for it. The mapping is technical, not legal; what counts as "appropriate" or "relevant" remains a governance call for the provider or deployer.

## Article 12(1): automatic recording of events

> High-risk AI systems shall technically allow for the automatic recording of events ('logs') over the lifetime of the system.

| Provenex artifact | What it provides |
| --- | --- |
| Signed receipts on every retrieval, tool call, memory read, memory write, and model inference | Per-event record. Each receipt is timestamped (`issued_at`) and signed; receipts are emitted unconditionally on both allow and deny outcomes. |
| `trajectory.trajectory_id` and `trajectory.session_id` on every receipt | Lifecycle correlation. All events produced by one agent run share a `trajectory_id`; events within one logical session share a `session_id`. |
| Receipt sinks (`KafkaSink`, `S3AppendSink`, `SQSSink`, `PubSubSink`, `FileJSONLSink`) | Durable persistence at emission time. Sinks are append-only at the storage layer. |
| [`docs/receipt_retention.md`](../receipt_retention.md) Terraform module | S3 Object Lock + Glacier 7-year retention bucket, suitable for "over the lifetime of the system" requirements. |

## Article 12(2): traceability of relevant events

> The logging capabilities shall enable the recording of events relevant for:
> (a) identifying situations that may result in the AI system presenting a risk within the meaning of Article 79(1) or in a substantial modification;
> (b) facilitating the post-market monitoring referred to in Article 72;
> (c) monitoring the operation of high-risk AI systems referred to in Article 26(5).

| Clause | Provenex artifact |
| --- | --- |
| 12(2)(a) risk situations | Five verification outcomes (`VERIFIED / STALE / UNAUTHORIZED / UNVERIFIED / TAMPERED`) classify each retrieved chunk; policy `decision` (`allow / deny`) plus `rules_fired` classify each tool call, memory write, and model inference. `summary.overall_status` rolls these up per receipt. Substantial-modification detection via `policy.access_control.policy_version_hash` and `policy.tool_call_control.policy_version_hash`: any change to the unified policy produces a new hash; archived receipts make the change point detectable. |
| 12(2)(b) post-market monitoring | Receipts streamed to SIEM via `Sink` interface. OCSF v1.3 mapping (`receipt_to_ocsf` and `OCSFAdapter`) provides cross-vendor SIEM compatibility. `provenex audit --trajectory <dir>` replays a stored trajectory end-to-end. |
| 12(2)(c) monitoring operation | `provenex index audit --threshold-days <n>` catches re-ingest paths that skipped Provenex and would otherwise leave stale rows VERIFIED. `provenex selftest` re-derives every load-bearing property against the installed binary. |

## Article 12(3): biometric-identification specifics

> For high-risk AI systems referred to in Annex III, point 1(a), the logging capabilities shall provide, at a minimum:
> (a) recording of the period of each use of the system (start date and time and end date and time of each use);
> (b) the reference database against which input data has been checked by the system;
> (c) the input data for which the search has led to a match;
> (d) the identification of the natural persons involved in the verification of the results, as referred to in Article 14(5).

Article 12(3) addresses remote biometric identification systems. The receipt fields that correspond, by analogy, are listed below for AI-agent deployments that touch comparable identification flows; deployers should confirm applicability with counsel.

| Clause | Receipt field |
| --- | --- |
| 12(3)(a) period of use | `trajectory.session_id` plus `issued_at` on the first and last receipts in the session. |
| 12(3)(b) reference database | `sources[*].document_id` plus `policy.access_control.policy_id`. For retrieval against external systems, `tool.target_system` on the action. |
| 12(3)(c) input data leading to match | `sources[*].fingerprint` plus `sources[*].entry_kind`; the verbatim chunk text is never stored, only the SHA-256 fingerprint. `request_binding.query_hash` ties the receipt to the triggering query without storing the query text. |
| 12(3)(d) identification of natural persons | `caller_hash` (top-level) plus `policy.*.decisions[*].inputs.request_context.caller`. The caller identifier is recorded; deployers control what subset is captured via the `RequestContext` shape. |

## Article 12(4): retention

Article 12(4) requires keeping the logs for a period appropriate to the intended purpose of the high-risk AI system, and at least six months unless other Union or national law provides otherwise.

| Provenex artifact | What it provides |
| --- | --- |
| Receipt-retention Terraform module ([`docs/receipt_retention.md`](../receipt_retention.md)) | S3 Object Lock in compliance mode, Glacier tier transition, 7-year default retention. Tunable per deployment. |
| `S3AppendSink` with versioning and Object Lock enabled on the destination bucket | Append-only durable storage at emission time; deletion or rewrite is blocked at the storage layer. |
| Hash-chain + Merkle transparency log + `WitnessLog` | Integrity verification across the retention window. A regulator can confirm at any point during the 6+ month period that no receipt was silently dropped, reordered, or rewritten. |

## What this mapping does not cover

- **Article 13 (transparency to deployers)** and **Article 14 (human oversight)** are documentation and design requirements, not record-keeping. Provenex receipts are an input to those requirements; the deployer's user-facing documentation closes the rest.
- **Article 50 (transparency obligations for certain AI systems)** addresses user-facing disclosure. Receipts are not user-facing.
- **Article 72 (post-market monitoring)** is a process requirement. Receipts feed into a post-market monitoring system; they do not constitute one by themselves.

For the technical algorithm an auditor runs against an individual receipt, see [`docs/regulator_verification.md`](../regulator_verification.md). For the trust model an auditor should hold, see [`docs/threat_model.md`](../threat_model.md).
