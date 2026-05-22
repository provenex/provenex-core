# DORA Articles 17 to 19: ICT-related incident management

**Source:** Regulation (EU) 2022/2554 of the European Parliament and of the Council of 14 December 2022 on digital operational resilience for the financial sector (DORA), [Articles 17, 18, and 19](https://eur-lex.europa.eu/eli/reg/2022/2554/oj). Authoritative text: the EUR-Lex publication of the regulation.

**Scope:** DORA applies to financial entities in the EU. Articles 17 to 19 require an ICT-related incident management process, classification of incidents, and reporting of major incidents to competent authorities. AI agents that act on behalf of a financial entity are ICT systems under DORA's definitions; their actions can produce ICT-related incidents.

This document maps each provision to the Provenex receipt field or operational artifact that produces evidence for it.

## Article 17: ICT-related incident management process

> Financial entities shall define, establish and implement an ICT-related incident management process to detect, manage and notify ICT-related incidents.

Article 17(2) requires that the process records "all" ICT-related incidents and significant cyber threats. Article 17(3) requires that the process establishes:
- early warning indicators
- procedures to identify, track, log, categorise, and classify
- assignment of roles and responsibilities
- communication plans
- procedures to report to senior management
- response procedures
- root-cause analysis

| Provenex artifact | What it provides for Article 17 |
| --- | --- |
| Signed receipts on every agent action (retrieval, tool call, memory read, memory write, model inference) | Per-event record suitable as input to the incident management process. The receipt is signed at emission; the record cannot be retroactively edited without breaking the signature. |
| `policy.tool_call_control.decisions[*].decision = "deny"` plus `rules_fired` | Early warning indicators: a deny on a high-risk rule is the indicator. SIEM streaming routes denies to the incident triage queue. |
| `trajectory.trajectory_id` + `trajectory.session_id` + `caller_hash` | Tracking, categorisation, classification axes. The same caller across many trajectories is one classification axis; the same rule firing across many callers is another. |
| OCSF v1.3 mapping (`receipt_to_ocsf`, `OCSFAdapter`) | Cross-vendor SIEM compatibility for tying receipts into the financial entity's existing incident management platform. |
| `provenex audit --trajectory <dir>` | Root-cause analysis tool: replays the trajectory from the saved receipts end-to-end. |

## Article 18: classification of ICT-related incidents and cyber threats

> Financial entities shall classify ICT-related incidents and shall determine their impact based on the following criteria:
> (a) the number and/or relevance of clients or financial counterparts affected and...
> (b) the duration of the ICT-related incident...
> (c) the geographical spread...
> (d) the data losses that the ICT-related incident entails...
> (e) the criticality of the services affected...
> (f) the economic impact...

Classification is a financial-entity-internal judgement. The receipt fields that feed each criterion:

| Criterion | Receipt fields that feed it |
| --- | --- |
| 18(a) clients affected | `caller_hash` distinct counts across receipts in the incident window. `policy.*.decisions[*].inputs.request_context.caller` if the operator chose to record the full caller dict. |
| 18(b) duration | `issued_at` on the first and last receipts in the incident window. `trajectory.session_id` correlates per-session duration. |
| 18(c) geographical spread | `policy.*.decisions[*].inputs.request_context.jurisdiction`. Distinct counts across receipts in the window. |
| 18(d) data losses | `sources[*].document_id` plus `sources[*].verification_outcome`. A run of TAMPERED outcomes against a specific `document_id` is a localised data-integrity event. |
| 18(e) criticality of services affected | `actions[*].target_system` plus `actions[*].tool.name`. A run of denies against a specific `target_system` is a localised service event. |
| 18(f) economic impact | Out of scope for Provenex. The receipt records what happened; financial impact is a business-side calculation. |

## Article 19: reporting of major ICT-related incidents

> Financial entities shall report major ICT-related incidents to the relevant competent authority...

Article 19(4) requires that the report include the following information (non-exhaustive): incident description, root cause, impact, mitigations, indicators of compromise.

| Reporting field | Provenex artifact |
| --- | --- |
| Incident description | Trajectory of receipts in the incident window, exported via `provenex audit --trajectory <dir> --json`. |
| Root cause | The first deny receipt in the chain plus the firing rule. `policy.*.policy_version_hash` shows the policy that was in effect. |
| Impact | Classification fields under Article 18 above. |
| Mitigations | A policy change is detectable as a new `policy_version_hash` on subsequent receipts. The "before" and "after" hashes bracket the mitigation. |
| Indicators of compromise | `caller_hash`, `rules_fired`, `actions[*].parameters_hash` (for parameter-based IOCs without storing verbatim parameters), `sources[*].fingerprint`. |
| Signed evidence of the report's contents | A separately-signed bundle of receipts produced by `provenex audit` plus the receipts themselves. The regulator independently re-verifies the bundle. |

## Article 19(8): standardised reporting templates

Article 19(8) requires harmonised reporting standards and templates developed by the ESAs. The receipts produced by Provenex are JSON with a fixed schema (`schema_version`); a wrapper that emits a regulator's template format from a trajectory of receipts is straightforward to write. The receipt fields above are the source material for any such template.

## What this mapping does not cover

- **Operational continuity and disaster recovery** (Article 11 and Chapter II more broadly) are infrastructure properties. Provenex contributes by being a library, not a service: it has no separate failover mode of its own. The deployer's continuity plan covers the rest.
- **Third-party ICT risk management** (Chapter V, including the Register of Information). Provenex is an open-source library; its provenance under DORA's third-party regime depends on how the financial entity classifies it.
- **Threat-led penetration testing** (Chapter IV). Out of scope for receipt-level evidence.

For the cryptographic verification path, see [`docs/regulator_verification.md`](../regulator_verification.md). For incident-time runbooks, see [`docs/runbooks/`](../runbooks/).
