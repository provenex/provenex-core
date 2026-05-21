# Failure modes and blast radius

This document is the operator's map of how Provenex behaves when
things go wrong. For each component on the verify / admission hot
path it states the failure behavior, whether the behavior is
operator-configurable, and which runbook covers recovery.

The shorter version: most failures are deliberately fail-closed.
Provenex is a proof system, and a receipt that says `VERIFIED`
when verification could not happen would destroy the signal the
product exists to deliver. The one place we accept a knob is the
provenance index, where a signed `index_status` annotation lets us
issue degraded receipts that are honest about what they could not
check.

## Per-component behavior

| Component | At startup | At runtime | Configurable? | Runbook |
| --- | --- | --- | --- | --- |
| **Provenance index** (Postgres / SQLite) | Refuses to start without a reachable DSN. | `on_index_error: block` raises `IndexUnavailable` → HTTP 503. `on_index_error: degrade` returns a signed receipt with all outcomes `UNVERIFIED` and a top-level `index_status` block. Circuit breaker short-circuits while OPEN. | **Yes.** `policy.availability.on_index_error` (`block` \| `degrade`), `timeout_seconds`, breaker thresholds. Default is `block`. | [runbooks/index_unavailability.md](runbooks/index_unavailability.md) |
| **Receipt signer** (HMAC / Ed25519 / KMS) | Refuses to start without `PROVENEX_RECEIPT_PRIVATE_KEY_FILE`, `PROVENEX_RECEIPT_SECRET`, or `PROVENEX_TENANTS_FILE`. The server will not emit unsigned receipts. | A signing failure propagates as a 5xx. The receipt is not issued. | **No, and intentionally.** "Fail open" here means issuing unsigned receipts, which is unacceptable for a proof system. KMS adapters can be plugged in for HA; see [docs/key_management.md](key_management.md). | [runbooks/key_rotation.md](runbooks/key_rotation.md), [runbooks/disaster_recovery.md](runbooks/disaster_recovery.md) |
| **Policy evaluator, load** (unified YAML) | A policy that fails `Policy.from_yaml(...)` raises `PolicyParseError`. Server refuses to start. In CRD mode the operator patches `status.phase=Rejected` and leaves the prior ConfigMap untouched. | n/a | **No, and intentionally.** A typo in a policy must not silently allow. | [runbooks/bad_policy_rollback.md](runbooks/bad_policy_rollback.md) |
| **Policy evaluator, per-request** (native YAML evaluator) | n/a | The native evaluator is deterministic and side-effect-free over the policy + inputs; it does not throw at runtime in production. A custom evaluator (Rego, OPA service) that throws would surface as a 5xx. | **No.** Failing-open on the access-control gate would defeat the gate. | [runbooks/bad_policy_rollback.md](runbooks/bad_policy_rollback.md) |
| **Verification gate** (`policy.verification`) | n/a | Pure function of `VerificationOutcome` per chunk. Cannot fail at runtime. | n/a | n/a |
| **Transparency / witness log** (commercial) | Server runs without it. | A witness fetch failure does not block the verify path. Receipts continue to issue without inclusion proofs. | Witness URL configured via env; absence means no witness. | [runbooks/witness_log.md](runbooks/witness_log.md) |
| **Tenant signer registry** (multi-tenant mode) | `PROVENEX_TENANTS_FILE` required when in multi-tenant mode. | A request with `X-Provenex-Tenant: <unknown>` returns 404. A request without the header to a multi-tenant-only server returns 503. | Tenant identity is the operator's concern; the server enforces. | [runbooks/disaster_recovery.md](runbooks/disaster_recovery.md) |
| **Streaming export sink** (Kafka / file / stdout) | Sink construction failures surface at startup. | Per-receipt sink failures are swallowed with a `warnings.warn(...)` event and the verify path continues. RetryQueueSink buffers up to its `maxlen`. Failure to publish does NOT block the request. | Sink class is the operator's choice; retry policy lives on the sink. | n/a (no recovery needed, the receipt is still emitted to the caller) |
| **Drift detector webhook** | Optional. Off if `PROVENEX_DRIFT_WEBHOOK_URL` is unset. | Webhook send failures are swallowed; the detector keeps counting. | URL + window + threshold configurable via env. | n/a |
| **Index drift detector → registry** | Optional. | Lookup error short-circuits the warning; no impact on verify. | n/a | n/a |

## Blast-radius table

The matrix below answers: if X fails, what does that do to the rest
of the system? Read across to see which functions stop working,
which degrade, and which keep working untouched.

| Failure | Verify | Tool-call admission | Ingest | `/healthz` | `/readyz` | Receipts already issued |
| --- | --- | --- | --- | --- | --- | --- |
| **Provenance index unreachable** (timeout / connection / pool exhausted) | `block`: 503. `degrade`: signed receipt with all-UNVERIFIED + `index_status`. | Unaffected. Admission decisions do not consult the index. | Fails. The receipt-producing `add_async` path also touches the index. | 200 | 503 (`breaker_open` or `index_unreachable`) | Untouched. Receipt signatures are independent of index state. |
| **Signer key file missing or unreadable at startup** | Server refuses to start. | Server refuses to start. | Server refuses to start. | n/a | n/a | Untouched. |
| **Per-request signing failure** (KMS outage on a KMS-backed signer) | 5xx for the duration. | 5xx for the duration. | Unaffected (ingest does not sign). | 200 | 503 if signer is the blocker. | Untouched. |
| **Policy file parse error at deploy** | Server refuses to start. Operator marks CR Rejected. | Server refuses to start. | Server refuses to start. | n/a | n/a | Untouched. |
| **Policy semantically wrong but parses cleanly** | Wrong decisions ship until rolled back. | Wrong decisions ship until rolled back. | Unaffected. | 200 | 200 | Signed, immutable, and tied to the bad `policy_version_hash`. Identify by hash; see runbook. |
| **Tenant signer not registered** | 404 on the verify call. Other tenants unaffected. | 404. | n/a | 200 | 200 | Untouched. |
| **Witness log fetch failure** | Verify path continues with no inclusion proof on the receipt. | Unaffected. | Unaffected. | 200 | 200 | Untouched. |
| **Streaming sink down** | Verify returns success; the receipt the caller gets is intact. Sink failure is logged. | Same. | n/a | 200 | 200 | Receipts in flight may not have reached the SIEM; replay via the RetryQueueSink or replay from caller-side persistence. |
| **Drift webhook target down** | Unaffected. | Unaffected. | Unaffected. | 200 | 200 | Untouched. |
| **Postgres replica failover** (primary down, replica promoted) | Brief 503 spike (timeout + connection error_class) while the pool reconnects. Breaker may trip and self-recover. | Unaffected. | Brief failure during the same window. | 200 | 503 during the window. | Untouched. |
| **Entire deployment down** (process / node loss) | Total outage. | Total outage. | Total outage. | n/a | n/a | Untouched. Receipts already in the SIEM are verifiable offline by anyone with the public key / shared secret. |

## Fail-open vs fail-closed, the design choice

The product principle: the receipt's claim is the asset. A
`VERIFIED` outcome must mean the index was consulted and the chunk
was present. A `decisions[i].decision=allow` must mean the policy
evaluator agreed. The signer must have signed.

That principle has three implications for failure behavior:

1. **The index can fail-open with an explicit signed annotation, or
   fail-closed entirely.** It is the only component where degraded
   operation has a sensible meaning, because the receipt can still
   carry a useful audit signal (the `index_status` block is signed
   and tamper-evident). Operators choose per deployment; default
   is fail-closed.

2. **The signer cannot fail-open.** "Fail open" here would mean
   issuing receipts without a valid signature, which is
   indistinguishable from receipts forged by an attacker. Hard
   fail-closed at startup and runtime.

3. **The policy evaluator cannot fail-open at load time.** A
   policy that does not parse must not become "allow everything";
   the operator must fix the policy. At runtime the native YAML
   evaluator is pure (it cannot throw), so the runtime question
   does not arise; pluggable evaluators (Rego, OPA service) inherit
   the same "no fail-open" rule by convention. A custom evaluator
   that throws will return 5xx, not allow-by-default.

## Configurable knob

The single operator-controlled fail mode lives on the unified
policy YAML:

```yaml
version: 1
availability:
  on_index_error: block        # "block" (default) or "degrade"
  timeout_seconds: 2.0
  breaker_threshold: 5
  breaker_window_seconds: 30
  breaker_cooldown_seconds: 30
```

See [runbooks/index_unavailability.md](runbooks/index_unavailability.md)
for when to set each, and what the receipts look like in each
mode.

## Companion runbooks

* [runbooks/index_unavailability.md](runbooks/index_unavailability.md): provenance index down or slow.
* [runbooks/bad_policy_rollback.md](runbooks/bad_policy_rollback.md): wrong policy reached production.
* [runbooks/key_rotation.md](runbooks/key_rotation.md): signer rotation, scheduled and emergency.
* [runbooks/disaster_recovery.md](runbooks/disaster_recovery.md): total Postgres loss, signing key compromise, vector-store drift, multi-region replication.
* [runbooks/postgres_operations.md](runbooks/postgres_operations.md): pool sizing, schema checks, vacuum.
* [runbooks/witness_log.md](runbooks/witness_log.md): transparency log gossip and split-view defense.

## What this document does NOT cover

* **Compromise of the signing key.** That is a security incident,
  not a failure mode. See [SECURITY.md](../SECURITY.md) and the
  key-rotation runbook.
* **Compromise of the index itself** (an attacker writes a row).
  The index entry's HMAC signature is part of the verify path,
  so a tampered row surfaces as a `TAMPERED` outcome on the
  receipt rather than a silent VERIFIED. See
  [threat_model.md](threat_model.md).
* **Prompt-injection in retrieved content.** Out of scope by
  design; see [threat_model.md](threat_model.md) for the
  trust-model discussion.
