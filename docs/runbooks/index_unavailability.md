# Runbook: provenance index unavailable

This runbook covers the case where the provenance index (Postgres
in self-hosted deployments) becomes unreachable or slow on the
verify hot path. It does not cover total data loss; see
[disaster_recovery.md](disaster_recovery.md) for that case.

## TL;DR

* Default behavior is **fail-closed**: the verify call raises
  `IndexUnavailable`, the HTTP server returns 503, the caller
  decides what to do next.
* Operators who would rather keep serving with a degraded receipt
  set `policy.availability.on_index_error: degrade`. Every chunk's
  outcome becomes `UNVERIFIED` and the receipt carries a signed
  top-level `index_status` block so an auditor can tell the
  degraded case apart from genuine misses.
* A per-replica circuit breaker trips after enough consecutive
  failures and short-circuits while OPEN. `/readyz` reflects
  breaker state.

## Symptoms

| What you see | Likely cause |
| --- | --- |
| `503 {"error": "index_unavailable", "error_class": "timeout"}` | The verify call ran longer than `availability.timeout_seconds`. Postgres slow query, pool exhaustion, network latency. |
| `503 {"error": "index_unavailable", "error_class": "connection"}` | Pool refused or dropped the connection. Postgres restart, network blip, DNS, or pool sized too small for traffic. |
| `503 {"error": "index_unavailable", "error_class": "breaker_open"}` | This replica's circuit breaker is OPEN. Past failures have tripped it; further calls are short-circuited until cooldown. |
| `/readyz` 503 with `{"error": "breaker_open"}` | Same. The replica is alive but cannot currently issue VERIFIED receipts. Load balancers should route around it. |
| Receipts with `index_status.available: false` flowing into your SIEM | The deployment is in `degrade` mode and the index was unavailable when those receipts were issued. |
| `provenex_index_error_total{error_class="..."}` rising | The wrapper is catching index failures. Each label tells you which class. |
| `provenex_verify_degraded_total{error_class="..."}` rising | The deployment is in `degrade` mode AND is actively issuing degraded receipts. If you set `block`, this counter is always zero. |

## Configuration knob

The `availability:` block on the unified policy YAML controls the
behavior. Defaults shown:

```yaml
version: 1
availability:
  on_index_error: block        # "block" (default) or "degrade"
  timeout_seconds: 2.0         # per-call timeout on the async path
  breaker_threshold: 5         # failures in window before OPEN
  breaker_window_seconds: 30
  breaker_cooldown_seconds: 30
```

* `on_index_error: block` (default, fail-closed) — the verify call
  raises `IndexUnavailable`; the HTTP server returns 503. Use this
  when a receipt that says VERIFIED must mean the index was
  consulted. Right for regulated workloads, paid customer-facing
  inference, and most production deployments.
* `on_index_error: degrade` (fail-open with a signed degraded
  receipt) — every chunk's outcome becomes `UNVERIFIED` and the
  receipt's signed `index_status` block records the failure. Use
  this for read-mostly workloads where the agent must keep moving
  and the audit trail matters more than the gate.

A third mode, `cache_only`, is reserved but not implemented in this
release.

## What `/readyz` means in this design

* `/healthz` returns 200 whenever the process is up. It does NOT
  consult the index. Use it as the kubelet liveness probe.
* `/readyz` returns 200 only when the index is reachable AND the
  circuit breaker is closed. Returns 503 otherwise with a
  structured detail explaining which check failed. Use it as the
  kubelet readiness probe so traffic routes away from a replica
  that cannot currently issue VERIFIED receipts.

A replica with the breaker OPEN is alive but degraded. If you run
in `block` mode, every request to it will 503; if you run in
`degrade` mode, every receipt it issues will carry `index_status`.

## Triage procedure

1. **Check `/readyz` on each replica.**
   * All replicas returning 200 with `breaker_state=closed` — the
     index is healthy; the alert was likely a brief spike.
   * Some replicas 503 with `breaker_open` — those replicas saw
     enough failures to trip. Investigate per-replica logs and
     pool state. The remaining replicas may still be healthy.
   * All replicas 503 with `index_unreachable` — the Postgres
     instance is the problem. Jump to step 4.

2. **Look at the metrics.**
   * `provenex_index_error_total{error_class="timeout"}` rising —
     queries are slow. Increase `timeout_seconds`, scale the pool
     up (`PROVENEX_POOL_MIN` / `PROVENEX_POOL_MAX`), or investigate
     Postgres performance.
   * `provenex_index_error_total{error_class="connection"}` rising
     — the pool can't talk to Postgres at all. Network / DNS /
     credentials.
   * `provenex_index_error_total{error_class="breaker_open"}` rising
     — the breaker is doing its job; the underlying problem is
     whichever class spiked first.

3. **Decide whether to flip to `degrade` mode.** This is an
   operational decision, not a permanent one:
   * If receipts in this window must be verifiable for compliance
     — leave it on `block`. Customers / agents will see 503s.
     Resolve the underlying issue, then traffic resumes.
   * If the audit trail is the goal and gating is secondary —
     temporarily set `on_index_error: degrade` in the policy YAML
     and restart (or hot-reload, if your deployment supports it).
     Every receipt issued during the outage will carry
     `index_status.available=false` and remain
     cryptographically valid. When the index returns, switch back.

4. **Postgres-side recovery.** See
   [postgres_operations.md](postgres_operations.md) for connection
   pool sizing, replica failover, and the `provenex_fingerprints`
   schema integrity checks.

5. **Bring the breaker back.** Once the index is healthy:
   * Wait for `breaker_cooldown_seconds` to elapse, or restart the
     replica to reset breaker state immediately.
   * The first call after cooldown is a HALF_OPEN probe. If it
     succeeds, the breaker closes; if it fails, the breaker
     re-OPENs for another cooldown.

## What an auditor sees on a degraded receipt

A receipt issued in `degrade` mode while the index was unavailable
looks like a normal 2.5.0 receipt with one additional top-level
block:

```json
{
  "schema_version": "2.5.0",
  "...": "...",
  "sources": [
    { "fingerprint": "sha256:...", "verification_outcome": "UNVERIFIED", "...": "..." }
  ],
  "index_status": {
    "available": false,
    "error_class": "timeout"
  },
  "signature": { "algorithm": "...", "value": "..." }
}
```

The `index_status` block is covered by the receipt signature. A
downstream SIEM or anomaly detector should treat
`index_status.available=false` as a strong signal — the receipt
is NOT evidence of verification; it is evidence that verification
could not happen, with the time and (via the signature) the
issuing replica's signer recorded. Distinguish from a healthy
receipt where every source happens to be UNVERIFIED (that case
has no `index_status` block).

## Customer-facing message

If you are running `block` mode and customers are seeing 503s, the
honest message is:

> The Provenex provenance index is currently unreachable from this
> deployment. We are not issuing verified receipts during the
> outage rather than issuing receipts we cannot stand behind. New
> requests will resume as soon as the index recovers; in-flight
> traffic from the previous minutes should be retried.

If you are running `degrade`, receipts continue to flow and carry
the `index_status` annotation. Downstream consumers SHOULD inspect
the field; we surface it in OCSF mapping and in our example
streaming-export integrations.

## Related runbooks

* [disaster_recovery.md](disaster_recovery.md) — total index loss,
  signing key compromise, multi-region replication.
* [postgres_operations.md](postgres_operations.md) — pool sizing,
  schema checks, vacuum.
* [key_rotation.md](key_rotation.md) — signer rotation.
* [witness_log.md](witness_log.md) — split-view defense via the
  transparency log.
