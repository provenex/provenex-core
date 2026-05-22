# Kubernetes deployment

End-to-end walkthrough of the Helm chart, with sizing notes that match
the bench numbers in [docs/scaling.md](scaling.md).

## What you get

The chart in [deploy/helm/provenex-server/](../deploy/helm/provenex-server/)
includes:

- `Deployment` for verify pods (the FastAPI server)
- `Service` (ClusterIP)
- `HorizontalPodAutoscaler` (CPU-driven)
- `PodDisruptionBudget`
- `NetworkPolicy` (deny-by-default ingress, egress only to Postgres + DNS)
- `CronJob` for the witness publisher (optional)
- `CronJob` for the ingester (optional)
- The bundled Bitnami Postgres subchart for dev / kind clusters

## Walkthrough

### Prerequisites

- Kubernetes 1.25+
- Helm 3.10+
- An existing namespace (e.g. `provenex`) and a Secret with the
  signing keys

### Create the signing-key Secret

For HMAC (dev / single-tenant):

```bash
kubectl create namespace provenex
kubectl -n provenex create secret generic provenex-signing \
    --from-literal=index_secret="$(openssl rand -base64 32)" \
    --from-literal=receipt_secret="$(openssl rand -base64 32)"
```

For Ed25519 (production):

```bash
openssl genpkey -algorithm ED25519 -out receipt.ed25519.pem
kubectl -n provenex create secret generic provenex-signing \
    --from-literal=index_secret="$(openssl rand -base64 32)" \
    --from-file=receipt_ed25519_pem=./receipt.ed25519.pem
shred -u receipt.ed25519.pem    # the only place the key lives is in the Secret
```

### Install (dev / kind)

```bash
cd deploy/helm/provenex-server
helm dependency update
helm install -n provenex provenex .
```

Smoke-test:

```bash
kubectl -n provenex port-forward svc/provenex-provenex-server 8080:8080 &
curl -s http://localhost:8080/healthz
curl -X POST http://localhost:8080/v1/verify \
    -H 'Content-Type: application/json' \
    -d '{"chunks":["hello"]}' | jq
```

### Install (production)

```bash
# External Postgres DSN as a Secret:
kubectl -n provenex create secret generic provenex-dsn \
    --from-literal=dsn="postgresql://provenex:...@pgbouncer.internal:6432/provenex"

helm install -n provenex provenex deploy/helm/provenex-server \
    -f deploy/helm/provenex-server/values-large.yaml \
    --set externalDsnSecret=provenex-dsn \
    --set secrets.receiptHmacKey="" \
    --set secrets.receiptEd25519Key=receipt_ed25519_pem
```

The `values-large.yaml` profile targets a 500 RPS / 10M-chunk
deployment: 10 verify pods minimum, HPA up to 60 replicas, external
Postgres assumed.

## Sizing guide

Working backwards from the bench numbers:

| Verify-batch p50 (warm, k=10) | 461 µs |
| Single Postgres backend ceiling | ~2.2k ops/sec (4 readers saturate) |
| 10-conn pool throughput | ~2k ops/sec / pod |
| Receipts per RAG retrieval | 1 per top-k call |

So a single verify pod at warm cache serves ~2k retrievals/sec.

| Workload shape | Replicas | Pool size / pod | PgBouncer pool | Postgres readers |
|---|---|---|---|---|
| Dev / kind | 1-3 | 1-10 | n/a | bundled Postgres |
| 50 RPS / 1M chunks | 3 | 1-10 | optional (25) | 1 primary, no replicas |
| 200 RPS / 1M chunks | 5-10 | 5-10 | yes (50) | 1 primary, 1 replica |
| 500 RPS / 10M chunks | 10-30 | 10 | yes (100) | 1 primary, 2 replicas |
| 2k RPS / 10M chunks | 30-60 | 10 | yes (200) | 1 primary, 4 replicas |

These are starting points. The bench in
[docs/scaling.md](scaling.md#postgres-at-scale-measured-1m-chunks)
is the source for the per-pod number; the rest is multiplication and
the PgBouncer + replica advice from the deployment-patterns section.

## Health, readiness, and metrics

- `GET /healthz`: liveness probe; cheap, no Postgres round-trip.
- `GET /readyz`: readiness probe; does a sentinel
  `verify_async` so it fails fast if the pool is broken.
- `GET /metrics`: Prometheus text format. Always-on; no separate
  scrape-config gate.

The Deployment template auto-annotates pods with
`prometheus.io/scrape=true` so annotation-driven Prometheus picks
them up automatically. For a ServiceMonitor-based setup, wire the
chart's metrics port (8080) into your existing monitor template.

## Rolling out a policy change

The recommended shape is the Policy CRD: apply a Policy CR, the
operator reconciles the ConfigMap, the verify pods roll over on next
pod restart. The chart's deployment.yaml mounts the
ConfigMap read-only at `/etc/provenex/policy.yaml`; `PROVENEX_POLICY_FILE`
is set to that path when `policyConfigMap.enabled=true`.

For an emergency tighten (the operator is unavailable), edit the
ConfigMap directly and `kubectl rollout restart deploy/provenex-server`.

## What this chart does NOT cover

- Service mesh / mTLS between pods. Plug your existing Istio / Linkerd
  config in; the NetworkPolicy is independent.
- External Secrets Operator integration. The chart reads from a
  named Secret; ESO + a `SecretStore` pointing at AWS Secrets
  Manager / Vault / etc. is one common shape, but the chart doesn't
  enforce it.
- Multi-tenant ingress (Pattern C with per-tenant routing). The
  signer registry is server-side; the chart deploys one Service.
  Per-tenant ingress is handled at your gateway.
