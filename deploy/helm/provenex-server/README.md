# provenex-server Helm chart

Helm chart for the Provenex HTTP server. Stands up:

- a verify `Deployment` (horizontally scaled, HPA + PDB attached)
- an ingester `CronJob` (off by default; enable in `values-large.yaml`)
- a witness-publisher `CronJob` (off by default)
- a `Service` and a `NetworkPolicy` (deny-by-default ingress + egress)
- the bundled Postgres subchart for dev / kind clusters

The signing key is read from a `Secret` you provide. The chart never
holds the key material.

## Install (kind / dev)

```bash
helm dependency update deploy/helm/provenex-server  # pull bitnami/postgresql

# Create the signing secret (HMAC, dev-only — use Ed25519 in prod):
kubectl create secret generic provenex-signing \
    --from-literal=index_secret=dev-index-secret \
    --from-literal=receipt_secret=dev-receipt-secret

helm install provenex deploy/helm/provenex-server

# Smoke test:
kubectl port-forward svc/provenex-provenex-server 8080:8080 &
curl -X POST http://localhost:8080/v1/verify \
    -H 'Content-Type: application/json' \
    -d '{"chunks":["hello"]}' | jq
```

## Install (production, external Postgres + Ed25519 keys)

```bash
# Create the DSN secret out-of-band:
kubectl create secret generic provenex-dsn \
    --from-literal=dsn="postgresql://provenex:...@db.internal:6432/provenex"

# Create the signing secret with an Ed25519 private key:
kubectl create secret generic provenex-signing \
    --from-literal=index_secret="$(openssl rand -base64 32)" \
    --from-file=receipt_ed25519_pem=./receipt.ed25519.pem

helm install provenex deploy/helm/provenex-server \
    -f deploy/helm/provenex-server/values-large.yaml \
    --set externalDsnSecret=provenex-dsn \
    --set secrets.receiptHmacKey="" \
    --set secrets.receiptEd25519Key=receipt_ed25519_pem
```

## Sizing

| Profile | `values` file | Replicas | HPA max | Notes |
|---|---|---|---|---|
| Default | `values.yaml` | 3 | 20 | 50 RPS / 1M chunks; bundled Postgres on. |
| Large | `values-large.yaml` | 10 | 60 | 500 RPS / 10M chunks; expects external Postgres + PgBouncer. |

See [docs/scaling.md#postgres-at-scale-measured-1m-chunks](../../../docs/scaling.md#postgres-at-scale-measured-1m-chunks) for the per-pod throughput numbers that back these defaults.

## Raw manifests

If you don't run Helm, the same shape lives under
[deploy/manifests/](../../manifests/) as plain YAML.
