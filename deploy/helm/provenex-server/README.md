# provenex-server Helm chart

Helm chart for the Provenex HTTP server. Stands up:

- a verify `Deployment` (horizontally scaled, HPA + PDB attached)
- an ingester `CronJob` (off by default)
- a witness-publisher `CronJob` (off by default; placeholder, see Known gaps)
- a `Service` and a `NetworkPolicy` (deny-by-default ingress + egress)
- the bundled Postgres subchart for dev / kind clusters

The signing key is read from a `Secret` you provide. The chart never
holds the key material.

## Maturity

This chart shipped in v0.9.0. It is **Beta**: tested against `kind` and
documented for production shape, but it has limited production hours
in third-party environments. Treat it as a starting point you can
customize, not a turnkey artifact. Concretely:

- The server container image is published to GitHub Container Registry
  as `ghcr.io/provenex/provenex-server:<version>`. It is built
  multi-arch (linux/amd64 + linux/arm64) on every tag, and signed
  with cosign keyless via the GitHub Actions OIDC identity (no
  long-lived signing key). Verify on pull with:
  ```bash
  cosign verify ghcr.io/provenex/provenex-server:0.10.1 \
    --certificate-identity 'https://github.com/provenex/provenex-core/.github/workflows/release.yml@refs/tags/v0.10.1' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
  ```
- The **operator image** `provenex/provenex-operator:<version>` is not
  yet built or published. Operator users must build it themselves
  (Dockerfile not yet shipped) or stick with the in-cluster `kopf` CLI
  path. Tracked for v0.11.
- Image references are by tag, not by digest. Pin to digests for
  production rollouts.
- No `values.schema.json`: typos in your values overrides go undetected
  until `helm install` fails or behavior surprises you.
- No `ServiceMonitor` template: the chart relies on
  `prometheus.io/scrape` annotations. Prometheus-Operator users will
  need to add their own `ServiceMonitor` CR.
- No `PodAntiAffinity` or `TopologySpreadConstraints`: all replicas can
  land on the same node, defeating the PDB during node drains.
- The bundled `bitnami/postgresql` subchart uses a hardcoded weak
  password (`provenex-dev-only`) suitable only for kind and CI. Switch
  to `externalDsnSecret` for any environment with real data.
- The witness-publisher `CronJob` is a template placeholder; the
  `provenex witness publish` CLI subcommand it expects is not yet
  implemented. Leave `witness.enabled=false` until v1.0.

Production deployments should expect to read the templates and adapt
them. They are short on purpose.

## Install (kind / dev)

```bash
helm dependency update deploy/helm/provenex-server  # pull bitnami/postgresql

kubectl create secret generic provenex-signing \
    --from-literal=index_secret=dev-index-secret \
    --from-literal=receipt_secret=dev-receipt-secret

helm install provenex deploy/helm/provenex-server

kubectl port-forward svc/provenex-provenex-server 8080:8080 &
curl -X POST http://localhost:8080/v1/verify \
    -H 'Content-Type: application/json' \
    -d '{"chunks":["hello"]}' | jq
```

## Install (production, external Postgres + Ed25519 keys)

```bash
kubectl create secret generic provenex-dsn \
    --from-literal=dsn="postgresql://provenex:...@db.internal:6432/provenex"

kubectl create secret generic provenex-signing \
    --from-literal=index_secret="$(openssl rand -base64 32)" \
    --from-file=receipt_ed25519_pem=./receipt.ed25519.pem

helm install provenex deploy/helm/provenex-server \
    -f deploy/helm/provenex-server/values-large.yaml \
    --set externalDsnSecret=provenex-dsn \
    --set secrets.receiptHmacKey="" \
    --set secrets.receiptEd25519Key=receipt_ed25519_pem \
    --set 'networkPolicy.databaseEgressCIDRs={10.0.0.0/16}' \
    --set networkPolicy.monitoringNamespace=monitoring
```

`networkPolicy.databaseEgressCIDRs` is required when the database is
external (RDS, Cloud SQL, Crunchy, self-managed). The default
NetworkPolicy egress block only matches pods labelled
`app.kubernetes.io/name=postgresql`, which works for the bundled
subchart but not for a managed service outside the cluster.

`networkPolicy.monitoringNamespace` is required if you want Prometheus
in another namespace to scrape `/metrics`. Without it the default
ingress rule limits scrape access to pods labelled `provenex-client`.

## Sizing

| Profile | `values` file | Replicas | HPA max | Notes |
|---|---|---|---|---|
| Default | `values.yaml` | 3 | 20 | 50 RPS / 1M chunks; bundled Postgres on. |
| Large | `values-large.yaml` | 10 | 60 | 500 RPS / 10M chunks; expects external Postgres + PgBouncer. |

See [docs/scaling.md#postgres-at-scale-measured-1m-chunks](../../../docs/scaling.md#postgres-at-scale-measured-1m-chunks) for the per-pod throughput numbers that back these defaults.

## Customization knobs added in v0.10.1

- `networkPolicy.databaseEgressCIDRs` (list of CIDRs): egress rules for
  external databases. Empty by default.
- `networkPolicy.databaseEgressPort` (int, default 5432): port for the
  CIDR egress rule above.
- `networkPolicy.monitoringNamespace` (string): namespace to allow
  ingress from for `/metrics` scraping. Empty disables the rule.
- `networkPolicy.extraIngress` and `networkPolicy.extraEgress` (list):
  free-form rules merged into the generated NetworkPolicy for
  topologies the defaults do not cover.

## Known gaps (v0.10.1)

| Gap | Workaround | Tracked for |
|---|---|---|
| Operator image not on a public registry | Build + push to your own registry; only the server image is on GHCR today | v0.11 |
| Image tags, not digests | Pin manually via `image.tag` or templating | v0.11 |
| No `values.schema.json` | None; read templates carefully | v0.11 |
| No `ServiceMonitor` template | Apply your own `ServiceMonitor` CR | v0.11 |
| No `PodAntiAffinity` / TopologySpreadConstraints | Add via Helm post-renderer | v1.0 |
| Bundled Postgres weak password | Use `externalDsnSecret` for anything beyond dev | n/a |
| `witness.enabled=true` blocked at render time | Wait for `provenex witness publish` CLI in v1.0 | v1.0 |
| Operator has no leader election | Run replicas=1 (already the default) | v1.0 |

## Raw manifests

If you don't run Helm, the same shape lives under
[deploy/manifests/](../../manifests/) as plain YAML. The raw manifests
do not include the new `networkPolicy.databaseEgressCIDRs` block; edit
the NetworkPolicy section directly for your environment.
