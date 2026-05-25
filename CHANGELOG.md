# Changelog

All notable customer-facing changes to provenex-core are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/).
Package versions follow [Semantic Versioning](https://semver.org/); the
on-the-wire receipt format follows its own schema-semver, tracked in
[docs/receipt_format.md](docs/receipt_format.md).

## [Unreleased]

## [1.0.0] - 2026-05-25

The first stable release. Two breaking defaults change in this release: the operating posture (was always-block, now record-only) and the default signer (was HMAC, now Ed25519). Receipt schema bumps from 2.5.0 to 2.6.0 additively. Existing 0.x receipts continue to verify under 1.0.0 unchanged.

### Why 1.0.0, not 0.11.0

Two reasons. First, the default behaviour of the engine changes: in 0.x the engine always dropped chunks that failed verification or access control; in 1.0.0 the default is `receipts_only`, which records the decision on the signed receipt but passes every chunk through to the LLM. Operators upgrading without reading this CHANGELOG will see their existing receipts unchanged but their pipelines stop blocking chunks. Second, `cryptography` moves from the `[ed25519]` extra into the base dependencies; the "pure-stdlib core" framing of 0.x is no longer accurate. Both changes are honest semver-major events.

### Added
- **Three operating modes** controlling whether the engine acts on policy decisions or only records them on the receipt.
  - `receipts_only` (new default): receipt records what the policy would have done; every chunk passes through; tool calls always admit. Lowest-friction onboarding posture.
  - `advisory`: same data-path semantics as `receipts_only`, plus invokes `Policy.advisory_callback` with a structured event each time a chunk or tool call would have been blocked. Default callback logs at `WARNING` to the `provenex.advisory` logger; pass your own callback for richer routing.
  - `enforce`: the 0.x behaviour. Drop blocked chunks, deny denied tool calls.
- **`Policy.mode` field** with the three string constants `MODE_RECEIPTS_ONLY`, `MODE_ADVISORY`, `MODE_ENFORCE` exported from `provenex`. The mode is also a valid top-level key in the unified YAML.
- **`policy.mode` in the canonical signed payload** (schema 2.6.0). The operating posture at decision time is itself tamper-evident: a verifier can read the mode off the receipt and refuse to trust receipts produced in `receipts_only` for compliance contexts that require enforcement.
- **`resolve_default_signer()`** factory function. Reads `PROVENEX_RECEIPT_PRIVATE_KEY_PATH` (Ed25519 PEM file) first, falls back to `PROVENEX_RECEIPT_SECRET` (HMAC), refuses to silently invent a transient keypair. Examples and the CLI use this helper.
- **`Ed25519Signer.from_env()`** class method. Reads `PROVENEX_RECEIPT_PRIVATE_KEY_PATH`. Convenience for the common case.
- **`provenex keys generate --output-dir keys/`** CLI subcommand. Writes a fresh Ed25519 keypair: `private.pem` mode `0600`, `public.pem` mode `0644`. Refuses to overwrite without `--force`. Prints the `export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=...` line to copy.

### Changed
- **Default signer is now Ed25519** rather than HMAC-SHA256. HMAC is still selectable explicitly via `HmacSha256Signer()` or by setting `PROVENEX_RECEIPT_SECRET` instead of `PROVENEX_RECEIPT_PRIVATE_KEY_PATH`. Receipts that cross an organisational boundary should always be Ed25519-signed (the verifier holds only the public key and cannot forge); HMAC remains useful for in-house pipelines where the same team produces and verifies.
- **`cryptography>=42.0` moves into the base dependencies.** The 0.x `[ed25519]` extra still exists as a no-op alias for backwards compatibility with `pip install "provenex-core[ed25519]"`. The "pure-stdlib core" framing is retired; in exchange Ed25519 works out of the box and the regulator-handoff story is the documented default.
- **Receipt schema 2.5.0 → 2.6.0** (additive). New optional `policy.mode` field. Pre-1.0.0 receipts without `policy.mode` remain valid 2.5.0 subsets and verify byte-identically.
- **Default `VerificationPolicy` is unchanged** at the field level, but in combination with `mode=receipts_only` the engine no longer drops chunks unless you opt in to `mode="enforce"`.
- **CHANGELOG entry style**: this release uses a single block at the top rather than splitting Added / Changed / Fixed under several version tags. The 0.x entries below are unchanged.

### Upgrading from 0.x

The most common surprise will be that retrieval receipts now look the same but chunks that previously got blocked now reach the LLM. To restore 0.x semantics, set the mode explicitly:

```python
from provenex import Policy, MODE_ENFORCE
policy = Policy(mode=MODE_ENFORCE, ...)
```

Or in the unified YAML:

```yaml
mode: enforce
verification: { ... }
access_control: { ... }
```

If you want to keep your existing HMAC signer (no migration needed):

```python
from provenex import HmacSha256Signer
signer = HmacSha256Signer()   # still reads PROVENEX_RECEIPT_SECRET
```

If you want to switch to Ed25519 (recommended for any deployment that may share receipts with auditors):

```
provenex keys generate --output-dir keys/
export PROVENEX_RECEIPT_PRIVATE_KEY_PATH=keys/private.pem
```

The standalone [`provenex-verifier`](https://github.com/provenex/provenex-verifier-python) library only accepts Ed25519 receipts; that is the right cue if you ever plan to hand receipts to a third party.

### Verifier compatibility

`provenex-verifier` 1.0.0 already accepts 2.6.0 receipts: it canonicalises the entire `policy` block (including the new `mode` field) as part of the signed payload, so the signature still verifies. No verifier update needed.

## [0.10.1] - 2026-05-21

This is a release-machinery patch on top of 0.10.0. No schema change,
no public API change. The release exists to populate the container
image on GitHub Container Registry and to ship the Helm chart
hardening from the same-day session.

### Added
- **Container image published to GHCR**. `ghcr.io/provenex/provenex-server:<version>` is built multi-arch (linux/amd64 + linux/arm64) on every release tag by `.github/workflows/release.yml`, signed with cosign keyless via the GitHub Actions OIDC identity (no long-lived signing key), with image SBOM and SLSA build provenance attached to the manifest. Verify with `cosign verify ghcr.io/provenex/provenex-server:0.10.1 --certificate-identity '...' --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'`. See [docs/supply_chain.md](docs/supply_chain.md).
- **Helm chart `networkPolicy` knobs**: `databaseEgressCIDRs`, `databaseEgressPort`, `monitoringNamespace`, `extraIngress`, `extraEgress`. The default chart NetworkPolicy now works for both bundled-Postgres dev and external managed Postgres production paths (previously the egress block was broken for non-pod databases).
- **Helm chart maturity disclosure** at the top of `deploy/helm/provenex-server/README.md` listing known gaps (no `values.schema.json`, no `ServiceMonitor` template, no `PodAntiAffinity`, operator image not yet on a public registry) with workarounds and tracked release.
- **`SECURITY.md` key inventory** clarifies the four distinct keys in the Provenex world (disclosure key, per-customer receipt signer, per-customer index-row signer, PyPI release attestation) with an explicit "two footguns to avoid in production" subsection covering the legacy shared-secret env var and HMAC's lack of non-repudiation against the verifier.
- **`docs/supply_chain.md`**: reproducible-build gap documented explicitly (identity attestation vs SLSA L3 byte-reproducibility); PyPI typosquat awareness section listing the names we own (`provenex-core`, `provenex`) vs plausible names we do not (`provenex-sdk`, `provenex-client`, etc.); container-image verification recipe.

### Changed
- **Helm chart**: CronJob templates (`ingester`, `witness`) now carry the same container-level `securityContext` (`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`) and resource requests/limits as the verify Deployment.
- **Helm chart**: the `witness` CronJob template now `{{ fail ... }}` at render time when `witness.enabled=true`, because the `provenex witness publish` CLI subcommand it references is not yet implemented. Surfaces the gap loudly rather than letting the CronJob fire and fail at runtime.
- **Helm chart `_helpers.tpl`**: emits `PROVENEX_INDEX_SECRET` (the recommended role-specific env var) rather than the legacy `PROVENEX_SIGNING_SECRET`. Eliminates the deprecation warning at server startup and models the recommended separated-secret posture.
- **Raw manifests** at `deploy/manifests/provenex-server.yaml`: same `PROVENEX_INDEX_SECRET` switch.
- **Operator Deployment** at `deploy/operator/operator.yaml`: liveness + readiness probes wired to kopf's built-in `--liveness` endpoint; container-level `securityContext` consistent with the verify Deployment; pod-level `runAsGroup` + `fsGroup`.
- **Examples** `standalone_demo.py`, `attack_thwarted_demo.py`, `basic_langchain_rag.py`: switched run-hint env vars to `PROVENEX_INDEX_SECRET` + `PROVENEX_RECEIPT_SECRET` instead of the deprecated shared `PROVENEX_SIGNING_SECRET`. `attack_thwarted_demo.py` install hint references `pip install "provenex-core[langchain]"` instead of `pip install langchain-core` directly.

### Fixed
- **`scripts/check_docs_consistency.py`**: image-tag regex tolerates registry prefixes (so `ghcr.io/provenex/provenex-server:X.Y.Z` lints alongside `provenex/provenex-operator:X.Y.Z`); the `values.yaml` `image:` block regex tolerates comment lines between `image:` and `tag:`.

## [0.10.0] - 2026-05-21

### Added
- **`IndexAvailabilityPolicy` and `CircuitBreaker`**. New `policy.availability` block on the unified YAML controls behavior when the provenance index is unreachable on the verify path. Two modes: `on_index_error: block` (default, fail-closed; raises `IndexUnavailable` → HTTP 503) and `degrade` (fail-open with a signed receipt carrying the new top-level `index_status` block). Per-replica circuit breaker with configurable threshold / window / cooldown short-circuits while OPEN. See [docs/runbooks/index_unavailability.md](docs/runbooks/index_unavailability.md) and [docs/failure_modes.md](docs/failure_modes.md).
- **Receipt schema 2.5.0**. Optional top-level `index_status` block (`{available, error_class}`) records that the verify call ran while the index was unreachable. Present only in `degrade` mode when the index actually failed; absent on the normal path. Covered by the receipt signature. A 2.4.0 receipt without the field remains a valid 2.5.0 receipt.
- **`provenex bench` CLI**. In-process SQLite reproducer for the Pattern A verify-path numbers in [docs/scaling.md](docs/scaling.md). Reports p50/p95/p99/p999 + ingest throughput as JSON, deterministic in `--seed`. Stdlib-only.
- **`docs/failure_modes.md`**. Per-component fail-open / fail-closed table + blast-radius matrix.
- **`docs/runbooks/index_unavailability.md`** and **`docs/runbooks/bad_policy_rollback.md`**.
- **`docs/supply_chain.md`**. Per-release artifacts: PyPI Sigstore (PEP 740) attestations and CycloneDX SBOM, plus the local verify recipe.
- **`SECURITY.md` "What Provenex does NOT prove"** section. Explicit non-claims, including the SDK-enforcement limit.
- **`docs/threat_model.md` § Unwrapped agent code that bypasses the SDK**. Coverage gap vs adversarial bypass; gateway / tool-side / receipt-rate mitigation patterns.
- **Release workflow** at [.github/workflows/release.yml](.github/workflows/release.yml). Tag-triggered build + CycloneDX SBOM + PyPI publish with Sigstore PEP 740 attestations via OIDC trusted publisher (no long-lived API token). SBOM attached to the GitHub Release.
- **CI SBOM job**. Test workflow runs `cyclonedx-py environment` on every PR so SBOM tooling drift is caught before release.
- **README badges**. SBOM (CycloneDX) and Sigstore-signed PyPI attestations.
- **README "Reproducible performance"** section. Pattern A / B / C labeled with verify p50 / p99 / p999 and the `provenex bench` reproduction command.
- **Metrics**: `provenex_index_error_total{error_class=...}` and `provenex_verify_degraded_total{error_class=...}` on `/metrics`.

### Changed
- **`/healthz` and `/readyz` semantics distinguished**. `/healthz` is liveness (always 200 once the process is up). `/readyz` returns 503 when the circuit breaker is OPEN or the sentinel index probe fails. Kubelet probes route traffic away from a replica that cannot currently issue VERIFIED receipts. Helm chart probe wiring unchanged.
- **`verify_chunks` and `verify_chunks_async`** accept an optional `breaker=` kwarg (a `CircuitBreaker` instance). When supplied, mediates index access across calls. The HTTP server constructs a process-wide breaker on lifespan startup.
- **`provenex audit`** reads `PROVENEX_RECEIPT_SECRET` in preference to the legacy `PROVENEX_SIGNING_SECRET`, matching the resolver in `provenex.core.receipt`. The legacy var still works as a fallback. Help text and error messages mention both.
- **`provenex audit` human output** surfaces an `Index status` row when the receipt has `index_status.available=false`. JSON output includes the `index_status` key on every receipt (null when healthy).
- **OpenAPI spec**. Regenerated; documents the 503 response shape for `/v1/verify` and `/readyz`.
- **`docs/secure_defaults.md`** gains `availability.on_index_error` and `availability.timeout_seconds` rows; cross-links to `failure_modes.md` and `runbooks/index_unavailability.md`.

### Fixed
- **`CircuitBreaker` memory bound**. Failure deque now `deque(maxlen=threshold)`. A misbehaving caller that bypasses `allow()` and hammers `record_failure()` no longer causes unbounded memory growth. Sliding-window semantics preserved.
- **`provenex audit` crash on malformed receipts**. Bare JSON arrays / nulls / primitives at the receipt root, and wrong-type `index_status` fields, now exit 2 with a clear "must be a JSON object" error instead of raising `AttributeError`.
- **`provenex bench` input validation**. Rejects `verify_samples < 1`, `chunk_chars < 1`, and `unknown_rate` outside `[0, 1]`.

### Test coverage
- Circuit breaker state-machine + bounded-deque invariants.
- `IndexAvailabilityPolicy` parsing, validation, and YAML round-trip (every knob).
- Verify path in both `block` and `degrade` modes (sync + async).
- HTTP integration for `/healthz`, `/readyz`, `/v1/verify` (block + degrade), metrics shape under both modes.
- CLI env-var resolution; audit graceful on every fuzzed non-object JSON; audit doesn't crash on malformed `index_status`.
- Trajectory chain with a degraded receipt in the middle still verifies offline.

## [0.9.0] - 2026-05-20

### Added
- **`provenex-server` HTTP wrapper** (`pip install "provenex-core[server]"`).
  FastAPI app exposing `POST /v1/verify`, `POST /v1/admit/{tool,memory_write,model_inference}`,
  `POST /v1/ingest`, plus `GET /healthz`, `GET /readyz`, `GET /metrics`. The signing
  key is loaded from env (`PROVENEX_RECEIPT_PRIVATE_KEY_FILE` or
  `PROVENEX_RECEIPT_SECRET`); the server never embeds keys. OpenAPI spec
  committed at [docs/openapi/openapi.json](docs/openapi/openapi.json). Reference
  Dockerfile at [Dockerfile.server](Dockerfile.server) (multi-stage, distroless-
  style, non-root). One-page Go client at
  [examples/go_client/](examples/go_client/) proves cross-runtime offline
  verification of issued receipts.
- **Helm chart + raw Kubernetes manifests** under
  [deploy/helm/provenex-server/](deploy/helm/provenex-server/) and
  [deploy/manifests/](deploy/manifests/). Includes verify Deployment, HPA, PDB,
  NetworkPolicy, optional Postgres subchart, witness + ingester CronJobs,
  and a `values-large.yaml` for a 500-RPS / 10M-chunk deployment. Walkthrough
  in [docs/k8s_deployment.md](docs/k8s_deployment.md).
- **Policy CRD + lightweight operator**
  (`pip install "provenex-core[operator]"`). The `policies.provenex.io/v1`
  CRD lives at [deploy/operator/crd.yaml](deploy/operator/crd.yaml); the kopf-
  based operator at [provenex/operator/main.py](provenex/operator/main.py)
  reconciles Policy CRs into the ConfigMap the verify pods read, runs the
  policy through `Policy.from_yaml` validation, and stamps the resulting
  `policy_version_hash` onto the CR's status.
- **KMS / HSM signer adapters** under
  [provenex/kms/](provenex/kms/): `AwsKmsSigner` (`[kms-aws]`),
  `GcpKmsSigner` (`[kms-gcp]`), `AzureKeyVaultSigner` (`[kms-azure]`),
  `PKCS11Signer` (`[pkcs11]`). Each implements the existing `ReceiptSigner`
  protocol so the signing key never has to leave the KMS / HSM. The receipt
  `signature.algorithm` discriminator carries the actual algorithm used
  (`hmac-sha256`, `ed25519`, `rsa-pss-sha256`). Integration test against
  moto-mocked AWS KMS covers the RSASSA-PSS-SHA256 round-trip end-to-end.
- **Multi-tenant signer registry** at
  [provenex/core/signer_registry.py](provenex/core/signer_registry.py).
  Maps `tenant_id` to `ReceiptSigner`; the HTTP server reads
  `X-Provenex-Tenant` and routes signing to the matching tenant. Tenant
  isolation locked in by test (receipts under tenant A do not verify under
  tenant B's public key).
- **Index drift webhook detector**
  ([provenex/drift/](provenex/drift/)). `IndexDriftDetector` coalesces
  distinct UNVERIFIED fingerprints over a sliding window (default 5 minutes)
  and fires a single webhook POST per flush. Lives behind
  `PROVENEX_DRIFT_WEBHOOK_URL` on the server; off by default.
- **`provenex policy simulate` CLI**
  ([provenex/policy/simulator.py](provenex/policy/simulator.py)). Replays
  a directory of historic receipts against a proposed new policy and reports
  exactly which decisions flip allow ↔ deny. JSON output or `--human`
  markdown diff. The SR-11-7 / Model Risk workflow primitive.
- **Receipt-retention Terraform module**
  ([deploy/terraform/receipt_archive/](deploy/terraform/receipt_archive/)).
  Stands up the canonical S3 Object Lock (compliance mode, 7-year) +
  Glacier Deep Archive + Athena pattern for per-receipt searchable
  long-term retention. Documented in
  [docs/receipt_retention.md](docs/receipt_retention.md).
- **JWT → `RequestContext` identity recipe**
  ([provenex/integrations/identity/](provenex/integrations/identity/)).
  Generic JWT extractor that maps standard OIDC claims onto a
  `RequestContext`. Working FastAPI examples at
  [examples/okta_request_context.py](examples/okta_request_context.py) and
  [examples/azure_ad_request_context.py](examples/azure_ad_request_context.py).
- **SIEM connector packs** under [siem/](siem/). Splunk app
  ([siem/splunk/](siem/splunk/)) with three saved searches (denied tool calls,
  UNVERIFIED chunks by jurisdiction, drift alerts) plus a landing dashboard.
  Microsoft Sentinel pack ([siem/sentinel/](siem/sentinel/)) with KQL queries
  + two ready-to-deploy analytics-rule templates.
- **Customer-facing rollup docs**:
  [docs/deployment_patterns.md](docs/deployment_patterns.md) (A/B/C patterns,
  when to use each, polyglot story),
  [docs/k8s_deployment.md](docs/k8s_deployment.md) (Helm walkthrough + sizing
  guide), [docs/key_management.md](docs/key_management.md) (HMAC vs Ed25519 vs
  KMS/HSM, rotation procedures, HSM caveats).

- **Async-safe verification path** (`provenex.verify_chunks_async` +
  `AsyncPostgresProvenanceIndex`). A FastAPI / Starlette / aiohttp
  handler can now `await provenex.verify_chunks_async(...)` directly
  without blocking the event loop or dispatching to a threadpool. The
  async index wraps `psycopg.AsyncConnection` and
  `psycopg_pool.AsyncConnectionPool`; the canonical signing payload,
  schema, and HMAC-row machinery are byte-identical to the sync
  backend, so a receipt produced via the async path verifies
  bit-identically against a sync-backed verifier and vice versa. The
  Phase 1.2 acceptance test (100 concurrent ASGI handlers each
  awaiting 50 ms of simulated work alongside a real verify) finishes
  in under 500 ms; the same load on a serializing event loop would
  take ~5 seconds. The async path is shipped behind the same
  `provenex-core[postgres]` extra as the sync Postgres backend.
- **Batched index verification** (`ProvenanceIndex.verify_batch`). Replaces
  the per-chunk pair of `verify()` + `lookup()` calls that
  `verify_chunks` issued internally on a multi-chunk retrieval. The base
  class ships a default-loop implementation so every backend gets correct
  behavior; `SQLiteProvenanceIndex` and `PostgresProvenanceIndex`
  override it with a single `IN (...)` / `WHERE fingerprint = ANY(%s)`
  query. On a top-10 Postgres retrieval the verify path drops from ~20
  backend round-trips to 1. Measured p50 speedups on a local
  Postgres at `k=10` is ~8×; at `k=25`, ~13× (see
  `bench/batch_verify.py`). Receipt format unchanged.

### Tests
- Cross-version receipt-portability regression. Two committed 0.8.2 receipt
  fixtures (`tests/fixtures/receipt_0_8_2_*.json`) are now re-verified under
  every build, so any silent drift in the canonical signing payload fails
  CI before it ships. Regenerate via
  `scripts/regenerate_portability_fixtures.py` after a conscious
  `SCHEMA_VERSION` bump and a matching entry in
  [docs/receipt_format.md](docs/receipt_format.md).

### Benchmarks
- **Postgres scale harness** (`bench/postgres_scale.py`) measures ingest
  throughput, warm/cold verify latency, concurrent reader+writer p99, and
  connection-budget sensitivity against any Postgres DSN. The first 1M-chunk
  numbers are now published in
  [docs/scaling.md](docs/scaling.md#postgres-at-scale-measured-1m-chunks):
  ingest 1,076 chunks/s, warm verify_batch (k=10) p50 461 µs / p99 1.04 ms,
  cold-cache p50 2.73 ms, 8-reader concurrent-with-writer p99 5.79 ms,
  and a Postgres-direct throughput curve that peaks at four concurrent
  readers on a 6-core laptop before connection contention starts trading
  throughput for tail latency.
- **Docker Compose bench rig** in [bench/postgres/](bench/postgres/) stands
  up a tuned Postgres 16 plus an optional PgBouncer in transaction mode,
  so anyone can reproduce the published numbers on their own hardware or
  measure PgBouncer-fronted topologies the laptop bench does not exercise.
- **Async vs sync-threadpool bench** (`bench/async_verify.py`) measures
  throughput at 1 / 10 / 50 / 100 client concurrency for the two
  hot-path shapes. The async path holds ~875 ops/sec at c=100 on a
  laptop while the sync-threadpool path degrades to ~265 ops/sec at
  the same concurrency (a 3.3x gap). Below c=10 the two paths are
  comparable; the async win is in the high-concurrency tail, which is
  where the typical RAG fan-out lives.

### Docs
- New operator and auditor docs: [docs/regulator_verification.md](docs/regulator_verification.md) (offline verification walkthrough with a pure-stdlib reference verifier) and [docs/secure_defaults.md](docs/secure_defaults.md) (every setting that affects security posture, default vs production recommendation).
- Five new runbooks under [docs/runbooks/](docs/runbooks/): `key_rotation`, `witness_log`, `postgres_operations`, `disaster_recovery`, `sizing_guide`.
- Engineering reference: [docs/cookbook.md](docs/cookbook.md) (twenty recipes), [docs/vector_db_integration.md](docs/vector_db_integration.md) (integration matrix across eleven backends), [docs/migration_guide.md](docs/migration_guide.md) (per-version upgrade notes back to 0.5.0), [docs/trajectory.md](docs/trajectory.md) (DAG model deep-dive).
- Boundary docs: [docs/streaming_export_ops.md](docs/streaming_export_ops.md), [docs/data_sovereignty.md](docs/data_sovereignty.md), [docs/mcp_integration.md](docs/mcp_integration.md).
- [docs/procurement_faq.md](docs/procurement_faq.md): supply-chain and license Q&A for procurement teams approving the OSS dependency.
- [SECURITY.md](SECURITY.md): vulnerability reporting policy at the repo root.
- [`scripts/generate_audit_bundle.py`](scripts/generate_audit_bundle.py) produces `dist/audit_bundle.zip`, a downloadable end-to-end verifiable audit artifact (three signed receipts plus the Ed25519 public key plus the matching policy file).
- [`scripts/check_docs_consistency.py`](scripts/check_docs_consistency.py) plus `tests/test_docs_consistency.py` catch schema-version and issuer-string drift between code and docs.
- All public contact addresses consolidated to `contact@provenex.ai`.
- README and architecture doc restructured to the buyer-first ordering; the attack demo narrates the seven regulator questions.

## [0.8.2] - 2026-05-18

### Changed
- Surface `Ed25519Signer` at the top-level import so the README example
  works without reaching into submodules.

## [0.8.1] - 2026-05-18

### Changed
- Policy DSL: refuse `fnmatch` patterns containing regex-only characters
  at parse time, closing a regex/glob-confusion footgun.

## [0.8.0] - 2026-05-18

### Added
- **Receipt schema 2.4.0.** Per-source `entry_kind`
  (`"whole_chunk"` vs `"window"`); only whole-chunk rows are eligible for
  `VERIFIED`. New top-level `request_binding` block cryptographically
  ties each receipt to the triggering query and request context.
- **Window-aligned splice control.** Sliding-window fingerprints are
  retained only as structural locators; substring promotion to
  `VERIFIED` is no longer possible.
- **Witness / checkpoint log** (`provenex/core/witness.py`): hash-chained,
  signed, append-only JSONL log over the Merkle tree head. Producer-side
  artifact; split-view resistance against a key-holding operator
  additionally requires external publication.
- **Peppered fingerprint mode** (`FingerprinterConfig.pepper`) for
  low-entropy corpora.
- **`provenex selftest`** — in-process conformance check that re-derives
  every property the docs claim against the installed binary.
- `OUTCOME_PRECEDENCE` + `reduce_outcomes` codified on
  `provenex.index.base`.

### Breaking
- Index storage layer gains an `entry_kind` column inside the canonical
  row signing payload. Pre-0.8.0 indexes refuse to open and must be
  re-ingested against a 0.8.0+ fingerprinter.

## [0.7.2] - 2026-05-15

### Removed
- `DECISION_ALLOW_WITH_CONDITIONS` constant from the public API (`provenex` and `provenex.policy`). The value was reserved-but-unimplemented and never returned by any evaluator; the native YAML evaluator continues to reject `on_violation` values other than `"deny"` at parse time.

## [0.7.1] - 2026-05-15

### Fixed
- `PostgresProvenanceIndex.add()`, `set_authorization()`, and `supersede()` now take a `pg_advisory_xact_lock` keyed on `document_id` so concurrent inserts of the same new document_id no longer race past the `SELECT ... FOR UPDATE` (which returned no row to lock on a not-yet-existing document).
- `matches_pattern` and `not_matches_pattern` cap string inputs at 64 KiB; oversized inputs fail-closed (the rule fires, the decision is deny). Bounds the per-decision cost when a hostile upstream value lands in a glob comparison.

## [0.7.0] - 2026-05-15

### Added
- `provenex audit --unsigned` flag opts back into the prior "skip signature check, return PASS" behaviour. Without it, the audit fails when no key material is available.
- Per-role HMAC environment variables: `PROVENEX_RECEIPT_SECRET` and `PROVENEX_INDEX_SECRET`. Falling back to the legacy shared `PROVENEX_SIGNING_SECRET` emits a one-time `DeprecationWarning`.

### Changed
- `ProvenanceReceipt.canonical_payload()` and `verify_receipt_signature` pin `ensure_ascii=False`. ASCII-only receipts produce byte-identical output; receipts with non-ASCII content (smart quotes, CJK callers, emoji in `rules_fired`) canonicalize as raw UTF-8 and round-trip across language boundaries. Old non-ASCII receipts signed under 0.6.x do not verify under 0.7.0; ASCII-only receipts are unaffected.

### Deprecated
- Bare `VerificationPolicy()` (no explicit `block_unverified=`) emits a `DeprecationWarning`. The default will flip to `True` in a future major release. Pass `block_unverified=True` for strict enforcement, or `block_unverified=False` to silence the warning while keeping current behaviour.
- Unsalted `compute_caller_hash(caller)` emits a one-time `DeprecationWarning` per process. Pass `caller_hash_salt=b"..."` on the emission entrypoint for per-deployment unlinkability.

### Fixed
- HMAC row signing: `_canonical_payload` validates that `document_id` (and the other string fields it covers) does not contain `\n`, `\r`, or `\x00`. Removes canonical-bytes ambiguity between two distinct field tuples that join to the same payload.
- `_safe_publish` and `RetryQueueSink` no longer emit the downstream exception body via `warnings.warn`; only the exception class name is logged. Prevents connection URIs, request signatures, and SSL/auth-time strings from third-party SDKs leaking into stderr / Sentry / Datadog.
- `RetryQueueSink`: drop-oldest on `maxlen` overflow emits an edge-triggered warning (re-armed on drain); `close()` uses peek-then-popleft-on-success so a final flush against a still-failing downstream does not silently lose receipts.
- `FileJSONLSink`: rejects path traversal in `prefix`; refuses to open the rotated file when the resolved path is a symlink (uses `O_NOFOLLOW` on POSIX). The constructor rejects `prefix` containing `/`, `\`, or `..`.

## [0.6.9] - 2026-05-15

### Added
- `examples/mcp_admission_demo.py`: runnable end-to-end MCP middleware integration with three live `tools/call` requests through a decorated handler, the `on_deny` callback pattern, and `wrap_mcp_request` for routers that do not decorate.
- `examples/langgraph_admission_node_demo.py`: runnable end-to-end LangGraph admission-node demo with the conditional-edge pattern routing to either an execute-tool node or a denial handler.

## [0.6.8] - 2026-05-14

### Added
- [docs/anomaly_detection.md](docs/anomaly_detection.md): the canonical positioning doc for the source-of-record architecture. Schema field reference for detectors plus five worked detection patterns (per-caller rate, trajectory shape drift, policy near-miss, cross-trajectory correlation, content-source anomaly).
- [docs/policy.md](docs/policy.md): explicit "deliberately doesn't do" section. The native DSL is per-decision-pure by design; trajectory-level rules live in the commercial Rego adapter or downstream in your anomaly detector.

## [0.6.7] - 2026-05-14

### Added
- OCSF v1.3 mapping: `provenex.export.ocsf.receipt_to_ocsf(receipt_dict)` is the pure transformation function; `provenex.export.ocsf.OCSFAdapter(downstream=sink)` wraps any `ReceiptSink` so receipts are translated to OCSF events before publishing.
- [docs/ocsf_mapping.md](docs/ocsf_mapping.md): the public mapping spec a SIEM vendor reads to wire Provenex into their pipeline.
- OCSF class constants: `OCSF_CLASS_APPLICATION_ACTIVITY` (6005, allowed retrieval), `OCSF_CLASS_API_ACTIVITY` (6003, allowed admission), `OCSF_CLASS_DETECTION_FINDING` (2004, block or deny).

## [0.6.6] - 2026-05-14

### Added
- Streaming export sinks. `ReceiptSink` Protocol (`runtime_checkable`) plus reference sinks: `StdoutJSONLSink`, `FileJSONLSink`, `MultiSink`, `RetryQueueSink` (stdlib core); `KafkaSink` (`[export-kafka]`), `SQSSink` and `S3AppendSink` (`[export-aws]`), `PubSubSink` (`[export-gcp]`).
- `sink=` parameter on every receipt-emitting entrypoint: `verify_chunks`, `verify_memory`, `admission_check`, `admit_memory_write`, `admit_model_inference`, plus every framework wrapper. Pass a single sink or a list; lists are auto-wrapped as `MultiSink`.
- [docs/streaming_export.md](docs/streaming_export.md).

### Changed
- Sink failures are swallowed and logged via `warnings.warn`. The agent's hot path is never broken by export degradation.

## [0.6.5] - 2026-05-14

### Added
- `provenex.verify_memory(memory_chunks, ...)`: convenience wrapper over `verify_chunks` that sets `step_kind="memory_read"` and `content_source="memory_store"`.
- `provenex.admit_memory_write(memory_key, value, ...)`: admission-shaped convenience for memory writes. `name="memory.write"`, `operation=<memory_key>`. Verbatim value redacted by default (`redact_value=True`); `value_hash` always recorded.
- `provenex.admit_model_inference(model_name, prompt, ...)`: admission-shaped convenience for LLM calls. `name=<model_name>`, `operation=<verb>`, `target_system=<provider>`. Verbatim prompt redacted by default (`redact_prompt=True`); `prompt_hash` always recorded.
- `caller_hash_salt=b"..."` opt-in on every emission entrypoint switches `caller_hash` from bare SHA-256 to HMAC-SHA256 keyed by the salt for per-deployment unlinkability across multi-tenant deployments.
- `provenex.compute_value_hash(value)` public helper using the same canonicalisation rule as the rest of the receipt.

### Fixed
- `PostgresProvenanceIndex` forces `client_encoding=UTF8` on every new connection. On a `SQL_ASCII` cluster (macOS `initdb` default) psycopg3 had been returning text columns as bytes, breaking canonical-payload HMAC at sign time.

## [0.6.4] - 2026-05-14

### Added
- Receipt schema **2.3.0** (additive). Top-level `caller_hash` (`"sha256:<hex>"`): SHA-256 over the canonical JSON of `request_context.caller`. Optional `trajectory.session_id`: caller-chosen opaque string for multi-trajectory correlation (chat sessions, multi-day investigations).
- `provenex.compute_caller_hash(caller)`: public helper using the receipt's canonicalisation rule.
- `RequestContext.session_id` and `TrajectoryContext.session_id` (also `start_trajectory(session_id=...)`).
- `examples/anomaly_correlation_demo.py` and `examples/anomaly_correlation_with_policy_demo.py`.

## [0.6.3] - 2026-05-14

### Added
- `provenex.integrations.langgraph.provenex_admission_node(...)`: LangGraph admission-node factory. The node writes `tool_admitted` / `tool_decision` / `tool_rules_fired` into state for a conditional edge to route execution; the admission node never invokes the underlying tool.
- `provenex audit --trajectory` aggregate summary block: total chunks per outcome, total actions, per-step-kind breakdown, aggregate `PASS` / `PARTIAL` / `FAIL`. Both human-readable and `--json` output carry it.

## [0.6.2] - 2026-05-14

### Added
- `ProvenexCrewSession.wrap_tool_admission(tool, ...)` and `ProvenexCrewSession.admission_check(...)`. Session-aware tool-call admission for CrewAI; denials raise `ToolCallDenied` before the underlying tool fires.
- `ProvenexCrewSession(..., policy=Policy)`: the unified `Policy` is accepted at session construction time alongside the legacy `VerificationPolicy` (coerced internally).

## [0.6.1] - 2026-05-14

### Changed
- README documentation pass surfacing tool-call admission alongside retrieval enforcement.

## [0.6.0] - 2026-05-14

### Added
- Tool-call admission. `provenex.ToolCallContext`, `provenex.admission_check(tool, request, policy=..., signer=...)`, `provenex.enforce_admission(...)` raise-on-deny convenience.
- Native YAML DSL extensions: `tool.*` path roots (`tool.name`, `tool.operation`, `tool.parameters.<key>`, `tool.target_system`, `tool.invocation_id`), `matches_pattern` and `not_matches_pattern` (POSIX `fnmatch` globs by design, not regex), `length_at_most` (string-length cap), and `{ in: [...] }` in `when` clauses.
- Unified `Policy` adds a third half: `tool_call_control`. The independent `policy_version_hash` per half means modifying one half does not invalidate audits that reference the other.
- Framework integrations: `provenex.tool_call.integrations.langchain.ProvenexToolWrapper`, `provenex.tool_call.integrations.mcp.{wrap_mcp_request, provenex_mcp_admission}`.
- CLI: `provenex policy hash` prints one bare hash for single-section files and a per-section breakdown for unified files (`--section` filters). `provenex audit --show-policy` renders both halves.

### Changed
- Receipt schema bumps to **2.2.0** (additive). Optional top-level `actions[]` array; optional `policy.tool_call_control` subsection; `summary` gains `total_actions` / `actions_allowed` / `actions_denied` when actions are present. Pure-retrieval receipts produce byte-identical 2.1.0 shape.

## [0.5.0] - 2026-05-14

### Added
- `PostgresProvenanceIndex`: production backend for multi-node deployments. Same `ProvenanceIndex` interface as `SQLiteProvenanceIndex`, same canonical HMAC payload, same receipt schema. A receipt produced against one backend verifies identically against the other.
- `provenex-core[postgres]` extra (`psycopg[binary]>=3.1`, `psycopg-pool>=3.2`).

## Notes on prior releases

Releases prior to 0.5.0 (0.4.x and earlier) are not enumerated here. The receipt schema history table in [docs/receipt_format.md § Schema history](docs/receipt_format.md) is the authoritative record for what each receipt-schema version added; the receipt format is the load-bearing customer surface, not the package version.
