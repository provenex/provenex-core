# Runbook: sizing guide

Provisioning recipes for three reference deployment shapes. This is the "given X chunks, Y RPS, Z retention, what do I deploy" doc. The underlying benchmarks live in [scaling.md](../scaling.md); this runbook turns them into operational recipes.

For the decision of which backend (SQLite vs Postgres) and whether to shard, jump to the decision tree at the bottom.

## Three reference shapes

The numbers below treat verify path latency as the constraint. Ingest is throughput-oriented and scales separately. All three shapes assume Postgres as the index backend; SQLite is the development default and rarely the right choice past 100k chunks.

| Shape | Index size | Verify RPS | Recommended deployment |
| --- | --- | --- | --- |
| **Small** | up to 1M chunks | up to 10 verify-per-second | 1 verify pod, db.t3.medium or equivalent, no PgBouncer needed |
| **Medium** | up to 10M chunks | up to 100 verify-per-second | 2-3 verify pods, db.m5.large primary + 1 read replica, PgBouncer in transaction mode |
| **Large** | up to 100M chunks | up to 1000 verify-per-second | 5-10 verify pods, db.r5.2xlarge primary + 2-4 read replicas, PgBouncer with 100-200 server connections, sharded ingest if cross-tenant |

The numbers below are upper-bound recommendations. Smaller hardware can work; start at one tier below if your peak RPS is near the boundary and scale up after monitoring.

### Small (up to 1M chunks, up to 10 RPS)

| Component | Recommendation |
| --- | --- |
| Verify pod count | 1 |
| Ingest pod count | 1 |
| Postgres tier | RDS `db.t3.medium` (2 vCPU, 4 GB), Cloud SQL equivalent, or self-managed with comparable specs |
| PgBouncer | Not required; the verify pod's internal pool (10 connections) is enough |
| Read replicas | None; verify against the primary |
| Witness-log cadence | Daily, if the Merkle-backed index is in use |
| Receipt storage | File JSONL sink (`FileJSONLSink`) plus optional S3 archive |
| Expected verify latency | p50 ~1-2 ms (network + Postgres point lookup), p99 ~5-10 ms |
| Index size on disk | ~1-2 GB (~1 KB per chunk; see [scaling.md § Index footprint](../scaling.md#index-footprint)) |
| Receipt storage size per million retrievals | ~2-5 GB JSONL |

### Medium (up to 10M chunks, up to 100 RPS)

| Component | Recommendation |
| --- | --- |
| Verify pod count | 2-3, behind a load balancer |
| Ingest pod count | 1 (single ingester remains the recommendation for the Merkle-backed index; multi-ingester for non-Merkle) |
| Postgres tier | RDS `db.m5.large` (2 vCPU, 8 GB) or equivalent, primary + 1 read replica |
| PgBouncer | Transaction mode, 50-100 server connections; verify pods point at PgBouncer, not directly at Postgres |
| Read replicas | 1 cross-AZ replica; verify pods read from it |
| Witness-log cadence | Hourly |
| Receipt storage | Kafka or SQS sink for real-time; S3 archive for retention |
| Expected verify latency | p50 ~2-3 ms, p99 ~10-20 ms |
| Index size on disk | ~10-20 GB |
| Receipt storage size per million retrievals | ~5-15 GB JSONL |

### Large (up to 100M chunks, up to 1000 RPS)

| Component | Recommendation |
| --- | --- |
| Verify pod count | 5-10, behind a load balancer with replica-affinity for cache locality |
| Ingest pod count | 1 per shard if cross-tenant sharding is in use; otherwise 1 |
| Postgres tier | RDS `db.r5.2xlarge` (8 vCPU, 64 GB) or equivalent, primary + 2-4 read replicas across AZs |
| PgBouncer | Transaction mode, 100-200 server connections; multiple PgBouncer instances behind their own load balancer |
| Read replicas | 2-4 in-region, ideally one per AZ |
| Witness-log cadence | Hourly (per-minute for very high-ingest deployments) |
| Receipt storage | Kafka with replication factor 3, S3 archive with versioning and Object Lock for the witness log |
| Expected verify latency | p50 ~3-5 ms, p99 ~20-50 ms (network plus replica lookup) |
| Index size on disk | ~100-200 GB on primary; replicated to replicas |
| Receipt storage size per million retrievals | ~5-15 GB JSONL |
| Sharding | Sharded indexes per tenant or per document range if tenants do not share a tree. Each shard is an independent Provenex instance with its own signing key. |

## Component-by-component sizing

**Verify pods.** Provision for peak RPS divided by ~2500 (the single-process verify ceiling per [scaling.md](../scaling.md)), rounded up, plus headroom. A verify pod at p50 of 371 µs is well below the network latency to Postgres; the actual bottleneck once Python overhead is paid is the database round-trip. Adding read replicas helps more than adding pods past a point.

**Postgres primary.** Sized for ingest throughput. Verify path is cheap (B-tree point lookup); ingest is the heavier workload (an INSERT plus the WAL flush plus the Merkle tree update if applicable). Single-primary writes are bounded at 5-15k commits/sec on managed Postgres with write cache enabled (per [scaling.md § What we expect on Postgres](../scaling.md#what-we-expect-on-postgres)). Batch ingest across documents (multiple chunks per transaction) to push throughput.

**Read replicas.** Sized for verify RPS. Each replica adds ~2500 verify/sec capacity at the replica's lag tolerance. Cross-AZ replicas absorb regional outages; cross-region replicas are operator-chosen for residency or DR (see [postgres_operations.md § Multi-writer ingest](postgres_operations.md#multi-writer-ingest) and [disaster_recovery.md § Multi-region replication patterns](disaster_recovery.md#scenario-4-multi-region-replication-patterns)).

**PgBouncer.** Required past ~100 verify pods. Each verify pod opens its own `psycopg_pool.ConnectionPool`; without PgBouncer, the pod count times the per-pod pool size exceeds Postgres's `max_connections`. Transaction-mode pooling collapses 10,000 client connections to ~100 server connections.

**Receipt storage size.** Each receipt is ~2-5 KB JSON in compact form. Per million receipts: ~5 GB JSONL.

**Witness-log storage.** Per-witness record is a few hundred bytes. Hourly cadence is ~8,800 records/year; annual storage ~5 MB. Storage cost is negligible; the operational cost is the publication-to-external-store overhead.

## Decision tree

**When to use SQLite (`SQLiteProvenanceIndex`):**

- Development. Always. The same `ProvenanceIndex` interface as Postgres; same canonical payload; receipts verify identically across backends.
- Single-process, single-machine production deployments where the index fits in one file and the process count is one.
- Up to ~100k chunks comfortably; up to ~1M chunks if the process is genuinely single. Past 1M, the SQLite file works but is more brittle than the Postgres equivalent.

**When to use Postgres (`PostgresProvenanceIndex`):**

- Any multi-pod production deployment.
- Any deployment where retention spans multiple application redeploys (SQLite file portability is not a great audit story).
- Past 1M chunks in any single-tenant deployment.
- Past 100k chunks in any deployment that ingests concurrently from multiple writers.

**When to shard:**

- Multi-tenant deployments where tenants do not share an audit tree. Each tenant gets its own Provenex instance with its own signing key and its own index.
- Past 100M chunks in a single tree. The B-tree depth and Merkle tree depth both grow logarithmically, so 100M is not a hard limit; the practical limits are Postgres VACUUM and replica lag at scale.
- When per-tenant residency rules require physical separation of indexes (the Pattern A multi-region case in [disaster_recovery.md](disaster_recovery.md)).

**When NOT to shard:**

- When all tenants share an audit tree by design (a single-org deployment serving multiple internal teams under one policy).
- When the operational overhead of N Provenex instances is higher than the operational overhead of a single sharded Postgres instance with residency tags. Sharding adds key-management complexity (N signing keys, N witness logs, N rotation schedules).

## Read next

- [scaling.md](../scaling.md): the benchmark numbers the recommendations are derived from.
- [postgres_operations.md](postgres_operations.md): the schema, failover, replica lag, and backup procedures.
- [disaster_recovery.md](disaster_recovery.md): the multi-region patterns and the recovery procedures.
- [secure_defaults.md § Index backend](../secure_defaults.md): the index-backend default vs production recommendation.
