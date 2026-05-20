# Runbook: Postgres operations

How to run `PostgresProvenanceIndex` in production: schema management, failover, replica lag, backup and restore, and index audit / rebuild. Applies to bring-your-own Postgres deployments (RDS, Aurora, Cloud SQL, Crunchy, Supabase, self-managed). The schema is in [provenex/index/postgres_index.py](../../provenex/index/postgres_index.py); the topology recommendations are in [scaling.md § Multi-node deployment shape](../scaling.md#multi-node-deployment-shape-postgres-backend).

## Schema management

**Provenex does not run migrations.** The Postgres backend creates its two tables (`provenex_documents`, `provenex_fingerprints`) and two indexes via `CREATE TABLE IF NOT EXISTS` on the first connection. The DDL is in [provenex/index/postgres_index.py:75-100](../../provenex/index/postgres_index.py#L75-L100). Subsequent connections find the tables and use them.

**No silent schema upgrades.** When the storage layer's canonical row payload changes (the 0.8.0 `entry_kind` column was the most recent example), Provenex does not attempt to alter an existing table or backfill rows. The release notes document the change; the operator's path forward is to re-ingest against the new fingerprinter into a fresh database. The release notes for the affected versions ([CHANGELOG.md](../../CHANGELOG.md)) state the migration impact explicitly.

**Why no automatic migrations:** the canonical row payload feeds the HMAC signature; an automatic backfill would either re-sign every row (changing the index's tamper-evidence story silently) or leave rows with their old signature against a new column shape (failing verification). Both options break the audit story. A deliberate re-ingest under a new database is the only safe path.

**Backwards-compatible reads.** A receipt produced under an older `SCHEMA_VERSION` continues to verify under a newer Provenex binary, per the additive-on-the-wire rule documented in [receipt_format.md § Versioning](../receipt_format.md#versioning). The Postgres backend, however, holds the *index*, not the receipts; an index storage-layer break (0.8.0's `entry_kind` column) requires re-ingest of the index, not of the receipts. Old receipts continue to verify against their original tree roots independently.

**On a fresh deployment**, point Provenex at an empty database and let it create the schema:

```python
from provenex import PostgresProvenanceIndex
index = PostgresProvenanceIndex(dsn="postgresql://provenex:secret@db.internal:5432/provenex")
```

The first call to `index.add(...)` or `index.verify(...)` triggers schema creation. Subsequent calls find the tables. No manual `psql -f schema.sql` step is required.

**On a deployment with an existing schema**, point Provenex at the existing database. The `IF NOT EXISTS` clauses are no-ops. If the existing schema disagrees with the current Provenex version (missing `entry_kind` column on a pre-0.8.0 database against a 0.8.0+ binary), the next `add(...)` fails with a clear error citing the column. Re-ingest into a fresh database is the recovery path.

## Failover (RDS / Aurora / Cloud SQL primary failure)

Provenex's Postgres backend uses `psycopg_pool.ConnectionPool` (or a caller-supplied pool). On primary failure:

- **Verify pods** continue to serve from read replicas if pointed at a replica DSN. The verify path is a pure point-lookup against an indexed column; replica reads return correct outcomes for any row whose write has replicated.
- **Ingester pods** fail their next `add(...)` because the primary is unreachable. Restart the ingester pod after the managed Postgres tier has promoted a replica to primary and DNS / endpoint failover has completed.
- **The Merkle layer's in-process tree** lives on the ingester pod, not in Postgres. Single-ingester deployments rebuild the in-memory tree from the persisted rows on restart (the tree is content-addressed, so the rebuild is deterministic). The signed inclusion proofs on receipts produced before the failover remain verifiable against the original tree root.

Set `psycopg_pool` `reconnect_failed` and `reconnect_timeout` appropriately for your managed Postgres tier's typical failover window. For RDS with Multi-AZ, the typical failover is 60-120 seconds; for Aurora with the cluster endpoint, single-digit seconds.

## Read-replica lag tolerance

The verify path returns one of the five outcomes (`VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`) based on the current state of the `provenex_fingerprints` row. A read against a stale replica returns the outcome that was correct *at the replica's WAL position*, not at the primary.

| Replica lag | Verify path consequence |
| --- | --- |
| 0-100 ms | No practical consequence. |
| 100 ms - 5 s | A document re-ingested less than 5 s ago may still appear as the prior version on the replica; the receipt records `STALE` or `VERIFIED` against the replica's view. Re-running the verify against the primary returns the updated outcome. |
| > 5 s | A re-ingest's supersession of an old version may not have replicated. A verify against the replica returns `VERIFIED` on the now-superseded row. The receipt is correct *at the recorded `ingested_at`* but does not reflect the primary's current state. |

**Rule of thumb:** read-replica reads are fine for retrieval verification during normal operation. For audit-time verification (re-checking a receipt months later against the index it was produced under), point at the primary or wait for replica catch-up; the audit is a one-shot operation where the extra latency is acceptable. For real-time verification, the replica's stale read is acceptable because the receipt's `issued_at` and the chunk's `ingested_at` both record the moment of decision; an auditor sees the timeline.

## Backup and restore

**Backup the database**, not just the receipts. Receipts are signed and self-verifying; the index holds the fingerprints and metadata that the receipts reference. Standard managed-Postgres backups (RDS snapshots, Aurora continuous backups, Cloud SQL automated backups) work directly.

For self-managed Postgres, `pg_basebackup` plus continuous WAL archiving is the recommended pattern.

**On restore**, the index returns to its state at the restore point. Implications:

- Receipts issued **before** the restore point continue to verify; their signed canonical payload references rows that exist in the restored database.
- Receipts issued **after** the restore point may reference rows that no longer exist (because they were added between the restore point and the failure). Those receipts return `UNVERIFIED` on re-verification against the restored index. The receipts themselves are valid (the signature verifies); the rows the receipts reference have been lost.
- A re-ingest of the post-restore-point documents recreates the index rows. The fingerprints are deterministic, so the restored rows match the original rows by content. The signed-row HMAC depends on the index secret, which is preserved across the restore (stored in your secrets manager, not in the database). Receipts that referenced the lost rows now verify again.

**Witness logs** (if you run the Merkle-backed index with witness publication) survive a database restore because they live outside the database (filesystem JSONL plus external publication). The witness chain remains intact; the operator's `tree_size` may regress to the restore point, which is visible to external auditors as a tree-size regression and should be documented as part of the recovery.

## Multi-writer ingest

The non-Merkle `PostgresProvenanceIndex` supports multiple ingester pods writing concurrently. Schema-level locking is row-locked on `document_id` via `pg_advisory_xact_lock(hashtext(document_id))` in `add()`, `set_authorization()`, and `supersede()` (landed in 0.7.1). Two ingesters writing different documents proceed in parallel; two ingesters writing the same `document_id` serialise on the advisory lock.

The Merkle-backed index (`MerklePostgresProvenanceIndex`) keeps its tree in process memory on the ingester pod, so the recommended topology is one ingester. Multiple Merkle-backed ingesters writing concurrently would each maintain their own tree and produce divergent tree roots; the divergence is visible to verifiers but not what an operator wants. The single-ingester constraint is documented in [scaling.md § Recommended topology](../scaling.md#recommended-topology).

## Index audit (`provenex index audit`)

The CLI command surfaces two supersession-skip failure modes:

```bash
provenex index audit --index <dsn-or-path> --threshold-days 180
```

- **Stale documents:** any document whose most-recent ingest is older than `--threshold-days` (default 180). A long-stale document is the population most likely to have drifted from its authoritative source while the Provenex index missed the re-ingest.
- **Unsuperseded older versions:** any document with rows from a non-current version still flagged not-superseded. This is the supersession-skip signature: a re-ingest reached the vector store but did not reach Provenex.

Exit 0 if both lists are empty; 1 if either is non-empty. Wire the command into cron at the cadence that matches your re-ingest discipline (daily for high-velocity corpora, weekly for low-velocity).

**On a non-empty audit:**

- Stale documents: investigate why the document has not been re-ingested. If the source is genuinely unchanged, the audit is informational; lengthen the threshold for stable documents. If the source has changed, run the re-ingest through Provenex's `index.add(...)` so the supersession bit flips correctly.
- Unsuperseded older versions: a re-ingest happened outside Provenex. Run the missing `index.supersede(document_id, version)` or re-add the new version through Provenex; the old version's `superseded` flag will flip automatically.

The audit is a lint, not a remediation. The operator runs the remediation against the ingest pipeline (the part that should have called Provenex and did not).

## Index rebuild

A full rebuild of the Provenex index from the underlying corpus is occasionally necessary:

- The schema changed in a breaking way (0.8.0 `entry_kind`) and the operator chose re-ingest over freezing on the prior major.
- The index storage suffered corruption beyond what a restore covers.
- A pepper rotation requires re-fingerprinting under the new pepper.

The rebuild procedure:

1. Stand up a fresh Postgres database.
2. Point a fresh `PostgresProvenanceIndex` at it.
3. Run your ingest pipeline against every document in the corpus, in the same order as the original ingest, with the same `document_id` and authorisation state.

The resulting index is byte-equivalent to the original under the deterministic fingerprinter rules; receipts produced against the original index do **not** automatically verify against the new index unless the new index's row HMAC secret is the same as the original (it should be; the secret lives in your secrets manager, not in the database). Receipt verification (which depends on the receipt signer, not the index secret) is unaffected.

Witness logs reset on a rebuild: a new tree starts at `tree_size=1`. Document the rebuild in the operations log and publish a transition witness record so external auditors see the boundary.

## Read next

- [scaling.md § Multi-node deployment shape](../scaling.md#multi-node-deployment-shape-postgres-backend): topology, PgBouncer sizing, polyglot-stack distribution patterns.
- [sizing_guide.md](sizing_guide.md): per-shape provisioning recipes.
- [disaster_recovery.md](disaster_recovery.md): what to do when Postgres is lost entirely.
- [secure_defaults.md § Index backend](../secure_defaults.md): when to choose Postgres vs SQLite.
- [provenex/index/postgres_index.py](../../provenex/index/postgres_index.py): source.
