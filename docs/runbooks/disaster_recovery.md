# Runbook: disaster recovery

What to do when things break in production. Four scenarios, each with a recovery procedure and the audit-trail implications. The cryptographic baselines are in [threat_model.md](../threat_model.md).

Receipts are the audit trail, not the index. Receipts are signed and self-verifying; the index holds the fingerprints that determine `VERIFIED` versus `UNVERIFIED` outcomes on re-verification. A disaster that takes out the index does not invalidate previously-signed receipts; it changes what *future* verifications can confirm.

## Scenario 1: total Postgres loss with no usable backup

The provenance index is gone. The last backup either does not exist or is older than your recovery point objective allows.

**What survives:**

- Every receipt previously issued. Receipts are signed and were emitted to your sink (file, Kafka, S3, OCSF firehose) which is not the same store as Postgres. Re-verify any receipt with `provenex audit receipt.json --public-key audit.pub`; the signature check passes against the existing key material.
- The signing key. Stored in your secrets manager, separate from the database.
- The witness log (if you ran one). Local JSONL plus externally-published checkpoints; both live outside Postgres.

**What is lost:**

- The ability to re-verify a receipt's source records against the live index. A receipt produced before the loss will return `UNVERIFIED` on re-verification because the fingerprints are no longer in any index. The receipt's signature still verifies; the `sources[].verification_outcome` recorded on the receipt at issuance time is still authoritative.
- Real-time verification of new retrievals. Until the index is rebuilt, every chunk returns `UNVERIFIED`.

**Recovery procedure:**

1. Stand up a fresh Postgres database and a fresh `PostgresProvenanceIndex` pointing at it. The signing key from the secrets manager remains unchanged; the new database adopts the same key.
2. Re-ingest every document in your corpus against the fresh index, using your existing ingest pipeline. The fingerprints are deterministic, so the rebuilt index is byte-equivalent to the lost one for any document the corpus retained.
3. Documents whose source has been lost (the underlying file or upstream record is also unrecoverable) cannot be re-ingested. Their receipts continue to verify the *signature* but `UNVERIFIED` on re-verification. Document the loss in the incident record.
4. Witness log: start a new chain. The pre-loss witness records remain valid for verifying pre-loss receipts; the new chain covers post-recovery activity. Publish a transition witness record so external auditors see the boundary.
5. **The audit trail is unbroken.** Receipts issued before the loss are still valid evidence of what happened at the time they were issued; receipts issued after the recovery are also valid. There is a window of `UNVERIFIED`-on-re-verification for documents that could not be re-ingested.

## Scenario 2: signing-key compromise

The receipt-signing key (HMAC secret or Ed25519 private key) has been exfiltrated.

**What an attacker can do:**

- Mint new receipts that verify cleanly under the compromised key. Receipts produced this way are indistinguishable from genuine receipts to a verifier holding only the public key.
- Re-sign existing receipts after modification (since they hold the signing key).

**What an attacker cannot do:**

- Forge a receipt that already exists in an external sink (Kafka, S3 with versioning, the auditor's archive). The attacker can mint a *new* receipt with a colliding `receipt_id`, but the prior one persists in the sink and the divergence is visible.
- Force the index to accept a forged ingest row (the index has a separate HMAC secret).

**Recovery procedure:**

1. **Identify the compromise window.** When did the key go out, and what new receipts has the attacker had the opportunity to mint? Cross-reference your sink with the operator-controlled emission record (every legitimate receipt was emitted by a Provenex process in your environment; receipts in the sink that did not come from your process are suspect).
2. **Rotate the key immediately.** Follow [key_rotation.md](key_rotation.md) for the dual-key window procedure. New emissions use the new key; the old key's public counterpart (Ed25519) or shared secret (HMAC) is added to a "compromised keys" list in the verifier so any auditor verifying against the prior signature gets a clear warning.
3. **Notify auditors.** Every external auditor who holds the prior public key needs to know it is no longer trustworthy as a sole-source-of-truth for receipts issued after the compromise window. Receipts issued *before* the compromise window are still trustworthy (the attacker did not have the key then).
4. **Reissue compromised-window receipts if possible.** If you can re-derive the receipts (the input chunks and the surviving provenance index are available), reissue them under the new key. The reissued receipts have a fresh `receipt_id` and `issued_at` but otherwise identical content; the audit-trail record names both the original and the reissued receipts.
5. **Treat any receipt in the sink within the compromise window with elevated scrutiny.** Cross-check against the operator's own emission logs (the host's process logs typically record every `result.receipt.receipt_id` returned); receipts in the sink that the operator did not emit are forgeries.

Old receipts (signed under the compromised key, before the compromise) continue to verify under the old public key / shared secret. The auditor uses the dual-key verifier chain: try the new key, try the old key, accept whichever validates. Documentation of the compromise window is what tells the auditor which receipts to scrutinise.

## Scenario 3: vector-store-only ingestion drift

The ingest pipeline re-ingested a document to the vector store but skipped Provenex. The Provenex index still holds the old fingerprints; the new chunks coming back from retrieval return `UNVERIFIED`. Worse: the *old* chunks (still in the Provenex index) still return `VERIFIED` even though the underlying document has changed.

**How to detect:**

- `provenex index audit --threshold-days <N>` (see [postgres_operations.md § Index audit](postgres_operations.md#index-audit-provenex-index-audit)) surfaces the two failure modes: stale documents (last ingest older than N days) and unsuperseded older versions (a re-ingest skipped Provenex).
- Receipts emitted post-drift carry `UNVERIFIED` outcomes on the new chunks; the receipt stream into your anomaly detector ([anomaly_detection.md](../anomaly_detection.md)) shows the spike.
- The `summary.unverified` count on receipts climbs.

**Recovery procedure:**

1. **Identify the drifted documents** via `provenex index audit`. The lint produces a list of `(document_id, last_ingest_timestamp)` pairs for stale documents and `(document_id, unsuperseded_version_count)` pairs for unsuperseded older versions.
2. **Run a remediation ingest through Provenex** for every drifted document. The remediation pipeline reads the same source the original re-ingest pulled from and calls `index.add(...)` with the same `document_id` and the new content. Provenex marks the old version superseded automatically.
3. **Fix the upstream ingest pipeline** so it does not skip Provenex on the next re-ingest. The recurring failure is the bug; the audit lint is the smoke detector.
4. **Past receipts that referenced the drifted documents remain valid evidence** of what was retrieved at that time. The receipt is non-repudiable; the operational drift is recorded in the post-incident report alongside the receipts.

## Scenario 4: multi-region replication patterns

Provenex's OSS layer is a single-region library: one Postgres primary, multiple replicas, application pods within reach of the primary. Multi-region patterns are operator-chosen; this section describes the two patterns customers run today.

**Pattern A: one Provenex instance per jurisdiction.** Each region has its own Postgres, its own ingester pod, its own signing key, and its own audit trail. Cross-region retrieval is rare or impossible by policy. Suitable when data residency rules prevent any cross-region read.

- Failover: each region recovers independently using the Scenario 1 procedure. Cross-region recovery is not needed.
- Receipts: each region's receipts are signed under that region's key. An auditor verifying receipts from two regions holds two public keys and dispatches per receipt.
- Trade-off: the two indexes are siloed; a document re-ingested in region A is not visible in region B's index. Cross-region knowledge sharing is the application's responsibility, not Provenex's.

**Pattern B: shared index with residency tags.** One Postgres cluster with a primary in the home region and read replicas in each operational region. Documents carry residency tags as chunk metadata; the policy `access_control` rules gate retrieval by `request.jurisdiction` against `chunk.metadata.residency`.

- Failover: standard managed-Postgres cross-region failover. The Provenex backend reconnects via the pool's reconnect logic.
- Cross-region read latency: each region's verify pods read from a local replica; replica lag is the dominant latency factor. See [postgres_operations.md § Read-replica lag tolerance](postgres_operations.md#read-replica-lag-tolerance).
- Trade-off: a single index serves all regions, simplifying the audit story (one signing key, one tree, one set of witness records). Residency enforcement depends on the policy file being correct; misconfiguration can leak cross-region content.

**Disaster recovery in either pattern** follows the single-region procedures above, applied per region. The auditor's per-region public keys handle the multi-region case naturally.

## Read next

- [key_rotation.md](key_rotation.md): the rotation procedure called out in Scenario 2.
- [witness_log.md](witness_log.md): the witness-log discipline that survives Scenarios 1 and 2.
- [postgres_operations.md](postgres_operations.md): the index-audit and rebuild procedures called out in Scenarios 1 and 3.
- [threat_model.md](../threat_model.md): the cryptographic baselines that determine what survives each scenario.
- [secure_defaults.md](../secure_defaults.md): the operational defaults that shape your recovery posture before an incident happens.
