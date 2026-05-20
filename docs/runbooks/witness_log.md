# Runbook: witness / checkpoint log

How to run the OSS witness / checkpoint log in production. This runbook is for the operator who has chosen to deploy the Merkle-backed index (`MerkleSQLiteProvenanceIndex` or `MerklePostgresProvenanceIndex`) and wants to close split-view resistance against a key-holding attacker. The cryptographic mechanism is described in [threat_model.md § Witness / checkpoint log](../threat_model.md#witness--checkpoint-log-v080) and [provenex/core/witness.py](../../provenex/core/witness.py); this runbook covers operations.

If you are not running a Merkle-backed index, this runbook does not apply. The HMAC-row-signing layer on the plain `SQLiteProvenanceIndex` and `PostgresProvenanceIndex` catches single-row tampering on its own; the witness log is the additional layer that catches insertion / removal by a key-holder.

## What the witness log does, in one paragraph

The witness log is a hash-chained, signed, append-only JSONL log of `(checkpoint_index, tree_size, tree_root, issued_at, previous_checkpoint_hash, signature)` records. Each record's signature covers the prior record's hash, so retroactively editing record N requires reforging every subsequent record. The local log alone gives **tamper-detection on past records** (a verifier who has seen any earlier record can detect after-the-fact rewrites). The local log does **not** give split-view resistance against an operator who maintains two parallel local logs; closing that property requires publishing the records to a store the operator does not retroactively control. The publication step is the load-bearing operational discipline this runbook documents.

## Required inputs

| Input | When required |
| --- | --- |
| A Merkle-backed index | The witness log records tree heads from `index.tree_root()` and `index.tree_size()`; non-Merkle backends do not produce these. |
| A witness signer | An `HmacSha256Signer` (in-house only) or `Ed25519Signer` (preferred when the publication target is external). Use a key distinct from the receipt-signing key; the witness key is what an auditor uses to verify the witness chain. |
| A path for the local log file | The local hash-chained JSONL. One file, append-only. |
| A publication destination | A store the operator does not retroactively control. See **Where to publish** below. |
| A cron-like scheduler | The witness log is a periodic checkpoint, not per-receipt; the operator chooses the cadence. |

## Where to publish the head

The witness log only closes split-view resistance against a key-holder when the records reach a store the operator cannot retroactively edit. Options, with trade-offs:

| Destination | Property | Trade-off |
| --- | --- | --- |
| **S3 with Object Lock in Compliance mode** | Write-once with a retention period; even the bucket owner cannot delete or overwrite a locked object before the retention expires. | Setup requires an explicit lock-policy configuration; operators occasionally misconfigure into "Governance mode" which the bucket owner *can* override (do not use that mode). |
| **A separate Git repo under a different team's control** | Each witness record becomes a commit; force-push protection on the repo prevents history rewrites. | The "different team" is operationally distinct; if the same person controls both the signing host and the witness repo, the property is not closed. |
| **A transparency-log service (e.g. Sigstore Rekor, an internal CT-style log)** | Append-only by construction; cryptographic proofs of inclusion. | Network dependency at publication time; if the service is down, publication retries. |
| **A regulator's intake endpoint** | The regulator holds the record; the operator cannot reach into the regulator's archive. | Specific to regulated industries; setup requires coordination with the regulator. |
| **A simple HTTPS POST to a partner organisation's append-only store** | Lightweight; works for cross-org provenance. | Trust in the partner is now a load-bearing assumption. |

Pick at least one; pick two if the data is high-stakes. The hosted Provenex commercial product runs a gossip cluster that publishes to multiple independent witnesses; see [provenex.ai](https://provenex.ai) for status.

## Cron frequency

The witness-log cadence is a tunable; the right answer depends on how often you ingest and how much "rewrite window" an attacker would gain between checkpoints.

| Cadence | When appropriate |
| --- | --- |
| Once per minute | High-ingest deployments where a one-minute rewrite window is the operational tolerance. Witness record size is small (few hundred bytes per record) so storage cost is negligible. |
| Once per hour | Standard production deployment. One hour is a defensible audit-trail granularity for most regulatory contexts. |
| Once per day | Low-ingest or batch-oriented deployments. Easier to operate; an attacker has up to 24 hours of rewrite window between checkpoints. |
| Per ingest batch | Triggered by ingest activity rather than time. Good when ingest is bursty. |

The records are tiny; over-checkpointing is cheap. Under-checkpointing widens the rewrite window. Pick a cadence that matches your audit posture, not your ingest volume.

## The publication procedure

A typical witness-publisher cron job:

```python
from provenex import Ed25519Signer, WitnessLog
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex

index = MerkleSQLiteProvenanceIndex("/var/provenex/provenance.db")
signer = Ed25519Signer.from_private_key_pem(open("/secrets/witness-key.pem", "rb").read())
log = WitnessLog("/var/provenex/witness.jsonl", signer=signer)

record = log.append(
    tree_size=index.tree_size(),
    tree_root=index.tree_root(),
)

# Publish to the external store. Replace this with your destination.
publish_to_s3_object_lock(record.to_json(), bucket="audit-witness", key=f"witness/{record.checkpoint_index:010d}.json")
```

`WitnessLog.append(...)` reads the prior record from the local file, hashes it, signs the new record over `(previous_checkpoint_hash, checkpoint_index, tree_size, tree_root, issued_at)`, appends to the local file, and returns the new `WitnessRecord` so the publication step can ship it elsewhere. If the publication step fails, the local log still has the new record; the operator catches up at the next cron tick (publishing the backlog).

## How an auditor verifies a witness chain

Given a receipt that carries `transparency_log.tree_root` and a set of witness records published to the operator's chosen external store, the auditor:

1. **Verifies the local witness chain.** Calls `WitnessLog(path, signer=Ed25519Signer.from_public_key_pem(public_pem)).verify()`. This walks the chain, re-derives each `previous_checkpoint_hash`, and re-checks each signature. Returns True on a clean chain; False if any record was rewritten.

2. **Locates the witness record covering the receipt.** The auditor reads the receipt's `transparency_log.tree_root` and finds the witness record whose `tree_root` matches (or whose `tree_size` is at least as large as the receipt's, with the receipt's inclusion proof walking up to that record's tree_root).

3. **Confirms the witness record's external publication.** The auditor reads the same witness record from the operator's published external store (S3 Object Lock, the partner Git repo, the transparency-log service) and compares it against the operator-supplied record. Identical bytes confirm the operator has not split-viewed; divergent bytes are evidence of a forked history.

4. **Walks the receipt's inclusion proof** against the witness record's `tree_root`. If the inclusion proof is valid against the published witness, the receipt is committed to the same log everyone else is reading. If not, the receipt is from a side-history.

`provenex audit receipt.json --public-key audit.pub` covers steps 1, 2, and 4 against a single witness-log file the auditor has out-of-band. Step 3 (the external-publication check) is the operator-discipline part that closes split-view resistance and is currently outside the OSS tooling (the hosted Provenex witness cluster covers it commercially).

## Failure modes

**The witness log file is corrupted.** `WitnessLog.verify()` returns False. Cause: disk corruption, a misbehaving log-rotation tool, an operator editing the file by hand. Restore from backup if the corruption is post-`append()`; if the corruption is in-flight, the next `append()` will write a record that does not chain to the corrupt prior. Treat this as a security incident: the local chain has lost integrity and the deployment's split-view defence is degraded until the chain is rebuilt against a known-good earlier witness.

**The publication gap exceeds the SLO.** The local witness log has records that have not yet been published. Cause: external store is down; cron job is failing; credentials rotated and the publisher cannot authenticate. Catch up the backlog at the next successful publish (the records are append-only; backlog publish is idempotent against an Object-Lock or write-once destination). If the gap is widening, escalate: a sustained publication gap means an in-progress key-compromise attack would not be detected by external witnesses.

**Two published witness logs disagree.** An auditor checking the receipt against witness records from two different external destinations finds different `tree_root` values for the same `checkpoint_index`. This is the split-view detection signal. Cause: the operator (or an attacker with the witness signing key) is maintaining two parallel histories. Treat as a security incident; the receipts on at least one of the histories are unreliable until the divergence is investigated.

**The witness signing key is compromised.** Same posture as the receipt signing key compromise (see [key_rotation.md](key_rotation.md) and [disaster_recovery.md](disaster_recovery.md)). Rotate the witness key, publish a transition record under both keys, and start a new chain. The pre-compromise records still verify under the old public key.

**The Merkle-backed index is rolled back to a prior backup.** The next `WitnessLog.append()` would write a record whose `tree_size` is smaller than the previously-witnessed one. The chain still verifies locally (the signature chain is intact), but external auditors holding the prior witness record see a tree-size regression and treat it as evidence of an integrity event. Recover by re-ingesting forward from the rollback point to the prior tree size before publishing the next witness, or document the rollback and accept the audit-trail discontinuity.

## Read next

- [threat_model.md § Witness / checkpoint log](../threat_model.md#witness--checkpoint-log-v080): the cryptographic statement of what the log defends.
- [threat_model.md § Insertion or removal of rows by a key-holding attacker](../threat_model.md#insertion-or-removal-of-rows-by-a-key-holding-attacker): the threat the witness log defends against.
- [key_rotation.md](key_rotation.md): the rotation procedure that complements witness publication.
- [disaster_recovery.md](disaster_recovery.md): the broader incident-response runbook including witness-divergence scenarios.
- [provenex/core/witness.py](../../provenex/core/witness.py): the source.
