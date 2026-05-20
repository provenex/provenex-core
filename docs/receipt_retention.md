# Receipt retention reference architecture

How to keep Provenex receipts for the SR-11-7 / SOX 7-year horizon
without giving up per-receipt searchability.

This document covers the AWS path in depth because it's the
most-asked-for shape; the same pattern transposes cleanly to
GCS + BigQuery + Coldline and to Azure Blob immutable storage + Synapse.
Sections [Mapping to GCP](#mapping-to-gcp) and
[Mapping to Azure](#mapping-to-azure) cover the deltas.

## The canonical AWS pattern

```
  Provenex verify pods ----(receipt JSON, one object per receipt)---->  S3 STANDARD
                                                                          + Object Lock (compliance mode, 7y)
                                                                          + Versioning on
                                                                          + SSE-KMS
                                                                              |
                                                                              | lifecycle, day 90
                                                                              v
                                                                          S3 GLACIER_DEEP_ARCHIVE
                                                                          (same Object Lock retention)
                                                                              |
                  +-----------------------------------------------------------+
                  |
                  v
            Glue Catalog (JSON SerDe over the bucket)
                  |
                  v
            Athena workgroup
              SELECT receipt_id, caller_hash, policy.access_control.policy_version_hash
              FROM receipts
              WHERE issued_at BETWEEN '2026-01-01' AND '2026-01-31'
              AND   policy.access_control.policy_version_hash = '<hash>'
```

The Terraform module in
[deploy/terraform/receipt_archive/](../deploy/terraform/receipt_archive/)
stands all of this up. Apply once per environment.

### Why this shape

- **Object Lock compliance mode** is the only retention surface AWS
  offers that even your account root cannot override. Governance
  mode would let an admin lift a hold; compliance mode does not.
  SR-11-7 / SOX auditors are explicit about this distinction.
- **Versioning on** is required for Object Lock and gives you the
  delete-marker recovery surface you want if someone goes wrong with
  a lifecycle policy.
- **Lifecycle to DEEP_ARCHIVE at day 90** keeps the storage cost
  flat at scale. 1B receipts at ~2 KB each = ~2 TB; STANDARD
  storage runs ~$48/TB/mo, DEEP_ARCHIVE runs ~$1/TB/mo. The
  90-day delay keeps recent receipts on the SOC-interactive tier.
- **Glue + Athena** lets ops and compliance query individual receipts
  without downloading objects. You usually query by `receipt_id`,
  `caller_hash`, or `policy_version_hash`; Athena scans the JSON
  directly via the Glue SerDe.
- **No additional KMS** is required: SSE-S3 (AES256) covers the at-
  rest discipline for free. Pass `kms_key_arn` to switch to SSE-KMS
  if your compliance posture requires it.

### What you ship in the bucket

One JSON object per receipt, key prefix:

```
receipts/<YYYY>/<MM>/<DD>/<receipt_id>.json
```

The witness-publisher CronJob in
[deploy/helm/provenex-server/templates/cronjob-witness.yaml](../deploy/helm/provenex-server/templates/cronjob-witness.yaml)
is one place to do this; any forwarder (Fluent Bit, Vector,
custom script) works as long as it preserves the JSON shape.

### Querying

Once the Glue catalog is populated (`MSCK REPAIR TABLE receipts;`
after a partition refresh), Athena queries look like:

```sql
-- Find every receipt issued by caller X in May 2026:
SELECT receipt_id, issued_at, policy.access_control.policy_version_hash
FROM receipts
WHERE caller_hash = '<sha256 hex>'
  AND issued_at BETWEEN '2026-05-01' AND '2026-05-31'
ORDER BY issued_at DESC;

-- Find every receipt issued under a now-superseded policy:
SELECT receipt_id, issued_at, caller_hash
FROM receipts
WHERE policy.access_control.policy_version_hash = '<old hash>';
```

The Athena workgroup is namespaced per the module's `bucket_prefix`
variable, so different deployments coexist cleanly.

## Cost envelope

For a deployment issuing 1M receipts/day at ~2 KB each:

| Tier | Storage 1y | Storage 7y | Notes |
|---|---|---|---|
| S3 STANDARD (first 90d) | 2 GB×$0.023 | 90d only | Daily cost trivial. |
| DEEP_ARCHIVE (rest) | 720 GB×$0.001/mo | 5 TB×$0.001/mo | Steady state ~$5/mo. |
| Athena (per query) | ~$5/TB scanned | same | Partitioned by date keeps scans bounded. |

7-year retention for ~2.5B receipts: under $100/mo total at the storage
tier. The dominant cost is Athena query volume, which is operator-
controlled.

## Restoring a DEEP_ARCHIVE object for compliance handoff

```bash
aws s3api restore-object \
    --bucket "$BUCKET" \
    --key "receipts/2024/03/15/r-abc.json" \
    --restore-request '{"Days":7,"GlacierJobParameters":{"Tier":"Standard"}}'
```

Standard tier restore is 12 hours; Expedited is 1-5 minutes (~$10/GB).
Plan for 12-48h SLA when regulators ask for a specific receipt from
year 5.

## Mapping to GCP

| AWS | GCP equivalent |
|---|---|
| S3 STANDARD | GCS Standard |
| Object Lock (compliance) | Bucket Lock + retention policy (locked) |
| GLACIER_DEEP_ARCHIVE | GCS Archive class |
| Glue Catalog | BigQuery external table (JSON) |
| Athena | BigQuery |
| Lifecycle transitions | GCS lifecycle rules |

The semantics line up cleanly; the Terraform module is AWS-specific
today but a `gcp/` sibling is straightforward and matches the same
shape.

## Mapping to Azure

| AWS | Azure equivalent |
|---|---|
| S3 STANDARD | Blob Storage Hot tier |
| Object Lock (compliance) | Immutable Blob Storage with time-based retention policy |
| GLACIER_DEEP_ARCHIVE | Archive access tier |
| Glue Catalog | Azure Synapse serverless SQL pool over JSON |
| Athena | Synapse serverless SQL / Azure Data Explorer |
| Lifecycle transitions | Lifecycle management policies |

Azure's immutable Blob Storage supports both time-based and legal-hold
retention; for receipt archives, time-based with a locked policy
matches the AWS Object Lock compliance mode semantics.

## What this does not cover

- **Cross-region replication.** Receipts are the durable side of the
  Provenex audit story; the corpus the receipts reference still lives
  in your vector store. CRR for the receipt bucket is one line of
  Terraform (`aws_s3_bucket_replication_configuration`); add it if
  your compliance posture requires multi-region durability.
- **Ed25519 public key archival.** The auditor needs the same
  Ed25519 public key the issuer used. Treat the public key as an
  archive artefact too (commit it to source, plus archive it under
  `pubkeys/<yyyy>/<key_fingerprint>.pem` in the receipt bucket).
- **Witness log archival.** The witness log itself
  (`docs/runbooks/witness_log.md`) is the orthogonal proof-of-
  inclusion artefact. Same pattern works: ship the periodic
  checkpoints to S3 under a separate prefix.
