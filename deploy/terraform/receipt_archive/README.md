# `receipt_archive` Terraform module

Stands up the canonical S3 Object Lock + Glacier Deep Archive + Athena
pattern documented in [docs/receipt_retention.md](../../../docs/receipt_retention.md).

Receipts land in an Object-Lock bucket in compliance mode (7-year
default), age into Deep Archive after 90 days, and stay queryable via
Athena over a Glue catalog the whole time.

## Apply

```hcl
module "provenex_receipts" {
  source = "github.com/provenex/provenex-core//deploy/terraform/receipt_archive"

  bucket_prefix               = "acme-provenex"
  retention_years             = 7
  deep_archive_after_days     = 90
  athena_query_results_bucket = "acme-athena-results"
}
```

Then `terraform init && terraform apply`.

## Smoke testing with LocalStack

The module is LocalStack-friendly for CI:

```bash
docker run --rm -d -p 4566:4566 localstack/localstack:latest

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export TF_VAR_athena_query_results_bucket=acme-athena-results

terraform init
terraform plan -var bucket_prefix=test-provenex
# In CI you typically validate the plan rather than apply against
# LocalStack — Object Lock + Glacier transitions need real AWS to
# fully exercise the lifecycle.
```

Note: LocalStack's free tier does not implement Object Lock
compliance-mode retention exactly the way AWS does. The plan validates
clean; the lifecycle and retention semantics need a real AWS account
for a faithful end-to-end test.

## Variables

| Name | Default | Notes |
|---|---|---|
| `bucket_prefix` | (required) | Globally unique prefix; `<prefix>-receipts` is the bucket name. |
| `retention_years` | 7 | Object Lock retention; the SR-11-7 / SOX 7-year horizon. |
| `deep_archive_after_days` | 90 | Lifecycle transition from STANDARD → DEEP_ARCHIVE. |
| `kms_key_arn` | null | Optional SSE-KMS key; falls back to SSE-S3 if null. |
| `athena_query_results_bucket` | (required) | Where Athena writes query results (separate bucket). |

## Outputs

| Name | Purpose |
|---|---|
| `bucket_name` | The receipt archive bucket (point your shipping pipeline here). |
| `glue_database` | Glue DB for Athena queries against the JSON receipts. |
| `athena_workgroup` | Workgroup name; reference it from query tooling. |

## Companion piece

The Helm chart's witness-publisher CronJob is what writes new receipts
to this bucket on a schedule. See
[deploy/helm/provenex-server/templates/cronjob-witness.yaml](../../helm/provenex-server/templates/cronjob-witness.yaml).
