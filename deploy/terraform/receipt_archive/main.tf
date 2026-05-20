# Provenex receipt archive: 7-year compliance retention with per-receipt
# searchability.
#
# Architecture (canonical S3 Object Lock + Athena + Glacier deep-archive
# pattern documented in docs/receipt_retention.md):
#
#   * Hot bucket (S3 STANDARD): receives every new receipt; Object Lock
#     in compliance mode enforces 7-year write-once retention. Athena
#     queries directly against the hot prefix for the first 90 days of
#     receipts when SOC interactivity matters.
#
#   * Cold bucket (S3 Glacier Deep Archive): lifecycle transition at
#     90 days. Cheapest long-term tier. Athena queries here too; cold
#     queries take 12-48h to pre-restore but the 7-year retention
#     guarantee is identical.
#
#   * Athena workgroup + Glue table: receipts are stored one JSON object
#     per file. Glue catalogs the JSON shape; Athena queries any
#     receipt by receipt_id / caller_hash / policy_version_hash without
#     downloading objects.
#
# Out of scope: KMS key for SSE-KMS (call this module with an external
# kms_key_arn), VPC endpoints, CloudTrail audit logging.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.30"
    }
  }
}

variable "bucket_prefix" {
  type        = string
  description = "Globally unique prefix for the S3 buckets (e.g. acme-provenex-receipts)."
}

variable "retention_years" {
  type        = number
  default     = 7
  description = "Object Lock retention period in years; defaults to the SR-11-7 / SOX 7-year horizon."
}

variable "deep_archive_after_days" {
  type        = number
  default     = 90
  description = "Lifecycle transition from STANDARD to DEEP_ARCHIVE."
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "Optional KMS key for SSE-KMS. Falls back to SSE-S3 (AES256) if null."
}

variable "athena_query_results_bucket" {
  type        = string
  description = "S3 bucket where Athena stores query results."
}

# -------------------------------------------------------------------- bucket --

resource "aws_s3_bucket" "receipts" {
  bucket = "${var.bucket_prefix}-receipts"

  # Object Lock requires versioning + can only be enabled at creation
  # time. Once on, every PutObject under the bucket is governed by the
  # retention rule below.
  object_lock_enabled = true

  tags = {
    "provenex.io/purpose"       = "receipt-archive"
    "provenex.io/retention-yrs" = tostring(var.retention_years)
  }
}

resource "aws_s3_bucket_versioning" "receipts" {
  bucket = aws_s3_bucket.receipts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "receipts" {
  bucket = aws_s3_bucket.receipts.id

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = var.retention_years
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "receipts" {
  bucket = aws_s3_bucket.receipts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_public_access_block" "receipts" {
  bucket                  = aws_s3_bucket.receipts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------- lifecycle --

resource "aws_s3_bucket_lifecycle_configuration" "receipts" {
  bucket = aws_s3_bucket.receipts.id

  rule {
    id     = "transition-to-deep-archive"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = var.deep_archive_after_days
      storage_class = "DEEP_ARCHIVE"
    }
  }
}

# ----------------------------------------------------------------- Glue + Athena

resource "aws_glue_catalog_database" "receipts" {
  name = replace("${var.bucket_prefix}-receipts", "-", "_")
}

resource "aws_glue_catalog_table" "receipts" {
  name          = "receipts"
  database_name = aws_glue_catalog_database.receipts.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "json"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.receipts.bucket}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "case.insensitive" = "TRUE"
      }
    }

    # Minimal schema; expand as you add fields you want to query on
    # without UNNEST. The full receipt JSON is always available via
    # the implicit `$path` column too.
    columns {
      name = "receipt_id"
      type = "string"
    }
    columns {
      name = "issued_at"
      type = "string"
    }
    columns {
      name = "caller_hash"
      type = "string"
    }
    columns {
      name = "schema_version"
      type = "string"
    }
    columns {
      name = "policy"
      type = "struct<access_control:struct<policy_version_hash:string>>"
    }
  }
}

resource "aws_athena_workgroup" "receipts" {
  name = "${var.bucket_prefix}-receipts"

  configuration {
    enforce_workgroup_configuration = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${var.athena_query_results_bucket}/athena/"
    }
  }
}

# --------------------------------------------------------------------- outputs

output "bucket_name" {
  value       = aws_s3_bucket.receipts.bucket
  description = "S3 bucket holding the immutable receipt archive."
}

output "glue_database" {
  value       = aws_glue_catalog_database.receipts.name
  description = "Glue catalog database for Athena queries."
}

output "athena_workgroup" {
  value       = aws_athena_workgroup.receipts.name
  description = "Athena workgroup for receipt queries."
}
