"""AWS receipt sinks (extra ``[export-aws]``, depends on ``boto3``).

Two sinks for the two common AWS export targets:

    * :class:`SQSSink` — one SQS message per receipt. Good for
      decoupled, retry-friendly consumer pipelines.
    * :class:`S3AppendSink` — one S3 object per receipt under a
      date-hour-partitioned key prefix. Good for long-term archive
      and Athena / Glue analytics.

Both lazy-import boto3 so the core stays stdlib-only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _require_boto3():
    """Import boto3 lazily so the core stays stdlib-only."""
    try:
        import boto3  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "AWS sinks require the [export-aws] extra: "
            "pip install 'provenex-core[export-aws]'"
        ) from e
    return boto3


class SQSSink:
    """Receipt sink that publishes one SQS message per receipt.

    Args:
        queue_url: The full SQS queue URL
            (``https://sqs.us-east-1.amazonaws.com/123456789012/my-queue``).
        client_kwargs: Extra kwargs forwarded to ``boto3.client("sqs", ...)``.
            Useful for region overrides or explicit credentials.
        message_attributes: Optional dict of SQS message attributes
            attached to every receipt. Example:
            ``{"environment": "prod", "tenant": "acme"}``.
    """

    def __init__(
        self,
        queue_url: str,
        *,
        client_kwargs: Optional[Dict[str, Any]] = None,
        message_attributes: Optional[Dict[str, str]] = None,
    ) -> None:
        boto3 = _require_boto3()
        self._queue_url = queue_url
        self._client = boto3.client("sqs", **(client_kwargs or {}))
        self._closed = False
        # Pre-format SQS message attributes (every value must be
        # {"DataType": "String", "StringValue": ...}).
        self._attrs = {
            k: {"DataType": "String", "StringValue": v}
            for k, v in (message_attributes or {}).items()
        }

    def publish(self, receipt: Any) -> None:
        if self._closed:
            from .streaming import SinkClosedError

            raise SinkClosedError("SQSSink is closed")
        body = receipt.to_json(indent=None)
        kwargs: Dict[str, Any] = {"QueueUrl": self._queue_url, "MessageBody": body}
        if self._attrs:
            kwargs["MessageAttributes"] = self._attrs
        self._client.send_message(**kwargs)

    def close(self) -> None:
        # boto3 clients have no explicit close; just mark closed so
        # subsequent publishes raise.
        self._closed = True


class S3AppendSink:
    """Receipt sink that writes one S3 object per receipt under a
    date-hour-partitioned key prefix.

    Key layout (deliberate; matches Athena / Glue / Splunk SmartStore
    partition expectations):

        s3://<bucket>/<prefix>/YYYY/MM/DD/HH/<receipt_id>.json

    One object per receipt — no in-process batching. S3 PUTs are
    cheap; per-receipt objects let an auditor fetch a single receipt
    without scanning a batch. High-volume deployments wanting batched
    objects should layer a customer-side batcher in front (or use
    Kinesis Firehose).

    Args:
        bucket: Destination bucket. Must exist.
        prefix: Key prefix inside the bucket. Default ``"provenex"``.
        client_kwargs: Extra kwargs forwarded to ``boto3.client("s3", ...)``.
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "provenex",
        *,
        client_kwargs: Optional[Dict[str, Any]] = None,
    ) -> None:
        boto3 = _require_boto3()
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._client = boto3.client("s3", **(client_kwargs or {}))
        self._closed = False

    def publish(self, receipt: Any) -> None:
        if self._closed:
            from .streaming import SinkClosedError

            raise SinkClosedError("S3AppendSink is closed")
        now = datetime.now(timezone.utc)
        key = (
            f"{self._prefix}/"
            f"{now.year:04d}/{now.month:02d}/{now.day:02d}/"
            f"{now.hour:02d}/"
            f"{receipt.receipt_id}.json"
        )
        body = receipt.to_json(indent=None).encode("utf-8")
        self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
        )

    def close(self) -> None:
        self._closed = True
