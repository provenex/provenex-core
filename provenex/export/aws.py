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

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_logger = logging.getLogger("provenex.export.aws")

# SQS hard limit per message (262144 bytes).
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html
_SQS_MESSAGE_MAX_BYTES = 262_144


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
        body_bytes = len(body.encode("utf-8"))
        if body_bytes > _SQS_MESSAGE_MAX_BYTES:
            # Surface the size + receipt id so the operator can locate
            # the offending receipt; raise so _safe_publish records a
            # warning that the publish failed. SQS would reject the
            # send with InvalidParameterException anyway, but the
            # operator can't connect that to "your receipt is too big"
            # without this preflight.
            receipt_id = getattr(receipt, "receipt_id", "?")
            _logger.warning(
                "SQSSink: receipt %s body is %d bytes, exceeds SQS limit "
                "(%d); skipping publish. Route large receipts through "
                "S3AppendSink or split the trajectory.",
                receipt_id, body_bytes, _SQS_MESSAGE_MAX_BYTES,
            )
            raise ValueError(
                f"SQS message body {body_bytes} bytes exceeds SQS limit "
                f"of {_SQS_MESSAGE_MAX_BYTES} bytes (receipt {receipt_id})"
            )
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

    .. note::
        "Append" in the name refers to **append-to-the-partition**, not
        append-to-an-object. S3 has no append operation: each
        :meth:`publish` is an independent ``PutObject`` writing a new
        key. The objects are immutable once written, which is the
        property that makes them safe to set Object-Lock + Glacier
        retention on (see :mod:`docs.receipt_retention`). The sink does
        not deduplicate on retry; an upstream network failure that
        causes Provenex to retry a publish may produce two objects
        with the same ``receipt_id`` in the same hour partition. Pair
        with S3 versioning if at-most-once write semantics matter to
        you.

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
