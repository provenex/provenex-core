"""Provenex export — streaming receipts to downstream sinks (0.6.6+).

Provenex emits signed receipts; an anomaly detector / SIEM / archival
store reads them downstream. ``provenex.export.streaming`` is the
1-2-line firehose: a :class:`ReceiptSink` Protocol plus reference
sinks for stdout, file, Kafka, SQS, S3, and Pub/Sub.

The core sinks (stdout, file, multi, retry-queue) ship in the pure-
stdlib core. The network sinks live behind optional extras
(``[export-kafka]``, ``[export-aws]``, ``[export-gcp]``) so the core
never grows third-party dependencies.

Every emission entrypoint accepts an optional ``sink=`` parameter and
calls ``sink.publish(receipt)`` after the receipt is finalized.
Sink failures are swallowed and logged via :mod:`warnings` — Provenex
never breaks the agent's hot path because export is degraded.
"""

from .ocsf import (
    OCSF_CATEGORY_APPLICATION_ACTIVITY,
    OCSF_CATEGORY_FINDINGS,
    OCSF_CLASS_API_ACTIVITY,
    OCSF_CLASS_APPLICATION_ACTIVITY,
    OCSF_CLASS_DETECTION_FINDING,
    OCSFAdapter,
    receipt_to_ocsf,
)
from .streaming import (
    FileJSONLSink,
    MultiSink,
    ReceiptSink,
    RetryQueueSink,
    SinkClosedError,
    StdoutJSONLSink,
)

__all__ = [
    "ReceiptSink",
    "StdoutJSONLSink",
    "FileJSONLSink",
    "MultiSink",
    "RetryQueueSink",
    "SinkClosedError",
    # OCSF export (0.6.7+)
    "OCSFAdapter",
    "receipt_to_ocsf",
    "OCSF_CLASS_APPLICATION_ACTIVITY",
    "OCSF_CLASS_API_ACTIVITY",
    "OCSF_CLASS_DETECTION_FINDING",
    "OCSF_CATEGORY_APPLICATION_ACTIVITY",
    "OCSF_CATEGORY_FINDINGS",
]
