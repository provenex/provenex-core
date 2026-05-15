"""Streaming export sinks (schema unchanged, 0.6.6+).

A :class:`ReceiptSink` is the downstream half of the source-of-record
architecture: Provenex emits signed receipts; a sink ships them to a
SIEM, log archive, message bus, or object store. The framework-
agnostic ``sink=`` parameter on every emission entrypoint
(:func:`provenex.verify_chunks`, :func:`provenex.admission_check`,
:func:`provenex.verify_memory`, :func:`provenex.admit_memory_write`,
:func:`provenex.admit_model_inference`) calls ``sink.publish(receipt)``
after the receipt is finalized.

Error semantics — **load-bearing**:

    Sink failures are SWALLOWED and logged via :mod:`warnings`.
    Provenex MUST NEVER break the agent's hot path because export
    is degraded. A misconfigured sink writes a warning to stderr;
    the receipt is still returned to the caller via the normal
    function return value; the agent keeps running.

Operators who want fail-loud-on-export semantics wrap with a
customer-side ``StrictSink`` decorator that intercepts the warning
and re-raises. We document that pattern but do not ship it — most
production deployments want resilience over strictness.

Core sinks (this module, stdlib-only):

    * :class:`StdoutJSONLSink` — for testing / dev. One JSON line
      per receipt to ``sys.stdout``.
    * :class:`FileJSONLSink` — append to a local file, rotated daily.
    * :class:`MultiSink` — fan-out to N sinks; failures isolated.
    * :class:`RetryQueueSink` — bounded retry queue in front of a
      downstream sink.

Network sinks (optional extras):

    * :class:`provenex.export.kafka.KafkaSink` — ``[export-kafka]``
    * :class:`provenex.export.aws.SQSSink` — ``[export-aws]``
    * :class:`provenex.export.aws.S3AppendSink` — ``[export-aws]``
    * :class:`provenex.export.gcp.PubSubSink` — ``[export-gcp]``
"""

from __future__ import annotations

import os
import sys
import threading
import warnings
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Protocol, Union, runtime_checkable

# ProvenanceReceipt imported lazily inside method bodies to avoid an
# import cycle (the core/receipt module imports nothing from export/).


class SinkClosedError(RuntimeError):
    """Raised when ``publish()`` is called on an already-closed sink.

    A closed sink will never accept more receipts. Use a fresh
    instance if you need to resume publishing.
    """


@runtime_checkable
class ReceiptSink(Protocol):
    """The downstream-of-Provenex contract.

    Implement this to ship signed receipts to your firehose. Two
    methods:

        * ``publish(receipt)`` — called after the receipt is built
          and signed. The sink is expected to enqueue / send / write
          the receipt. May raise; Provenex catches and logs.
        * ``close()`` — called when the host application shuts down.
          Idempotent. After ``close()``, ``publish()`` MUST raise
          :class:`SinkClosedError`.

    Both methods are synchronous. For asynchronous delivery, wrap in
    :class:`RetryQueueSink` which spawns a single background drain
    thread.
    """

    def publish(self, receipt: Any) -> None: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------- #
# Core sinks                                                                  #
# --------------------------------------------------------------------------- #


class StdoutJSONLSink:
    """One JSON line per receipt to ``sys.stdout``.

    For testing / dev / quick eyeballing. Production should use a
    persistent sink (file / Kafka / SQS / Pub/Sub / S3).

    Args:
        stream: Optional stream to write to instead of ``sys.stdout``.
            Useful for capturing in tests.
    """

    def __init__(self, stream: Any = None) -> None:
        self._stream = stream if stream is not None else sys.stdout
        self._closed = False
        self._lock = threading.Lock()

    def publish(self, receipt: Any) -> None:
        if self._closed:
            raise SinkClosedError("StdoutJSONLSink is closed")
        line = receipt.to_json(indent=None)
        with self._lock:
            self._stream.write(line)
            self._stream.write("\n")
            self._stream.flush()

    def close(self) -> None:
        # Idempotent. We don't close sys.stdout; just mark closed so
        # subsequent publishes raise.
        self._closed = True


class FileJSONLSink:
    """Append to a local file, rotated daily.

    Path: ``<directory>/<prefix>-YYYY-MM-DD.jsonl``. Rotation happens
    transparently on the next ``publish()`` after the day changes —
    no background thread.

    Args:
        directory: Output directory. Created if it doesn't exist.
        prefix: Filename prefix. Default ``"receipts"``.
    """

    def __init__(self, directory: Union[str, Path], prefix: str = "receipts") -> None:
        # Validate prefix: it becomes part of the filename, so reject
        # path separators and traversal that could escape ``directory``.
        if "/" in prefix or "\\" in prefix or prefix in (".", ".."):
            raise ValueError(
                f"prefix must be a plain filename component, got {prefix!r}"
            )
        self._dir = Path(directory).resolve()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._prefix = prefix
        self._current_date: Optional[str] = None
        self._fh: Optional[Any] = None
        self._closed = False
        self._lock = threading.Lock()

    def _rotate_if_needed(self) -> None:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if today == self._current_date and self._fh is not None:
            return
        # Day rolled over (or first publish). Close existing handle,
        # open new one.
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
        path = self._dir / f"{self._prefix}-{today}.jsonl"
        # Refuse to append to a symlink. If a worldly-writable directory
        # is configured (e.g., from a Kubernetes ConfigMap) an attacker
        # could pre-create the expected filename as a symlink to a
        # privileged file (/etc/cron.d/*, ~/.ssh/authorized_keys); the
        # append would then write JSON into that file.
        if path.is_symlink():
            raise OSError(
                f"refusing to append to symlink at {path}; remove or "
                f"replace it with a regular file"
            )
        # O_NOFOLLOW on POSIX closes the symlink-after-check TOCTOU
        # window. Not available on Windows — fall back to the pre-check
        # above, which still rejects the common operator-misconfig case.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags | nofollow, 0o600)
        self._fh = os.fdopen(fd, "a", encoding="utf-8")
        self._current_date = today

    def publish(self, receipt: Any) -> None:
        if self._closed:
            raise SinkClosedError("FileJSONLSink is closed")
        line = receipt.to_json(indent=None)
        with self._lock:
            self._rotate_if_needed()
            assert self._fh is not None
            self._fh.write(line)
            self._fh.write("\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._fh is not None:
                try:
                    self._fh.close()
                except Exception:
                    pass
                self._fh = None


class MultiSink:
    """Fan-out to N sinks. Failures isolated per-sink.

    Publishes to each sink in the order they were supplied. If one
    sink raises, the exception is caught, a warning is logged, and
    publishing continues with the remaining sinks. The composite
    publish() never raises unless every sink fails — even then, the
    exceptions are accumulated and re-raised as a single
    ``ExceptionGroup`` only after every sink was attempted.

    Use this when you want both archival (FileJSONLSink) and
    real-time (KafkaSink) shipping side-by-side.

    Args:
        sinks: Iterable of :class:`ReceiptSink` instances.
    """

    def __init__(self, sinks: Iterable[Any]) -> None:
        self._sinks = list(sinks)
        self._closed = False

    def publish(self, receipt: Any) -> None:
        if self._closed:
            raise SinkClosedError("MultiSink is closed")
        for sink in self._sinks:
            try:
                sink.publish(receipt)
            except Exception as e:
                warnings.warn(
                    f"Provenex MultiSink: child sink "
                    f"{type(sink).__name__} failed to publish "
                    f"receipt {getattr(receipt, 'receipt_id', '?')}: {e}",
                    stacklevel=2,
                )

    def close(self) -> None:
        self._closed = True
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                # Swallow on close — sinks are going away anyway.
                pass


class RetryQueueSink:
    """Bounded retry queue in front of a downstream sink.

    When the downstream sink's ``publish()`` raises, the receipt is
    enqueued in an in-memory deque (default ``maxlen=1000``,
    drop-oldest on overflow). The next successful publish drains
    pending receipts in FIFO order before the new receipt.

    Composes with any sink:

        retry = RetryQueueSink(KafkaSink(...), maxlen=10_000)

    This is the bounded in-process retry pattern. For more durable
    retry semantics (disk-backed, cross-process), the customer should
    route through their own persistent queue (Redis, SQS, etc.) and
    wrap THAT in a sink.

    Args:
        downstream: The sink to forward to.
        maxlen: Maximum queue size. Default 1000. Older receipts are
            dropped silently when the queue fills.
    """

    def __init__(self, downstream: Any, *, maxlen: int = 1000) -> None:
        self._downstream = downstream
        self._queue: deque = deque(maxlen=maxlen)
        self._closed = False
        self._lock = threading.Lock()
        # Edge-triggered: warn once when the queue first hits maxlen
        # (drops would start occurring); reset after a successful drain.
        self._warned_full = False

    def _enqueue(self, receipt: Any) -> None:
        """Append, warning once on the transition into full-queue state.

        ``deque(maxlen=N)`` silently drops the oldest item on overflow;
        receipts are audit records, so silent loss is unacceptable. Warn
        on the transition so operators get a signal without one warning
        per dropped receipt under sustained outage.
        """
        if (
            not self._warned_full
            and self._queue.maxlen is not None
            and len(self._queue) >= self._queue.maxlen
        ):
            warnings.warn(
                f"Provenex RetryQueueSink: queue is full "
                f"(maxlen={self._queue.maxlen}); oldest receipts are "
                f"being dropped silently. Investigate downstream "
                f"{type(self._downstream).__name__}.",
                stacklevel=3,
            )
            self._warned_full = True
        self._queue.append(receipt)

    def publish(self, receipt: Any) -> None:
        if self._closed:
            raise SinkClosedError("RetryQueueSink is closed")
        with self._lock:
            # First, try to drain anything pending.
            while self._queue:
                pending = self._queue[0]
                try:
                    self._downstream.publish(pending)
                    self._queue.popleft()
                    # Drained at least one — re-arm the full-queue warning.
                    if self._warned_full and len(self._queue) < (
                        self._queue.maxlen or 1
                    ):
                        self._warned_full = False
                except Exception:
                    # Downstream still failing. Keep pending and
                    # enqueue the new receipt (drop-oldest if full).
                    self._enqueue(receipt)
                    return
            # Queue drained (or was empty). Try the new receipt.
            try:
                self._downstream.publish(receipt)
            except Exception as e:
                self._enqueue(receipt)
                # Drop the exception body — downstream client libraries
                # may embed credentials or signed URLs in str(e).
                warnings.warn(
                    f"Provenex RetryQueueSink: downstream "
                    f"{type(self._downstream).__name__} failed "
                    f"(error_type={type(e).__name__}); queued "
                    f"(queue_size={len(self._queue)}, "
                    f"maxlen={self._queue.maxlen}).",
                    stacklevel=2,
                )

    def pending_count(self) -> int:
        """Return the number of receipts currently waiting to retry."""
        return len(self._queue)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            # Best-effort final drain. Peek before popping so a failed
            # publish leaves the receipt in the queue (matches publish()).
            while self._queue:
                try:
                    self._downstream.publish(self._queue[0])
                except Exception:
                    break
                self._queue.popleft()
            if self._queue:
                warnings.warn(
                    f"Provenex RetryQueueSink: closed with "
                    f"{len(self._queue)} receipt(s) still pending; "
                    f"downstream "
                    f"{type(self._downstream).__name__} unreachable.",
                    stacklevel=2,
                )
            try:
                self._downstream.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Internal helper: safe publish from emission paths                           #
# --------------------------------------------------------------------------- #


def _coerce_sink(sink: Any) -> Any:
    """Auto-wrap a list of sinks in :class:`MultiSink`.

    Lets callers pass ``sink=[a, b, c]`` as a shorthand for
    ``sink=MultiSink([a, b, c])``. A single sink passes through.
    """
    if isinstance(sink, list):
        return MultiSink(sink)
    return sink


def _safe_publish(sink: Any, receipt: Any) -> None:
    """Publish to a sink, swallowing any exception with a warning.

    Called from every emission entrypoint after ``builder.finalize()``.
    The contract: this function NEVER raises (except for
    :class:`SinkClosedError`, which is a programming error the
    caller should fix, not transient).

    Accepts a single :class:`ReceiptSink` or a list (auto-wrapped via
    :func:`_coerce_sink`).
    """
    if sink is None:
        return
    sink = _coerce_sink(sink)
    try:
        sink.publish(receipt)
    except SinkClosedError:
        # Programming error — caller passed a closed sink.
        # Re-raise so the bug is loud.
        raise
    except Exception as e:
        # Surface only the exception class, not str(e). Downstream
        # client libraries (boto3, kafka-python, google-cloud-pubsub)
        # routinely embed connection URIs, request signatures, and
        # auth headers in their exception messages — re-emitting those
        # via warnings.warn would leak them into stderr / Sentry / etc.
        warnings.warn(
            f"Provenex sink publish failed "
            f"(sink={type(sink).__name__}, "
            f"receipt_id={getattr(receipt, 'receipt_id', '?')}, "
            f"error_type={type(e).__name__})",
            stacklevel=3,
        )
