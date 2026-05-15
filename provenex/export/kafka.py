"""Kafka receipt sink (extra ``[export-kafka]``, depends on ``kafka-python``).

Pure-Python Kafka client — no C build dependency. Sufficient for the
durability requirements Provenex sets (signed events with retry queue
in front; not high-frequency tick data).

Usage:

    from provenex.export.kafka import KafkaSink

    sink = KafkaSink(
        bootstrap_servers="kafka1.internal:9092,kafka2.internal:9092",
        topic="provenex-receipts",
    )
    result = provenex.admission_check(..., sink=sink)
    # ...
    sink.close()   # producer.flush() + close()
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def _require_kafka_python():
    """Import kafka-python lazily so the core stays stdlib-only."""
    try:
        from kafka import KafkaProducer  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "KafkaSink requires the [export-kafka] extra: "
            "pip install 'provenex-core[export-kafka]'"
        ) from e
    return KafkaProducer


class KafkaSink:
    """Receipt sink that publishes one message per receipt to a Kafka topic.

    The receipt JSON is the message value (UTF-8 bytes). The message
    key is the ``receipt_id`` (so all messages for one receipt land on
    the same partition if you ever shard by receipt — though normally
    you'd shard by ``caller_hash`` for downstream consumer locality).

    Args:
        bootstrap_servers: Kafka bootstrap server string
            (``"host:port"`` or comma-separated for a cluster).
        topic: Target topic. The topic must exist; KafkaSink doesn't
            create topics.
        key_field: Which receipt field becomes the Kafka message key.
            Default ``"receipt_id"``. Pass ``"caller_hash"`` if your
            downstream consumers shard by caller.
        producer_kwargs: Extra kwargs forwarded to
            ``kafka.KafkaProducer``. Useful for security
            (``security_protocol``, ``sasl_*``, ``ssl_*``).
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        *,
        key_field: str = "receipt_id",
        producer_kwargs: Optional[Dict[str, Any]] = None,
    ) -> None:
        KafkaProducer = _require_kafka_python()
        self._topic = topic
        self._key_field = key_field
        self._producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: v.encode("utf-8"),
            key_serializer=lambda v: v.encode("utf-8") if v else None,
            **(producer_kwargs or {}),
        )
        self._closed = False

    def publish(self, receipt: Any) -> None:
        if self._closed:
            from .streaming import SinkClosedError

            raise SinkClosedError("KafkaSink is closed")
        receipt_dict = receipt.to_dict()
        key = receipt_dict.get(self._key_field) or receipt_dict.get("receipt_id")
        value = receipt.to_json(indent=None)
        future = self._producer.send(self._topic, key=key, value=value)
        # Block briefly on the per-message send to surface broker
        # errors synchronously — Provenex's swallow-and-log wrapper
        # ((_safe_publish) catches them. Without get(), errors would
        # only surface at flush() time.
        future.get(timeout=10)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._producer.flush(timeout=10)
        finally:
            self._producer.close(timeout=10)
            self._closed = True
