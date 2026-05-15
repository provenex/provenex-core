"""GCP Pub/Sub receipt sink (extra ``[export-gcp]``).

Depends on ``google-cloud-pubsub``. Lazy-imported so the core stays
stdlib-only.

Usage:

    from provenex.export.gcp import PubSubSink

    sink = PubSubSink(project_id="my-project", topic_id="provenex-receipts")
    result = provenex.admission_check(..., sink=sink)
    # ...
    sink.close()
"""

from __future__ import annotations

from typing import Any, Dict, Optional


def _require_pubsub():
    """Import google-cloud-pubsub lazily so the core stays stdlib-only."""
    try:
        from google.cloud import pubsub_v1  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "PubSubSink requires the [export-gcp] extra: "
            "pip install 'provenex-core[export-gcp]'"
        ) from e
    return pubsub_v1


class PubSubSink:
    """Receipt sink that publishes one Pub/Sub message per receipt.

    The receipt JSON is the message data (UTF-8 bytes). Per-receipt
    attributes are attached so subscribers can filter without
    parsing the JSON body — ``receipt_id``, ``caller_hash``,
    ``trajectory_id`` (if present), ``step_kind`` (if present).

    Args:
        project_id: GCP project containing the topic.
        topic_id: Pub/Sub topic name (just the name, not the full
            resource path — ``PubSubSink`` builds the path).
        publisher_kwargs: Extra kwargs forwarded to
            ``pubsub_v1.PublisherClient(...)``.
        wait_for_publish: When True (default), each ``publish`` call
            blocks briefly on the per-message Future so broker
            errors surface synchronously (Provenex's
            ``_safe_publish`` wrapper then catches them). When False,
            messages are fire-and-forget — faster, but failures only
            surface at ``close()``.
    """

    def __init__(
        self,
        project_id: str,
        topic_id: str,
        *,
        publisher_kwargs: Optional[Dict[str, Any]] = None,
        wait_for_publish: bool = True,
    ) -> None:
        pubsub_v1 = _require_pubsub()
        self._publisher = pubsub_v1.PublisherClient(**(publisher_kwargs or {}))
        self._topic_path = self._publisher.topic_path(project_id, topic_id)
        self._wait = wait_for_publish
        self._closed = False

    def publish(self, receipt: Any) -> None:
        if self._closed:
            from .streaming import SinkClosedError

            raise SinkClosedError("PubSubSink is closed")
        receipt_dict = receipt.to_dict()
        data = receipt.to_json(indent=None).encode("utf-8")
        # Attributes must be strings.
        attrs: Dict[str, str] = {"receipt_id": str(receipt_dict["receipt_id"])}
        if "caller_hash" in receipt_dict:
            attrs["caller_hash"] = str(receipt_dict["caller_hash"])
        if "trajectory" in receipt_dict and receipt_dict["trajectory"]:
            traj = receipt_dict["trajectory"]
            attrs["trajectory_id"] = str(traj.get("trajectory_id", ""))
            if traj.get("step_kind"):
                attrs["step_kind"] = str(traj["step_kind"])
        future = self._publisher.publish(self._topic_path, data, **attrs)
        if self._wait:
            future.result(timeout=10)

    def close(self) -> None:
        if self._closed:
            return
        # Newer pubsub_v1 PublisherClient has no explicit close;
        # transports are managed lazily. Mark closed defensively.
        self._closed = True
