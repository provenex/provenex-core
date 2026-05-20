# Streaming export: operational notes

The SDK surface for receipt streaming sinks is documented in [streaming_export.md](streaming_export.md): the `ReceiptSink` Protocol, the reference sinks, the `sink=` parameter on every emission entrypoint. This doc covers the operational side: how sinks behave under production conditions, what to do when downstream is slow or offline, and the quirks of the OCSF mapping path.

If you are wiring sinks in for the first time, read [streaming_export.md](streaming_export.md) first. This doc assumes you have a basic sink setup and are now operationalising it.

## Sink-failure semantics

**Sink failures are swallowed and logged via `warnings.warn`.** Provenex's hot path is never broken by export degradation. A misconfigured Kafka cluster, an SQS quota error, an S3 permissions issue, a TCP timeout on Pub/Sub: each produces a warning on stderr and the receipt continues to flow through the function return value. The agent keeps running.

**What the warning looks like.** The exception class name is logged; the exception body is **not**. This was a deliberate hardening in 0.7.0: third-party SDKs (boto3, kafka-python, google-cloud-pubsub) routinely embed connection URIs, request signatures, and SSL/auth-time strings in exception bodies. Routing those to stderr (and then to Sentry / Datadog) leaks credentials.

```
UserWarning: ReceiptSink.publish raised KafkaError; receipt not exported
```

That is the format. If you need the exception body for triage, instrument your own logger inside a custom `ReceiptSink` wrapper; do not rely on the warning channel.

**Receipts that failed to ship.** A receipt whose sink call raised is **not** queued for retry by default. The receipt is in the calling process's return value (`result.receipt`); the caller can persist it elsewhere if the sink failure is operationally significant. Wrap the sink in `RetryQueueSink` for in-process retry; see **Backpressure and retry** below.

**Fail-loud variant.** A few deployments want sink failures to propagate (compliance contexts where unrecorded receipts are unacceptable). Implement a `StrictSink` wrapper:

```python
class StrictSink:
    def __init__(self, inner): self._inner = inner
    def publish(self, r):
        try:
            self._inner.publish(r)
        except Exception:
            raise   # bubble back to the caller
    def close(self):
        self._inner.close()
```

Even with `StrictSink`, Provenex's `_safe_publish` still swallows-and-warns; the strict behavior must be instrumented in your *own* code path (catch the re-raise where you call `verify_chunks` and act on it). We do not ship `StrictSink` for that reason.

## Backpressure and retry

**The in-process retry queue.** `RetryQueueSink(downstream, maxlen=N)` buffers receipts whose downstream call failed and drains them in FIFO order on the next successful publish. Inspect with `pending_count()`. Designed for transient broker hiccups, not multi-hour outages.

```python
from provenex import RetryQueueSink
from provenex.export.kafka import KafkaSink

retry_kafka = RetryQueueSink(
    KafkaSink(bootstrap_servers="kafka:9092", topic="provenex"),
    maxlen=10_000,
)
verify_chunks(..., sink=retry_kafka)
```

**Drop-oldest on overflow.** When the queue reaches `maxlen`, the oldest queued receipt is dropped to make room for the new one. An edge-triggered warning fires when the queue first hits full state; it re-arms once the queue drains below full. This is the right behavior for a real-time firehose where stale receipts matter less than current ones, but **it does mean receipts can be lost under sustained outage**. For audit-grade durability, queue to a persistent store, not the in-process deque.

**Persistent retry.** Wrap your sink in a persistent queue at the OS layer (a local Redis with append-only persistence, a disk-backed message broker, a local SQS-style queue). The persistent queue absorbs the outage; the Provenex sink reads from it and ships to the eventual destination. Provenex's in-process retry queue is fast and bounded; persistence is your operating-system's job, not Provenex's.

**Close-time drain.** `RetryQueueSink.close()` drains pending receipts to the downstream before returning. If the downstream is still failing at close time, the un-shipped receipts are logged via warning so the operator sees how many were abandoned. This was a hardening in 0.7.0.

**Multi-sink fan-out.** `MultiSink([a, b, c])` ships each receipt to every wrapped sink. A failure in one sink does not block the others; failures are isolated per-sink. Combine with `RetryQueueSink` per downstream:

```python
sink = MultiSink([
    RetryQueueSink(KafkaSink(...), maxlen=10_000),
    RetryQueueSink(S3AppendSink(...), maxlen=10_000),
    FileJSONLSink("/var/log/provenex"),  # local file rarely fails
])
```

A failing Kafka does not stop S3; a failing S3 does not stop the local file. Configure a local-file sink as the durable fallback.

## Recovering from a sink that was offline

When a downstream sink (Kafka, SQS, Pub/Sub) has been offline for longer than the in-process retry queue can absorb, the receipts produced during the outage are not in the downstream store. Recovery depends on what else they landed in.

**If a local FileJSONLSink was in your `MultiSink`:** the receipts are on disk under `/var/log/provenex/receipts-YYYY-MM-DD.jsonl`. Replay to the recovered downstream:

```python
import json
from provenex.export.kafka import KafkaSink

kafka = KafkaSink(bootstrap_servers="kafka:9092", topic="provenex")
for line in open("/var/log/provenex/receipts-2026-05-20.jsonl"):
    receipt_dict = json.loads(line)
    # Ship through the sink interface; the receipt's signature is unchanged.
    kafka.publish(_FakeReceipt(receipt_dict))   # construct a tiny shim that publish() can consume
```

The receipts' signatures still verify; replay does not weaken any audit property.

**If no local fallback was in your sink configuration:** the receipts produced during the outage are not in any durable store. The Provenex receipts in the return value are short-lived in process memory; once the calling code has consumed them, they're gone. Configure at least one local fallback in your sink so an outage does not lose receipts:

```python
sink = MultiSink([
    network_sink,                       # fails during outage
    FileJSONLSink("/var/log/provenex"), # never fails; survives the outage
])
```

**OCSFAdapter recovery.** Receipts streamed through `OCSFAdapter` are converted to OCSF events on the way to the downstream. The conversion is pure (no state, no I/O); replay through the adapter produces the same OCSF events. Recovery works identically: replay through `OCSFAdapter(downstream=recovered_sink)` against the local raw archive, and the SIEM receives the events as if the outage never happened.

## OCSF mapping consistency

The OCSF mapping (see [ocsf_mapping.md](ocsf_mapping.md) for the field-by-field) has a few operational quirks worth surfacing.

**One receipt becomes one to many OCSF events.** A retrieval receipt with three allowed sources becomes three `Application Activity` (6005) events. A tool-call receipt with one allowed action becomes one `API Activity` (6003) event. A receipt with both retrieval blocks and admission denies becomes a mix of `Detection Finding` (2004) events plus per-allowed-source / per-allowed-action events. Counts in your SIEM are event counts, not receipt counts; the conversion factor depends on the receipt shape.

**Verbatim parameters / values / prompts never land on OCSF events.** The mapping deliberately omits them, regardless of whether the receipt itself recorded them. The hash anchor on `api.request.uid` is the auditor's re-derivation point. Receipts that recorded the verbatim values keep them on the receipt (the raw archive); the OCSF stream carries only the hash.

**Severity routing.** `Detection Finding` events for verification blocks (TAMPERED, UNAUTHORIZED-and-blocked) come through at `severity_id=5` (Critical). Policy denies come through at `severity_id=4` (High). Your SIEM's alert-routing rules can dispatch on these without inspecting the body. The severity assignment is in [ocsf_mapping.md § Severity assignment](ocsf_mapping.md#severity-assignment).

**Correlation fields and SIEM joins.** `metadata.correlation_uid` (mirrors `trajectory.trajectory_id`) and `metadata.session_uid` (`trajectory.session_id`) are the join keys for reconstructing trajectories. `actor.user.uid` (mirrors `caller_hash`) is the per-user grouping key. These three fields are the correlation surface for OCSF-aware queries; SIEM rules over Provenex events join on them, not on the raw receipt content.

**Suppressing the correlation_uid for single-step receipts.** Pass `include_trajectory_correlator=False` to `receipt_to_ocsf(...)` when the trajectory is implicit (single-step, non-DAG flows). The OCSF events still verify but do not advertise a correlation that does not exist.

## Sink configuration checklist

A production sink configuration:

- [ ] At least one local fallback (`FileJSONLSink`) in the `MultiSink` so an outage does not lose receipts.
- [ ] Network sinks wrapped in `RetryQueueSink` with a `maxlen` matched to your expected outage duration.
- [ ] The chosen network sink's broker has at-least-once delivery semantics (Kafka with `min.insync.replicas`, SQS FIFO, S3 with versioning).
- [ ] A signature-verification step at the downstream consumer that rejects unsigned or invalid receipts (the consumer holds the verifier-side key material).
- [ ] An alarm on unsigned receipts in production: a production detector should never see an unsigned receipt; the appearance of one is itself an alarm condition.
- [ ] Log routing for the `warnings.warn` channel so sink failures are visible in your log aggregation.

## Read next

- [streaming_export.md](streaming_export.md): the SDK surface for sinks.
- [ocsf_mapping.md](ocsf_mapping.md): the OCSF v1.3 field-by-field mapping.
- [anomaly_detection.md § Trust model for the detector](anomaly_detection.md#trust-model-for-the-detector): the detector-side trust posture.
- [runbooks/disaster_recovery.md](runbooks/disaster_recovery.md): the broader recovery procedures.
