# Streaming export — receipts → your firehose

Provenex emits signed receipts; a downstream anomaly detector / SIEM /
archival store reads them. `provenex.export.streaming` is the 1–2-line
firehose that closes the loop: a `ReceiptSink` Protocol plus reference
sinks for stdout, file, Kafka, SQS, S3, and Pub/Sub. Available since
**0.6.6**.

Schema is unchanged — sinks consume serialised receipts; the wire
format stays at 2.3.0.

## TL;DR

```python
from provenex import HmacSha256Signer, RequestContext, admission_check
from provenex.export.streaming import FileJSONLSink

sink = FileJSONLSink("/var/log/provenex")

result = admission_check(
    tool=...,
    request=request,
    signer=HmacSha256Signer(),
    sink=sink,                  # the new parameter
)
# Every receipt-emitting entrypoint accepts ``sink=``. The receipt
# is still returned via the function value; the sink gets a copy.
```

That's it. The host code's hot path is unchanged; the sink runs after
the receipt is finalised.

## The `ReceiptSink` Protocol

```python
from typing import Protocol

class ReceiptSink(Protocol):
    def publish(self, receipt: ProvenanceReceipt) -> None: ...
    def close(self) -> None: ...
```

Two methods, both synchronous. Implement your own when none of the
reference sinks fit.

- `publish(receipt)` is called after the receipt is built and signed.
  It may raise; Provenex catches and logs (see **Error semantics**
  below).
- `close()` is idempotent. After a sink is closed, `publish()` raises
  `SinkClosedError`.

The Protocol is `runtime_checkable` — `isinstance(my_sink, ReceiptSink)`
returns `True` for any duck-typed implementation.

## Reference sinks

### Core (always available, no extras)

```python
from provenex import (
    StdoutJSONLSink, FileJSONLSink, MultiSink, RetryQueueSink,
)
```

- **`StdoutJSONLSink(stream=None)`** — one JSON line per receipt to
  `sys.stdout` (or any writable stream). For testing / dev / quick
  eyeballing.
- **`FileJSONLSink(directory, prefix="receipts")`** — append to a
  local file rotated daily by UTC date:
  `<directory>/<prefix>-YYYY-MM-DD.jsonl`. Rotation happens
  transparently on the next `publish()` after the day changes — no
  background thread.
- **`MultiSink([sink_a, sink_b, ...])`** — fan-out to N sinks.
  Failures are isolated per-sink; if one raises, a warning is logged
  and publishing continues with the remaining sinks.
- **`RetryQueueSink(downstream, maxlen=1000)`** — bounded retry queue
  in front of a downstream sink. When `downstream.publish()` raises,
  the receipt is enqueued in an in-memory deque (drop-oldest on
  overflow). On the next successful publish, pending receipts drain
  in FIFO order before the new receipt.

### Kafka — extra `[export-kafka]`

```bash
pip install "provenex-core[export-kafka]"
```

```python
from provenex.export.kafka import KafkaSink

sink = KafkaSink(
    bootstrap_servers="kafka1.internal:9092,kafka2.internal:9092",
    topic="provenex-receipts",
    # Optional: shard by caller for downstream consumer locality.
    key_field="caller_hash",
    # Pass-through to kafka.KafkaProducer for security, etc.
    producer_kwargs={"security_protocol": "SASL_SSL", "sasl_mechanism": "PLAIN", ...},
)
```

Depends on `kafka-python` (pure Python, no C build deps). Each
message has the receipt JSON as value (UTF-8 bytes); the key is the
field named by `key_field` (default `receipt_id`).

### AWS — extra `[export-aws]`

```bash
pip install "provenex-core[export-aws]"
```

```python
from provenex.export.aws import SQSSink, S3AppendSink

# Message bus: one SQS message per receipt
sqs = SQSSink(
    queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/provenex-receipts",
    message_attributes={"environment": "prod", "tenant": "acme"},
)

# Long-term archive / Athena / Glue: one S3 object per receipt under
# a date-hour-partitioned key:
#   s3://<bucket>/<prefix>/YYYY/MM/DD/HH/<receipt_id>.json
s3 = S3AppendSink(bucket="my-audit-bucket", prefix="provenex")
```

Both lazy-import `boto3`. SQS is best for decoupled, retry-friendly
pipelines; S3 is best for long-term archive with Athena / Glue
analytics. Use them together via `MultiSink([sqs, s3])`.

### GCP Pub/Sub — extra `[export-gcp]`

```bash
pip install "provenex-core[export-gcp]"
```

```python
from provenex.export.gcp import PubSubSink

sink = PubSubSink(project_id="my-project", topic_id="provenex-receipts")
```

Depends on `google-cloud-pubsub`. Subscribers receive the receipt JSON
as message data; correlation attributes (`receipt_id`, `caller_hash`,
`trajectory_id`, `step_kind`) are attached so subscriber filters work
without parsing the JSON body.

## Where `sink=` is accepted

Every receipt-emitting entrypoint accepts an optional `sink=`:

```python
# Framework-agnostic
verify_chunks(..., sink=sink)
verify_memory(..., sink=sink)
admission_check(..., sink=sink)
admit_memory_write(..., sink=sink)
admit_model_inference(..., sink=sink)

# Framework wrappers — sink= on the constructor / factory
ProvenexRetriever(..., sink=sink)              # LangChain
ProvenexToolWrapper(..., sink=sink)            # LangChain Phase 2
provenex_retrieval_node(..., sink=sink)        # LangGraph
provenex_admission_node(..., sink=sink)        # LangGraph Phase 2
provenex_mcp_admission(..., sink=sink)         # MCP
ProvenexLlamaIndexRetriever(..., sink=sink)    # LlamaIndex

# CrewAI session — constructor + add_sink()
session = ProvenexCrewSession(..., sink=sink)
session.add_sink(other_sink)                   # accumulates
```

A single sink or a list of sinks is accepted everywhere — passing
`sink=[a, b]` is auto-wrapped as `MultiSink([a, b])` internally.

## Error semantics — load-bearing

**Sink failures are swallowed and logged via `warnings.warn`.**
Provenex must never break the agent's hot path because export is
degraded. A misconfigured Kafka cluster, an SQS quota error, an S3
permissions issue — all produce a warning on stderr and the receipt
keeps flowing through the function return value. The agent keeps
running.

```python
# A failing sink:
class Broken:
    def publish(self, r): raise RuntimeError("downstream is down")
    def close(self): pass

result = admission_check(..., sink=Broken())
# result.receipt is still complete; a warning was emitted to stderr.
```

If you want **fail-loud-on-export** semantics (rare — production
deployments almost always want resilience), wrap your sink in your
own strict adapter:

```python
class StrictSink:
    """Re-raise instead of swallowing."""
    def __init__(self, inner): self._inner = inner
    def publish(self, r):
        try: self._inner.publish(r)
        except Exception:
            raise   # propagate — Provenex's _safe_publish will still warn,
                    # then the exception bubbles back up through your caller.
    def close(self): self._inner.close()
```

Note: even with `StrictSink`, Provenex's `_safe_publish` still
catches the re-raise and logs — that's by design. The strict path
needs to instrument your own code, not Provenex's. We do not ship
`StrictSink` for that reason — most production deployments want
resilience by default, and the few that don't can write the
appropriate adapter at their boundary.

## Retry semantics

`RetryQueueSink` is the in-process retry pattern: bounded queue
(default 1000), drop-oldest on overflow, FIFO drain on the next
successful publish.

```python
sink = RetryQueueSink(KafkaSink(...), maxlen=10_000)
```

For more durable retry semantics (cross-process, disk-backed), the
customer's pipeline should route receipts through a persistent queue
(Redis, SQS, Kafka itself with mirror) and wrap **that** in a sink.
Provenex's in-process retry is meant for transient broker hiccups,
not multi-hour outages.

Inspect the queue at runtime:

```python
retry = RetryQueueSink(KafkaSink(...))
# ... after some publishes ...
print(retry.pending_count())   # how many receipts waiting to retry
```

## Implementing your own sink

```python
from provenex import ReceiptSink

class MyCustomSink:
    def __init__(self):
        self._closed = False

    def publish(self, receipt) -> None:
        if self._closed:
            from provenex import SinkClosedError
            raise SinkClosedError("MyCustomSink is closed")
        body = receipt.to_json(indent=None)   # one-line JSON
        # ... ship it ...

    def close(self) -> None:
        # Idempotent: safe to call repeatedly.
        self._closed = True

assert isinstance(MyCustomSink(), ReceiptSink)   # runtime_checkable
```

Use `receipt.to_json(indent=None)` for compact one-line JSON
(suitable for JSONL); use `receipt.to_json(indent=2)` for the
human-readable form. The receipt's canonical-bytes payload (what the
signature covers) is `receipt.canonical_payload()` — useful when
publishing to a system that also verifies the signature
independently.

## Multi-sink composition

Real deployments usually want at least two destinations: a real-time
firehose (Kafka / Pub/Sub) for the detector, and a long-term archive
(S3 / file) for compliance. Compose with `MultiSink`:

```python
from provenex import MultiSink, FileJSONLSink
from provenex.export.kafka import KafkaSink
from provenex.export.aws import S3AppendSink

sink = MultiSink([
    KafkaSink(bootstrap_servers="...", topic="provenex-receipts"),
    S3AppendSink(bucket="audit-archive", prefix="provenex"),
    FileJSONLSink("/var/log/provenex"),
])

# Each receipt now lands in three places. One sink failing doesn't
# affect the others.
```

Pair with a retry queue in front of the network sinks:

```python
sink = MultiSink([
    RetryQueueSink(KafkaSink(...), maxlen=10_000),
    RetryQueueSink(S3AppendSink(...), maxlen=10_000),
    FileJSONLSink("/var/log/provenex"),    # local file rarely fails
])
```

## Examples

- [`examples/streaming_export_demo.py`](../examples/streaming_export_demo.py)
  — pure stdlib end-to-end. Generates ~5 receipts across mixed step
  kinds, ships them to a `MultiSink([StdoutJSONLSink(),
  FileJSONLSink(temp_dir)])`, prints the resulting JSONL contents,
  and demonstrates the retry queue absorbing a flaky downstream.

- The "Reading receipts as an anomaly-detection event stream" section
  of [`quickstart.md`](quickstart.md) shows the consumer side — how
  to `GROUP BY caller_hash` and `GROUP BY session_id` over the JSONL
  stream that comes out of `FileJSONLSink`.
