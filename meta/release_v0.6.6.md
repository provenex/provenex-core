# Release notes — v0.6.6

**Headline.** Streaming export. `provenex.export.streaming` ships the `ReceiptSink` Protocol and reference sinks (stdout, file, multi, retry-queue in the stdlib core; Kafka, SQS, S3, Pub/Sub behind optional extras). Every emission entrypoint accepts a `sink=` parameter. Sink failures are swallowed-and-logged so the agent's hot path is never broken by export degradation. No schema bump — sinks consume the existing 2.3.0 wire format.

## What's new since 0.6.5

### `provenex.export.streaming` (new module, stdlib core)

- **`ReceiptSink`** Protocol — the downstream-of-Provenex contract. Two methods: `publish(receipt)` and idempotent `close()`. `runtime_checkable` — your custom sinks satisfy the Protocol structurally.

- **Core sinks (always available, no extras):**
    - `StdoutJSONLSink(stream=None)` — one JSON line per receipt to `sys.stdout` (or any writable stream). For testing / dev.
    - `FileJSONLSink(directory, prefix="receipts")` — append to a local file rotated daily by UTC date. Path: `<directory>/<prefix>-YYYY-MM-DD.jsonl`. No background thread; rotation happens transparently on the next publish after the day rolls.
    - `MultiSink([sink_a, sink_b, ...])` — fan-out to N sinks. Failures isolated per-sink; one failing sink doesn't block the others.
    - `RetryQueueSink(downstream, maxlen=1000)` — bounded retry queue in front of any sink. Failed publishes enqueue (drop-oldest on overflow); the next successful publish drains pending receipts in FIFO order. Inspect with `pending_count()`.
    - `SinkClosedError` — raised when `publish()` is called on a closed sink.

### Network sinks (optional extras)

- **`provenex.export.kafka.KafkaSink`** — extra `[export-kafka]`, depends on `kafka-python` (pure Python, no C build deps). One Kafka message per receipt; configurable message-key field for downstream consumer locality.

- **`provenex.export.aws.SQSSink`** + **`provenex.export.aws.S3AppendSink`** — extra `[export-aws]`, depends on `boto3`. SQS for decoupled message-bus pipelines; S3 for long-term archive with date-hour-partitioned keys (`s3://<bucket>/<prefix>/YYYY/MM/DD/HH/<receipt_id>.json` — Athena / Glue / Splunk SmartStore-friendly).

- **`provenex.export.gcp.PubSubSink`** — extra `[export-gcp]`, depends on `google-cloud-pubsub`. Per-receipt correlation attributes (`receipt_id`, `caller_hash`, `trajectory_id`, `step_kind`) attached so subscriber filters work without parsing the JSON body.

### Wiring across every emission entrypoint

`sink=` is a new optional parameter on:

- Framework-agnostic: `verify_chunks`, `verify_memory`, `admission_check`, `admit_memory_write`, `admit_model_inference`.
- LangChain: `ProvenexRetriever`, `ProvenexToolWrapper`.
- LangGraph: `provenex_retrieval_node`, `provenex_admission_node`.
- LlamaIndex: `ProvenexLlamaIndexRetriever`.
- MCP: `provenex_mcp_admission`, `wrap_mcp_request`.
- CrewAI: `ProvenexCrewSession(sink=...)` constructor + new `session.add_sink(sink)` accumulator method.

Pass either a single sink or a list — `sink=[a, b]` is auto-wrapped as `MultiSink([a, b])` internally.

### Error semantics — load-bearing

**Sink failures are swallowed and logged via `warnings.warn`.** Provenex must never break the agent's hot path because export is degraded. A misconfigured Kafka cluster writes a warning to stderr; the receipt is still returned to the caller through the function value; the agent keeps running.

Operators who want fail-loud-on-export semantics implement a customer-side `StrictSink` decorator that re-raises (documented pattern in [`docs/streaming_export.md`](docs/streaming_export.md#error-semantics---load-bearing)). We do not ship `StrictSink` because production deployments overwhelmingly want resilience over strictness.

### Comprehensive doc + example sweep

- New: [`docs/streaming_export.md`](docs/streaming_export.md) — full reference. Protocol shape, every reference sink, error semantics, retry semantics, custom-sink implementation, multi-sink composition.
- `README.md`: new "Streaming receipts to a SIEM / firehose" subsection; OSS feature list updated; install commands for the three new extras.
- `docs/quickstart.md`: new "Streaming receipts to a SIEM / firehose" section.
- New example: [`examples/streaming_export_demo.py`](examples/streaming_export_demo.py) — runnable end-to-end. Fan-out across StdoutJSONLSink + FileJSONLSink + an in-memory KafkaSink stand-in; demonstrates auto-coerce from sink-list; demonstrates RetryQueueSink absorbing a flaky downstream that fails twice then succeeds.

## Compatibility

- **No schema bump.** Wire format stays at `2.3.0`. Streaming sinks consume the existing receipt JSON unchanged.
- **Backward compatible across the board.** Every `sink=` parameter defaults to `None` — existing callers see no behavior change.
- **`ProvenexCrewSession` constructor:** new `sink=` kwarg at the end; existing positional / keyword construction unaffected. The new `add_sink()` method is additive.
- **`provenex_mcp_admission`:** new `sink=` kwarg; the existing `receipts_sink=` (list-append) keeps working for back-compat.
- **Postgres backend (0.6.5 hardening) unchanged.**

## Example

```python
from provenex import (
    HmacSha256Signer, RequestContext, ToolCallContext,
    admission_check, MultiSink, FileJSONLSink, RetryQueueSink,
)
from provenex.export.kafka import KafkaSink   # extra: [export-kafka]
from provenex.export.aws import S3AppendSink  # extra: [export-aws]

# Real-time firehose for the detector + long-term archive for compliance.
# Retry queues in front of the network sinks absorb transient broker hiccups.
sink = MultiSink([
    RetryQueueSink(
        KafkaSink(bootstrap_servers="kafka.internal:9092", topic="provenex-receipts"),
        maxlen=10_000,
    ),
    RetryQueueSink(
        S3AppendSink(bucket="audit-archive", prefix="provenex"),
        maxlen=10_000,
    ),
    FileJSONLSink("/var/log/provenex"),   # local file rarely fails
])

result = admission_check(
    tool=ToolCallContext(name="jira", operation="create_issue", parameters={...}),
    request=RequestContext(...),
    signer=HmacSha256Signer(),
    sink=sink,
)
# Receipt landed in three destinations. The host code's hot path is
# unchanged. If Kafka is degraded, the warning hits stderr, the
# receipt still rides on S3 + the local file, and the retry queue
# absorbs the Kafka backlog until the broker recovers.
```

## Install

```bash
pip install provenex-core==0.6.6
pip install "provenex-core[policy]==0.6.6"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[postgres]==0.6.6"      # Postgres backend (UTF8-hardened in 0.6.5)
pip install "provenex-core[langgraph]==0.6.6"     # LangGraph nodes
pip install "provenex-core[crewai]==0.6.6"        # CrewAI session + admission
pip install "provenex-core[langchain]==0.6.6"     # LangChain retriever + admission wrapper
pip install "provenex-core[ed25519]==0.6.6"       # asymmetric receipt signing
pip install "provenex-core[export-kafka]==0.6.6"  # KafkaSink (kafka-python)
pip install "provenex-core[export-aws]==0.6.6"    # SQSSink / S3AppendSink (boto3)
pip install "provenex-core[export-gcp]==0.6.6"    # PubSubSink (google-cloud-pubsub)
```
