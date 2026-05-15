"""Streaming export demo (0.6.6+).

Run with:

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/streaming_export_demo.py

What it shows, in order:

    1. Set up a ``MultiSink`` fan-out across three destinations:
       ``StdoutJSONLSink`` (for live eyeballing), ``FileJSONLSink``
       (for archive), and a custom in-memory sink (a stand-in for
       Kafka / SQS / Pub/Sub).

    2. Emit ~5 receipts across mixed step kinds — retrieval,
       tool_call, memory_write, model_inference — each finalised
       under one trajectory. Every receipt lands in all three
       destinations.

    3. Print the on-disk JSONL file contents to show the
       "FileJSONLSink → SIEM-readable archive" wire shape.

    4. Demonstrate the auto-coerce: ``sink=[a, b]`` is equivalent to
       ``sink=MultiSink([a, b])`` — one-parameter ergonomics.

    5. Demonstrate ``RetryQueueSink`` absorbing a flaky downstream:
       a fake sink that fails the first two calls then succeeds.
       The retry queue buffers the failures and drains on the next
       successful publish.

The pitch: one parameter (``sink=``) on every Provenex entrypoint
plugs the source-of-record into whatever firehose your SOC reads
from. Provenex never breaks the agent's hot path because export
is degraded.

Pure stdlib. No extras required for this demo (the Kafka / SQS / S3
/ Pub/Sub sinks behind extras share the exact same ``ReceiptSink``
interface — the in-memory sink in this demo is shape-identical).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import warnings
from pathlib import Path
from typing import Any, List

from provenex import (
    FileJSONLSink,
    HmacSha256Signer,
    MultiSink,
    ReceiptSink,
    RequestContext,
    RetryQueueSink,
    SQLiteProvenanceIndex,
    StdoutJSONLSink,
    ToolCallContext,
    admission_check,
    admit_memory_write,
    admit_model_inference,
    start_trajectory,
    verify_chunks,
)
from provenex.core.fingerprinter import Fingerprinter


_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
BLUE = "\033[34m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


CORPUS = (
    "TICKET-001: Service degradation reported. SEV-2 incident "
    "on auth-gateway. Owner: platform team."
)


class InMemorySink:
    """A stand-in for KafkaSink / SQSSink / PubSubSink.

    Captures every receipt JSON in a list so the demo can show what
    a downstream consumer would receive without standing up a broker.
    Shape-identical to the real network sinks: ``publish(receipt)``
    + ``close()``.
    """

    def __init__(self, label: str) -> None:
        self.label = label
        self.received: List[str] = []
        self._closed = False

    def publish(self, receipt: Any) -> None:
        if self._closed:
            from provenex import SinkClosedError

            raise SinkClosedError(f"{self.label} is closed")
        self.received.append(receipt.to_json(indent=None))

    def close(self) -> None:
        self._closed = True


def banner(s: str) -> None:
    print()
    print(f"{BOLD}{BLUE}=== {s} ==={RESET}")
    print()


def main() -> int:
    if not os.environ.get("PROVENEX_SIGNING_SECRET"):
        print(
            f"{RED}error:{RESET} PROVENEX_SIGNING_SECRET is not set.",
            file=sys.stderr,
        )
        print(
            '  export PROVENEX_SIGNING_SECRET='
            '"$(python3 -c \'import secrets; print(secrets.token_hex(32))\')"',
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # --- 1. Set up the sink fan-out --- #
        banner("1. Fan-out sink: stdout + local file + (simulated) firehose")

        log_dir = tmp_path / "log"
        firehose = InMemorySink(label="firehose-stand-in")
        stdout_buffer_path = tmp_path / "stdout_capture.jsonl"
        # We tee stdout output to a file so the demo's final summary
        # can show the JSONL bytes without scrolling.
        captured_stdout = open(stdout_buffer_path, "w", encoding="utf-8")

        sink = MultiSink(
            [
                StdoutJSONLSink(stream=captured_stdout),
                FileJSONLSink(directory=str(log_dir)),
                firehose,
            ]
        )
        print(
            f"  Three destinations:\n"
            f"    1. {DIM}StdoutJSONLSink → tee to {stdout_buffer_path}{RESET}\n"
            f"    2. {DIM}FileJSONLSink   → {log_dir}{RESET}\n"
            f"    3. {DIM}InMemorySink    → stand-in for Kafka / SQS / Pub/Sub{RESET}"
        )

        # --- 2. Emit receipts across mixed step kinds, one sink call each --- #
        banner("2. Emit receipts across mixed step kinds — one trajectory")

        idx = SQLiteProvenanceIndex(str(tmp_path / "p.db"))
        fp = Fingerprinter()
        fp_value = fp.fingerprint_chunk(CORPUS)
        idx.add(
            fingerprint=fp_value,
            document_id="doc-ticket-001",
            document_version="sha256:" + "1" * 64,
            chunk_offset=0,
            chunk_length=len(CORPUS),
            authorized=True,
        )
        signer = HmacSha256Signer()
        request = RequestContext(
            caller={"id": "u_42", "role": "engineer"},
            jurisdiction="US",
            purpose="incident_response",
            timestamp="2026-05-15T11:30:00Z",
            session_id="streaming-export-demo-001",
        )
        trj = start_trajectory(
            agent_id="incident_agent", session_id="streaming-export-demo-001"
        )

        # Retrieval
        r1 = verify_chunks(
            [CORPUS], idx, signer=signer, request_context=request,
            trajectory=trj, step_kind="retrieval", sink=sink,
        )
        print(f"  {GREEN}✓{RESET} retrieval        → {r1.receipt.receipt_id}")

        # Tool call
        r2 = admission_check(
            tool=ToolCallContext(
                name="web_search", operation="query",
                parameters={"q": "auth-gateway 5xx mitigation"},
                target_system="google_custom_search",
            ),
            request=request, signer=signer,
            trajectory=r1.next_trajectory, sink=sink,
        )
        print(f"  {GREEN}✓{RESET} tool_call        → {r2.receipt.receipt_id}")

        # Memory write
        r3 = admit_memory_write(
            memory_key="user_profile",
            value={"prefers": "concise_summaries"},
            request=request, signer=signer,
            trajectory=r2.next_trajectory, sink=sink,
        )
        print(f"  {GREEN}✓{RESET} memory_write     → {r3.receipt.receipt_id}")

        # Model inference
        r4 = admit_model_inference(
            model_name="claude-opus-4-7",
            prompt="Summarize TICKET-001 concisely.",
            request=request, target_provider="anthropic",
            extra_parameters={"max_tokens": 4000},
            signer=signer, trajectory=r3.next_trajectory, sink=sink,
        )
        print(f"  {GREEN}✓{RESET} model_inference  → {r4.receipt.receipt_id}")

        captured_stdout.flush()
        captured_stdout.close()
        idx.close()

        # --- 3. Show what landed in the on-disk archive --- #
        banner("3. FileJSONLSink contents (long-term archive shape)")

        files = sorted(log_dir.glob("receipts-*.jsonl"))
        assert len(files) == 1, "expected one daily-rotated file"
        for line in files[0].read_text(encoding="utf-8").splitlines():
            if not line:
                continue
            d = json.loads(line)
            print(
                f"  {DIM}{d['receipt_id'][:20]}…{RESET}  "
                f"step_kind={YELLOW}{d['trajectory']['step_kind']:<15}{RESET}  "
                f"caller={DIM}{d['caller_hash'][:18]}…{RESET}"
            )

        # --- 4. Show what the firehose (KafkaSink stand-in) received --- #
        banner("4. Firehose (KafkaSink stand-in) received the same stream")

        print(f"  {firehose.label} captured {GREEN}{len(firehose.received)}{RESET} receipts")
        for raw in firehose.received:
            d = json.loads(raw)
            print(
                f"    {DIM}{d['receipt_id'][:20]}…{RESET}  "
                f"step_kind={YELLOW}{d['trajectory']['step_kind']}{RESET}"
            )

        # --- 5. Auto-coerce: sink=[a, b] is auto-wrapped as MultiSink --- #
        banner("5. Auto-coerce — passing a list of sinks is auto-MultiSink'd")

        a, b = InMemorySink("sink-A"), InMemorySink("sink-B")
        # sink=[a, b] is auto-wrapped — same behavior as MultiSink([a, b]).
        admission_check(
            tool=ToolCallContext(name="t", operation="op", parameters={}),
            request=request, signer=signer,
            sink=[a, b],
        )
        print(
            f"  Both sinks received the receipt: "
            f"{GREEN}a={len(a.received)}{RESET} "
            f"{GREEN}b={len(b.received)}{RESET}"
        )

        # --- 6. RetryQueueSink absorbs a flaky downstream --- #
        banner("6. RetryQueueSink — absorbs transient downstream failures")

        class FlakySink:
            """Fails the first two publishes, then succeeds."""

            def __init__(self) -> None:
                self.delivered: List[str] = []
                self.fails_remaining = 2

            def publish(self, receipt: Any) -> None:
                if self.fails_remaining > 0:
                    self.fails_remaining -= 1
                    raise RuntimeError("downstream temporarily unavailable")
                self.delivered.append(receipt.receipt_id)

            def close(self) -> None:
                pass

        flaky = FlakySink()
        retry = RetryQueueSink(flaky, maxlen=100)

        print(
            f"  {DIM}Publishing 3 receipts through RetryQueueSink "
            f"with a downstream that fails twice…{RESET}"
        )
        rids: List[str] = []
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            for i in range(3):
                r = admission_check(
                    tool=ToolCallContext(name="t", operation="op", parameters={}),
                    request=request, signer=signer, sink=retry,
                )
                rids.append(r.receipt.receipt_id)
                print(
                    f"    publish {i+1}: pending in retry queue = "
                    f"{YELLOW}{retry.pending_count()}{RESET}, "
                    f"delivered downstream = {GREEN}{len(flaky.delivered)}{RESET}"
                )

        match = flaky.delivered == rids
        print(
            f"  Final state: all {len(flaky.delivered)} receipts delivered in FIFO order — "
            f"{GREEN if match else RED}{'match' if match else 'MISMATCH'}{RESET}"
        )

        # --- 7. Close everything --- #
        sink.close()
        retry.close()

        # --- 8. Pitch --- #
        banner("7. The 1-parameter firehose")
        print(
            f"  {DIM}Every emission entrypoint accepts ``sink=``. The agent's"
            f"{RESET}"
        )
        print(
            f"  {DIM}hot path is unchanged; the firehose runs alongside.{RESET}"
        )
        print(
            f"  {DIM}Sink failures are swallowed-and-logged — Provenex never"
            f"{RESET}"
        )
        print(
            f"  {DIM}breaks the agent because export is degraded.{RESET}"
        )

        return 0


if __name__ == "__main__":
    sys.exit(main())
