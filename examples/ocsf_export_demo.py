"""OCSF v1.3 export demo (0.6.7+).

Run with:

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/ocsf_export_demo.py

What it shows, in order:

    1. Emit a mixed-step-kind trajectory of receipts: retrieval
       allowed + tool_call allowed + memory_write allowed +
       model_inference allowed + tool_call DENIED. Five receipts,
       one trajectory.

    2. Convert each receipt to OCSF v1.3 events via the pure
       ``receipt_to_ocsf(receipt_dict)`` transformation. Print one
       sample event per class so the wire format is visible.

    3. Switch hats. Show the SIEM-side perspective — grouping
       events by ``metadata.correlation_uid`` (the trajectory),
       ``metadata.session_uid`` (the session), and
       ``actor.user.uid`` (the caller).

    4. Demonstrate ``OCSFAdapter`` streaming variant: wraps a
       downstream ``StdoutJSONLSink`` so the same admission_check
       call ships OCSF events directly via ``sink=``. One-line
       integration with any existing Provenex sink (Kafka, SQS, S3,
       Pub/Sub, your own).

    5. Demonstrate ``extra_metadata`` for deployment-level tags
       (``organization_uid``, ``environment``, ``tenant``) that
       SIEMs use for per-customer rule scoping.

The pitch: receipts are signed, verifiable, privacy-preserving. OCSF
events are the cross-vendor wire format every modern SIEM ingests.
Provenex emits the source-of-record AND the OCSF translation; the
SIEM is what reads both.

Pure stdlib. Total runtime ~2 s.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

from provenex import (
    HmacSha256Signer,
    OCSFAdapter,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    StdoutJSONLSink,
    ToolCallContext,
    admission_check,
    admit_memory_write,
    admit_model_inference,
    receipt_to_ocsf,
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


SESSION_ID = "incident-2026-05-15-customer-success-001"
CORPUS = (
    "INC-2026-05-001: Service degradation reported. SEV-2 incident "
    "on auth-gateway. Owner: platform team."
)

# Minimal policy that denies the second tool call (to viewers).
POLICY_YAML = """
version: 1
policy_id: ocsf-demo-v1

tool_call_control:
  rules:
    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue, update_issue, delete_issue] }
      require:
        request.caller.role: { in: [engineer, manager, admin] }
      on_violation: deny
  defaults:
    unknown_metadata: allow
"""


def banner(s: str) -> None:
    print()
    print(f"{BOLD}{BLUE}=== {s} ==={RESET}")
    print()


def hat_swap(s: str) -> None:
    print()
    print(f"{BOLD}{CYAN}>>> {s}{RESET}")
    print()


def _pretty(label: str, event: dict) -> None:
    print(f"{BOLD}{label}{RESET}")
    print(json.dumps(event, indent=2))


def main() -> int:
    if not os.environ.get("PROVENEX_SIGNING_SECRET"):
        print(
            f"{RED}error:{RESET} PROVENEX_SIGNING_SECRET is not set.",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        signer = HmacSha256Signer()
        policy = Policy.from_text(POLICY_YAML)

        # --- 1. Emit a mixed-step-kind trajectory --- #
        banner("1. Emit a mixed-step-kind trajectory of 5 signed receipts")

        idx = SQLiteProvenanceIndex(str(tmp_path / "p.db"))
        fp = Fingerprinter()
        chunk_fp = fp.fingerprint_chunk(CORPUS)
        idx.add(
            fingerprint=chunk_fp,
            document_id="incident-INC-2026-05-001",
            document_version="sha256:" + "1" * 64,
            chunk_offset=0,
            chunk_length=len(CORPUS),
            authorized=True,
        )

        engineer = RequestContext(
            caller={"id": "u_42", "role": "engineer"},
            jurisdiction="US",
            purpose="incident_response",
            timestamp="2026-05-15T11:30:00Z",
            session_id=SESSION_ID,
        )
        viewer = RequestContext(
            caller={"id": "u_99", "role": "viewer"},
            jurisdiction="US",
            purpose="incident_response",
            timestamp="2026-05-15T11:30:00Z",
            session_id=SESSION_ID,
        )

        trj = start_trajectory(agent_id="incident_agent", session_id=SESSION_ID)

        r1 = verify_chunks(
            [CORPUS], idx, signer=signer, request_context=engineer,
            trajectory=trj, step_kind="retrieval",
        )
        print(f"  {GREEN}✓{RESET} retrieval        → {r1.receipt.receipt_id}")

        r2 = admission_check(
            tool=ToolCallContext(
                name="web_search", operation="query",
                parameters={"q": "auth-gateway 5xx runbook"},
                target_system="google_custom_search",
            ),
            request=engineer, policy=policy, signer=signer,
            trajectory=r1.next_trajectory,
        )
        print(f"  {GREEN}✓{RESET} tool_call (allow)→ {r2.receipt.receipt_id}")

        r3 = admit_memory_write(
            memory_key="user_profile",
            value={"prefers": "concise_summaries"},
            request=engineer, signer=signer,
            trajectory=r2.next_trajectory,
        )
        print(f"  {GREEN}✓{RESET} memory_write     → {r3.receipt.receipt_id}")

        r4 = admit_model_inference(
            model_name="claude-opus-4-7",
            prompt="Summarize INC-2026-05-001.",
            request=engineer, target_provider="anthropic",
            extra_parameters={"max_tokens": 4000},
            signer=signer, trajectory=r3.next_trajectory,
        )
        print(f"  {GREEN}✓{RESET} model_inference  → {r4.receipt.receipt_id}")

        r5 = admission_check(
            tool=ToolCallContext(
                name="jira", operation="create_issue",
                parameters={"project": "INC"},
                target_system="acme.atlassian.net",
            ),
            request=viewer, policy=policy, signer=signer,
            trajectory=r4.next_trajectory,
        )
        deny_label = f"{RED}DENY{RESET}" if not r5.allowed else "ALLOW"
        print(f"  {RED}✗{RESET} tool_call ({deny_label})→ {r5.receipt.receipt_id}")
        idx.close()

        receipts = [r.receipt for r in (r1, r2, r3, r4, r5)]

        # --- 2. Convert each receipt to OCSF --- #
        banner("2. Convert receipts → OCSF v1.3 events")

        all_events = []
        for r in receipts:
            events = receipt_to_ocsf(
                r.to_dict(),
                extra_metadata={"organization_uid": "demo-corp", "environment": "demo"},
            )
            all_events.extend(events)
            print(
                f"  {DIM}{r.receipt_id[:24]}…{RESET}  →  "
                f"{GREEN}{len(events)}{RESET} event(s); "
                f"class_uids={[e['class_uid'] for e in events]}, "
                f"severity_ids={[e['severity_id'] for e in events]}"
            )
        print(f"\n  Total OCSF events emitted: {BOLD}{len(all_events)}{RESET}")

        # --- Show sample of each event class --- #
        banner("3. Sample OCSF events — one per class")

        seen = set()
        for event in all_events:
            uid = event["class_uid"]
            if uid in seen:
                continue
            seen.add(uid)
            _pretty(
                f"OCSF class_uid={uid} ({event['class_name']}) "
                f"severity={event['severity']}",
                event,
            )
            print()

        # --- 4. SIEM-side hat: group + correlate --- #
        hat_swap("Now reading the OCSF stream as a SIEM analyst would")

        banner("4a. GROUP BY metadata.correlation_uid (trajectory)")

        by_trj = Counter()
        for e in all_events:
            by_trj[e["metadata"].get("correlation_uid")] += 1
        for trj_id, n in by_trj.items():
            print(f"  {DIM}{trj_id}{RESET}  →  {GREEN}{n}{RESET} events")

        banner("4b. GROUP BY actor.user.uid (caller_hash)")

        by_caller = Counter()
        for e in all_events:
            by_caller[e["actor"]["user"]["uid"]] += 1
        for cid, n in by_caller.most_common():
            short = cid[:32] + ("…" if len(cid) > 32 else "")
            print(f"  {DIM}{short}{RESET}  →  {GREEN}{n}{RESET} events")

        banner("4c. GROUP BY metadata.labels (step_kind distribution)")

        sk = Counter()
        for e in all_events:
            for label in e["metadata"].get("labels", []):
                if label.startswith("step_kind:"):
                    sk[label[len("step_kind:"):]] += 1
        for kind, n in sk.most_common():
            print(f"  {YELLOW}{kind:<18}{RESET}  →  {GREEN}{n}{RESET}")

        banner("4d. Severity distribution (SOC routing)")

        sev = Counter()
        for e in all_events:
            sev[e["severity"]] += 1
        for s, n in sev.most_common():
            colour = RED if s in ("Critical", "High") else GREEN
            print(f"  {colour}{s:<14}{RESET}  →  {n}")

        # --- 5. Streaming via OCSFAdapter --- #
        banner("5. Streaming variant — OCSFAdapter wraps any ReceiptSink")

        import io
        buf = io.StringIO()
        ocsf_sink = OCSFAdapter(
            downstream=StdoutJSONLSink(stream=buf),
            extra_metadata={"organization_uid": "demo-corp", "environment": "demo"},
        )

        # The exact same admission_check call — only sink= changed.
        admission_check(
            tool=ToolCallContext(
                name="github", operation="create_pr",
                parameters={"title": "demo"},
                target_system="acme/repo",
            ),
            request=engineer, signer=signer, sink=ocsf_sink,
        )

        lines = [line for line in buf.getvalue().splitlines() if line]
        print(
            f"  {GREEN}{len(lines)}{RESET} OCSF event(s) shipped via OCSFAdapter."
        )
        if lines:
            e = json.loads(lines[0])
            print(
                f"  {DIM}class_uid={e['class_uid']}  "
                f"severity={e['severity']}  "
                f"service.name={e['api']['service']['name']}{RESET}"
            )

        # --- 6. Pitch --- #
        banner("6. Source-of-record AND SIEM-compatible")
        print(
            f"  {DIM}Receipts are signed, verifiable, privacy-preserving."
            f"{RESET}"
        )
        print(
            f"  {DIM}OCSF events are the cross-vendor wire format every modern"
            f"{RESET}"
        )
        print(
            f"  {DIM}SIEM ingests. Provenex emits both — the audit-grade source"
            f"{RESET}"
        )
        print(
            f"  {DIM}and the detector-side translation. We don't compete with"
            f"{RESET}"
        )
        print(
            f"  {DIM}the SIEM; we are the substrate that makes detection work."
            f"{RESET}"
        )

        return 0


if __name__ == "__main__":
    sys.exit(main())
