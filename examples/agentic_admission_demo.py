"""Phase 2 headline demo: mixed retrieval + tool-call trajectory.

Run with:

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/agentic_admission_demo.py

What it shows, in order:

    1. Load one unified policy file covering chunk access AND tool-call
       admission. One file, two halves, independently versioned hashes.

    2. Step 0 — RETRIEVAL. The agent pulls chunks for an incident-response
       query. verify_chunks emits a signed receipt with the
       access_control decisions block; chunks are filtered by the
       classification gate.

    3. Step 1 — TOOL CALL. The agent decides to call `web_search` to
       supplement the corpus content. admission_check enforces the
       allowlisted-provider rule and the PII-pattern rule. ALLOWED.
       Signed receipt records the action + decision.

    4. Step 2 — TOOL CALL (denied). The agent tries to call `jira` with
       a parameter that triggers the role gate. DENIED. The receipt
       still records the attempt — denials are auditable.

    5. Step 3 — RETRIEVAL. Another chunk pull, this time linked into
       the trajectory as a child of step 2.

    6. Audit the whole trajectory in one CLI invocation:
       `provenex audit --trajectory <dir>` — all four receipts validate
       end-to-end. Mixed step_kinds (retrieval / tool_call) are
       first-class.

The pitch: ONE signed audit trail across mixed retrieval and tool-call
enforcement. That is the demo that sells Phase 2.

Total runtime ~3 s. The dependencies are the [policy] extra (PyYAML)
plus the stdlib.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    ToolCallContext,
    admission_check,
    start_trajectory,
    verify_chunks,
)
from provenex.core.fingerprinter import Fingerprinter


# ANSI colour codes. Auto-disable when stdout is not a terminal.
_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
BLUE = "\033[34m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


UNIFIED_POLICY = """
version: 1
policy_id: incident-response-agent-v1
description: Mixed-flow policy for retrieval + agentic tool calls.

verification:
  block_unauthorized: true
  block_tampered: true

access_control:
  rules:
    - name: classification_gate
      when:
        chunk.metadata.classification: confidential
      require:
        request.caller.role:
          in: [engineer, manager, admin]
      on_violation: deny
  defaults:
    unknown_metadata: allow

tool_call_control:
  rules:
    # Demo 1 — domain allowlist on the search tool.
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny

    # Demo 5 — PII / secrets pattern on the query string.
    - name: no_secrets_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*(api[_-]?key|password|secret)*"
      on_violation: deny

    # Length cap. Cheapest defense against prompt-injection-via-long-query.
    - name: query_length_cap
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          length_at_most: 500
      on_violation: deny

    # Demo 2 — CRUD-style role gate using `in:` in when.
    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue, update_issue, delete_issue] }
      require:
        request.caller.role:
          in: [engineer, manager, admin]
      on_violation: deny

  defaults:
    unknown_metadata: deny
"""


# A made-up corpus snippet the demo ingests. Realistic-looking but
# entirely synthetic.
CORPUS_CHUNK = (
    "INC-2026-05-001: Service degradation reported by customer-success at "
    "11:02 UTC. Initial triage points to elevated 5xx rates on the "
    "auth-gateway. Owner: platform team. Severity: SEV-2."
)


def banner(s: str) -> None:
    print()
    print(f"{BOLD}{BLUE}=== {s} ==={RESET}")
    print()


def step_header(num: int, kind: str, title: str) -> None:
    colour = GREEN if kind == "retrieval" else YELLOW
    print(f"{BOLD}{colour}STEP {num} — {kind.upper()}{RESET}  {DIM}{title}{RESET}")


def summary_line(label: str, value: str) -> None:
    print(f"  {DIM}{label:.<28}{RESET} {value}")


def main() -> int:
    if not os.environ.get("PROVENEX_SIGNING_SECRET"):
        print(
            f"{RED}error:{RESET} PROVENEX_SIGNING_SECRET is not set. "
            f"Set it before running this demo:",
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
        receipts_dir = tmp_path / "receipts"
        receipts_dir.mkdir()

        # --- Setup ---
        banner("1. Setup")

        # Write the policy to disk so the CLI hash command can read it.
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(UNIFIED_POLICY, encoding="utf-8")
        print(
            f"  Policy: {DIM}{policy_path}{RESET}  "
            f"({DIM}provenex policy validate {policy_path}{RESET})"
        )
        # Show the dual-section hash output — one of the demo moments.
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "provenex.cli.main",
                "policy",
                "hash",
                str(policy_path),
            ],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.strip().splitlines():
            print(f"  {DIM}{line}{RESET}")

        # Ingest one chunk into a Provenex index so the retrieval steps
        # can produce VERIFIED outcomes.
        index_path = tmp_path / "provenance.db"
        index = SQLiteProvenanceIndex(str(index_path))
        fp = Fingerprinter()
        chunk_fp = fp.fingerprint_chunk(CORPUS_CHUNK)
        index.add(
            fingerprint=chunk_fp,
            document_id="incident-INC-2026-05-001",
            document_version="sha256:" + "1" * 64,
            chunk_offset=0,
            chunk_length=len(CORPUS_CHUNK),
            authorized=True,
        )
        print(f"  Index:  {DIM}1 chunk ingested as authorized{RESET}")

        # Build common pieces.
        policy = Policy.from_text(UNIFIED_POLICY)
        signer = HmacSha256Signer()
        request = RequestContext(
            caller={"id": "u_42", "role": "engineer", "team": "platform"},
            jurisdiction="US",
            purpose="incident_response",
            timestamp="2026-05-14T11:30:00Z",
        )

        # --- Step 0: retrieval ---
        banner("2. Step 0 — retrieve corpus content")
        trj = start_trajectory(agent_id="incident_agent")
        step_header(0, "retrieval", "agent pulls one corpus chunk")

        r0 = verify_chunks(
            chunks=[CORPUS_CHUNK],
            index=index,
            signer=signer,
            policy=policy,
            request_context=request,
            chunk_metadata=[{"classification": "internal"}],
            trajectory=trj,
        )
        summary_line("Receipt id", r0.receipt.receipt_id)
        summary_line(
            "Overall status",
            f"{GREEN}{r0.receipt.summary['overall_status']}{RESET}",
        )
        summary_line(
            "Chunks kept / blocked", f"{len(r0.kept)} / {len(r0.blocked)}"
        )
        (receipts_dir / "step0_retrieval.json").write_text(
            r0.receipt.to_json(), encoding="utf-8"
        )

        # --- Step 1: tool call (allowed) ---
        banner("3. Step 1 — agent calls `web_search` (ALLOWED)")
        step_header(1, "tool_call", "search supplemental info")

        r1 = admission_check(
            tool=ToolCallContext(
                name="web_search",
                operation="query",
                parameters={"q": "auth-gateway 5xx mitigation runbook"},
                target_system="google_custom_search",
            ),
            request=request,
            policy=policy,
            signer=signer,
            trajectory=r0.next_trajectory,
        )
        summary_line("Receipt id", r1.receipt.receipt_id)
        summary_line(
            "Decision",
            f"{GREEN if r1.allowed else RED}{r1.decision.upper()}{RESET}",
        )
        summary_line("Rules fired", ", ".join(r1.rules_fired))
        summary_line(
            "Overall status",
            f"{GREEN}{r1.receipt.summary['overall_status']}{RESET}",
        )
        (receipts_dir / "step1_websearch_allow.json").write_text(
            r1.receipt.to_json(), encoding="utf-8"
        )

        # --- Step 2: tool call (denied) ---
        banner("4. Step 2 — agent calls `jira.create_issue` as wrong role")
        step_header(2, "tool_call", "deliberately denied — role gate fires")

        viewer_request = RequestContext(
            caller={"id": "u_99", "role": "viewer"},  # not allowed for writes
            jurisdiction="US",
            purpose="incident_response",
            timestamp="2026-05-14T11:30:00Z",
        )
        r2 = admission_check(
            tool=ToolCallContext(
                name="jira",
                operation="create_issue",
                parameters={
                    "project": "INC",
                    "summary": "Auth-gateway 5xx investigation",
                },
                target_system="acme.atlassian.net",
            ),
            request=viewer_request,
            policy=policy,
            signer=signer,
            trajectory=r1.next_trajectory,
        )
        summary_line("Receipt id", r2.receipt.receipt_id)
        summary_line(
            "Decision",
            f"{RED if not r2.allowed else GREEN}{r2.decision.upper()}{RESET}",
        )
        summary_line("Rules fired", ", ".join(r2.rules_fired))
        summary_line(
            "Overall status",
            f"{RED}{r2.receipt.summary['overall_status']}{RESET}",
        )
        print(
            f"  {DIM}# Caller does NOT make the actual Jira call. Decision and{RESET}"
        )
        print(
            f"  {DIM}# proof, not execution — the receipt is the audit record.{RESET}"
        )
        (receipts_dir / "step2_jira_deny.json").write_text(
            r2.receipt.to_json(), encoding="utf-8"
        )

        # --- Step 3: another retrieval ---
        banner("5. Step 3 — retrieve a second corpus chunk")
        step_header(3, "retrieval", "agent gathers more context")

        r3 = verify_chunks(
            chunks=[CORPUS_CHUNK],
            index=index,
            signer=signer,
            policy=policy,
            request_context=request,
            chunk_metadata=[{"classification": "internal"}],
            trajectory=r2.next_trajectory,
        )
        summary_line("Receipt id", r3.receipt.receipt_id)
        summary_line(
            "Overall status",
            f"{GREEN}{r3.receipt.summary['overall_status']}{RESET}",
        )
        (receipts_dir / "step3_retrieval.json").write_text(
            r3.receipt.to_json(), encoding="utf-8"
        )

        index.close()

        # --- Audit ---
        banner("6. provenex audit --trajectory <dir>")
        print(
            f"  {DIM}One CLI invocation; mixed step_kinds; full DAG validation.{RESET}"
        )
        print()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "provenex.cli.main",
                "audit",
                "--trajectory",
                str(receipts_dir),
            ],
        )
        print()
        if result.returncode == 0:
            print(
                f"  {GREEN}{BOLD}END-TO-END AUDIT PASS{RESET}  "
                f"{DIM}4 receipts. Mixed retrieval + tool calls. "
                f"One signed audit trail.{RESET}"
            )
        else:
            print(f"  {RED}{BOLD}AUDIT FAILED — investigate above{RESET}")

        # --- Per-receipt detail (one example, --show-policy) ---
        banner("7. Inspect the denied tool-call receipt")
        print(
            f"  {DIM}provenex audit step2_jira_deny.json --show-policy{RESET}"
        )
        print()
        subprocess.run(
            [
                sys.executable,
                "-m",
                "provenex.cli.main",
                "audit",
                "--show-policy",
                str(receipts_dir / "step2_jira_deny.json"),
            ],
        )
        print()

        return 0


if __name__ == "__main__":
    sys.exit(main())
