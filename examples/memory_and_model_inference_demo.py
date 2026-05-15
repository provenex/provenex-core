"""Memory + model-inference admission demo (0.6.5+).

Run with:

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/memory_and_model_inference_demo.py

What it shows, in order:

    1. An agent reads from a memory store via ``verify_memory(...)``.
       Same five outcomes as retrieval; source records carry
       content_source="memory_store"; trajectory step_kind is
       "memory_read".

    2. The agent writes to memory via ``admit_memory_write(...)``.
       Admission-shaped receipt: name="memory.write",
       operation=<memory_key>, value_hash always present, verbatim
       value redacted by default. Trajectory step_kind is
       "memory_write".

    3. The agent calls Claude Opus via ``admit_model_inference(...)``.
       Admission-shaped receipt: name=<model>, target_system=<provider>,
       prompt_hash always present, verbatim prompt redacted by default,
       extra_parameters captured. Trajectory step_kind is
       "model_inference".

    4. All three linked into one trajectory. ``provenex audit
       --trajectory`` validates the whole DAG end-to-end — mixed step
       kinds, one signed audit trail.

The pitch: every action class an agent takes — read corpus, read
memory, write memory, call a model, call a tool — produces one signed
receipt under one trajectory. The receipts are the source-of-record
a downstream anomaly detector / SIEM consumes; we don't compete with
the detector.

Pure stdlib (the [policy] extra is optional). Total runtime ~2 s.
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
    RequestContext,
    SQLiteProvenanceIndex,
    admit_memory_write,
    admit_model_inference,
    start_trajectory,
    verify_memory,
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


# Synthetic memory entry — what the agent stored earlier in the session
# and is now reading back as context.
MEMORY_ENTRY = (
    "User u_42 last reported the auth-gateway 5xx issue on 2026-05-13. "
    "Prefers concise summaries with the SEV level called out."
)

SESSION_ID = "session-2026-001"


def banner(s: str) -> None:
    print()
    print(f"{BOLD}{BLUE}=== {s} ==={RESET}")
    print()


def step(num: int, kind: str, title: str) -> None:
    colour = {
        "memory_read": GREEN,
        "memory_write": YELLOW,
        "model_inference": CYAN,
    }.get(kind, GREEN)
    print(f"{BOLD}{colour}STEP {num} — {kind.upper()}{RESET}  {DIM}{title}{RESET}")


def summary_line(label: str, value: str) -> None:
    print(f"  {DIM}{label:.<28}{RESET} {value}")


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
        receipts_dir = tmp_path / "receipts"
        receipts_dir.mkdir()

        # --- Setup --- #
        banner("1. Setup")

        # Pre-seed the memory store with one entry so step 1 produces a
        # VERIFIED outcome rather than UNVERIFIED.
        memory_index = SQLiteProvenanceIndex(str(tmp_path / "memory.db"))
        fp = Fingerprinter()
        mem_fp = fp.fingerprint_chunk(MEMORY_ENTRY)
        memory_index.add(
            fingerprint=mem_fp,
            document_id="memory-u_42-preferences",
            document_version="sha256:" + "1" * 64,
            chunk_offset=0,
            chunk_length=len(MEMORY_ENTRY),
            authorized=True,
        )
        print(
            f"  Memory store: {DIM}1 entry pre-ingested as authorized{RESET}"
        )

        signer = HmacSha256Signer()
        request = RequestContext(
            caller={"id": "u_42", "role": "engineer", "team": "platform"},
            jurisdiction="US",
            purpose="incident_response",
            timestamp="2026-05-14T11:30:00Z",
            session_id=SESSION_ID,
        )

        trj = start_trajectory(
            agent_id="incident_agent", session_id=SESSION_ID
        )

        # --- Step 0: memory_read --- #
        banner("2. Step 0 — agent reads memory")
        step(0, "memory_read", "verify_memory(...)")
        r0 = verify_memory(
            [MEMORY_ENTRY],
            index=memory_index,
            signer=signer,
            request_context=request,
            trajectory=trj,
        )
        d = r0.receipt.to_dict()
        summary_line("Receipt id", r0.receipt.receipt_id)
        summary_line("step_kind", d["trajectory"]["step_kind"])
        summary_line("content_source", d["sources"][0]["content_source"])
        summary_line(
            "Outcome", f"{GREEN}{d['sources'][0]['verification_outcome']}{RESET}"
        )
        (receipts_dir / "r0_memory_read.json").write_text(
            r0.receipt.to_json(), encoding="utf-8"
        )

        # --- Step 1: memory_write --- #
        banner(
            "3. Step 1 — agent persists an updated preference "
            "(value redacted on the receipt)"
        )
        step(1, "memory_write", "admit_memory_write(...)")
        r1 = admit_memory_write(
            memory_key="user_profile",
            value={
                "prefers": "concise_summaries",
                "preferred_severity_field": "SEV-2",
                "last_interaction": "2026-05-14T11:30:00Z",
            },
            request=request,
            store_id="crewai_memory",
            ttl=86400,
            signer=signer,
            trajectory=r0.next_trajectory,
        )
        d = r1.receipt.to_dict()
        action = d["actions"][0]
        summary_line("Receipt id", r1.receipt.receipt_id)
        summary_line("step_kind", d["trajectory"]["step_kind"])
        summary_line("action.name", action["name"])
        summary_line("action.operation", action["operation"])
        summary_line("action.target_system", action.get("target_system", "—"))
        summary_line(
            "value redacted?",
            f"{GREEN}yes{RESET}" if "value" not in action["parameters"]
            else f"{RED}no{RESET}",
        )
        summary_line(
            "value_hash", action["parameters"]["value_hash"][:32] + "…"
        )
        summary_line(
            "Decision",
            f"{GREEN if r1.allowed else RED}{r1.decision.upper()}{RESET}",
        )
        (receipts_dir / "r1_memory_write.json").write_text(
            r1.receipt.to_json(), encoding="utf-8"
        )

        # --- Step 2: model_inference --- #
        banner(
            "4. Step 2 — agent invokes Claude Opus "
            "(prompt redacted on the receipt)"
        )
        step(2, "model_inference", "admit_model_inference(...)")
        prompt_messages = [
            {
                "role": "user",
                "content": (
                    "Summarize TICKET-001 in two sentences. "
                    "Use a concise tone. Call out the SEV."
                ),
            }
        ]
        r2 = admit_model_inference(
            model_name="claude-opus-4-7",
            prompt=prompt_messages,
            request=request,
            target_provider="anthropic",
            operation="complete",
            extra_parameters={"max_tokens": 4000, "temperature": 0.2},
            signer=signer,
            trajectory=r1.next_trajectory,
        )
        d = r2.receipt.to_dict()
        action = d["actions"][0]
        summary_line("Receipt id", r2.receipt.receipt_id)
        summary_line("step_kind", d["trajectory"]["step_kind"])
        summary_line("action.name", action["name"])
        summary_line("action.operation", action["operation"])
        summary_line("action.target_system", action["target_system"])
        summary_line(
            "prompt redacted?",
            f"{GREEN}yes{RESET}" if "prompt" not in action["parameters"]
            else f"{RED}no{RESET}",
        )
        summary_line(
            "prompt_hash", action["parameters"]["prompt_hash"][:32] + "…"
        )
        summary_line("max_tokens", str(action["parameters"]["max_tokens"]))
        summary_line(
            "Decision",
            f"{GREEN if r2.allowed else RED}{r2.decision.upper()}{RESET}",
        )
        (receipts_dir / "r2_model_inference.json").write_text(
            r2.receipt.to_json(), encoding="utf-8"
        )

        memory_index.close()

        # --- Audit the trajectory --- #
        banner("5. provenex audit --trajectory <dir>")
        print(
            f"  {DIM}One CLI invocation; "
            f"mixed step_kinds (memory_read / memory_write / model_inference); "
            f"full DAG validation.{RESET}"
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
                f"{DIM}3 receipts. 3 step kinds. One signed audit trail.{RESET}"
            )
        else:
            print(f"  {RED}{BOLD}AUDIT FAILED — investigate above{RESET}")

        # --- Show that the verbatim values are recoverable from the hashes
        #     (when the detector has them out-of-band) --- #
        banner("6. The hashes are the audit anchor — recoverable out-of-band")
        from provenex import compute_value_hash

        mem_value = {
            "prefers": "concise_summaries",
            "preferred_severity_field": "SEV-2",
            "last_interaction": "2026-05-14T11:30:00Z",
        }
        rederived_value_hash = compute_value_hash(mem_value)
        on_receipt_value_hash = json.loads(
            (receipts_dir / "r1_memory_write.json").read_text(
                encoding="utf-8"
            )
        )["actions"][0]["parameters"]["value_hash"]
        match = rederived_value_hash == on_receipt_value_hash
        print(
            f"  Detector recomputes value_hash from out-of-band memory log: "
            f"{GREEN if match else RED}{'match' if match else 'MISMATCH'}{RESET}"
        )

        rederived_prompt_hash = compute_value_hash(prompt_messages)
        on_receipt_prompt_hash = json.loads(
            (receipts_dir / "r2_model_inference.json").read_text(
                encoding="utf-8"
            )
        )["actions"][0]["parameters"]["prompt_hash"]
        match = rederived_prompt_hash == on_receipt_prompt_hash
        print(
            f"  Detector recomputes prompt_hash from out-of-band model log: "
            f"{GREEN if match else RED}{'match' if match else 'MISMATCH'}{RESET}"
        )
        print(
            f"  {DIM}Provenex stays decision-and-proof, never on the data path."
            f"{RESET}"
        )

        return 0


if __name__ == "__main__":
    sys.exit(main())
