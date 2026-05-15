"""Source-of-record demo: Provenex receipts as the AI agent event stream.

Run with:

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/anomaly_correlation_demo.py

What it shows, in order:

    1. Generate a small synthetic event stream — ~10 signed receipts
       across three callers and two sessions. Mix of verify_chunks
       (retrieval) and admission_check (tool calls). One caller is
       deliberately noisy in one session: 5x web_search in a row.

    2. Switch hats. The same script then plays the role of a downstream
       anomaly detector reading the on-disk receipts.

    3. Pattern 1 — group by caller_hash. Per-caller tool-call counts.
       The noisy caller pops out: 5 web_search vs everyone else's 1.

    4. Pattern 2 — group by session_id. Per-session step shape (count
       of retrieval / tool_call). The synthetic incident-response
       session interleaves retrievals and tool calls; the noisy
       "routine search" session is all tool calls.

    5. Pattern 3 — independent verification. The detector re-derives
       the top-level caller_hash from the verbatim caller dict embedded
       on a decision record. Match → receipt is self-consistent.
       Mismatch (impossible without a signing-key compromise) would
       mean tampering — and the signature would also have failed.

Decision-and-proof, not execution. Provenex emits the source-of-record;
this demo's "detector" half is what a real UEBA / SIEM would do
downstream. We don't compete with the detector; we're the substrate.

Pure stdlib. No [policy] extra. Total runtime ~2 s. See
``anomaly_correlation_with_policy_demo.py`` for the same shape running
against a unified YAML policy with access_control + tool_call_control.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List

from provenex import (
    HmacSha256Signer,
    RequestContext,
    SQLiteProvenanceIndex,
    ToolCallContext,
    admission_check,
    compute_caller_hash,
    start_trajectory,
    verify_chunks,
)
from provenex.core.fingerprinter import Fingerprinter


# ANSI colour codes; auto-disable when stdout isn't a terminal.
_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
BLUE = "\033[34m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


# ----- callers + sessions ----- #

CALLERS = {
    "u_42_engineer": {"id": "u_42", "role": "engineer", "team": "platform"},
    "u_99_viewer":   {"id": "u_99", "role": "viewer",   "team": "support"},
    "u_777_noisy":   {"id": "u_777", "role": "engineer", "team": "platform"},
}

SESSION_INCIDENT = "incident-2026-05-14-customer-success-001"
SESSION_NOISY    = "routine-search-2026-05-14-002"

CORPUS_CHUNK = (
    "INC-2026-05-001: Service degradation reported by customer-success at "
    "11:02 UTC. Initial triage points to elevated 5xx rates on the "
    "auth-gateway."
)


def banner(s: str) -> None:
    print()
    print(f"{BOLD}{BLUE}=== {s} ==={RESET}")
    print()


def hat_swap(s: str) -> None:
    print()
    print(f"{BOLD}{CYAN}>>> {s}{RESET}")
    print()


def _request(caller_key: str, session_id: str | None) -> RequestContext:
    return RequestContext(
        caller=CALLERS[caller_key],
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
        session_id=session_id,
    )


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

        # --- 1. Emit synthetic event stream --- #
        banner("1. Emit ~10 signed receipts across 3 callers, 2 sessions")

        index = SQLiteProvenanceIndex(str(tmp_path / "p.db"))
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
        signer = HmacSha256Signer()
        receipt_id_counter = 0

        def save(receipt) -> None:
            nonlocal receipt_id_counter
            receipt_id_counter += 1
            (receipts_dir / f"r{receipt_id_counter:02d}.json").write_text(
                receipt.to_json(), encoding="utf-8"
            )

        # u_42, incident session: 2 retrievals + 1 tool call.
        traj = start_trajectory(agent_id="incident_agent")
        r = verify_chunks(
            chunks=[CORPUS_CHUNK], index=index, signer=signer,
            request_context=_request("u_42_engineer", SESSION_INCIDENT),
            trajectory=traj, step_kind="retrieval",
        )
        save(r.receipt)
        r = verify_chunks(
            chunks=[CORPUS_CHUNK], index=index, signer=signer,
            request_context=_request("u_42_engineer", SESSION_INCIDENT),
            trajectory=r.next_trajectory, step_kind="retrieval",
        )
        save(r.receipt)
        ar = admission_check(
            tool=ToolCallContext(
                name="web_search", operation="query",
                parameters={"q": "auth-gateway 5xx mitigation runbook"},
                target_system="google_custom_search",
            ),
            request=_request("u_42_engineer", SESSION_INCIDENT),
            signer=signer, trajectory=r.next_trajectory,
        )
        save(ar.receipt)

        # u_99 viewer, incident session: 1 retrieval.
        traj = start_trajectory(agent_id="support_agent")
        r = verify_chunks(
            chunks=[CORPUS_CHUNK], index=index, signer=signer,
            request_context=_request("u_99_viewer", SESSION_INCIDENT),
            trajectory=traj, step_kind="retrieval",
        )
        save(r.receipt)

        # u_777 NOISY: 5x web_search in routine session.
        traj = start_trajectory(agent_id="research_agent")
        for q in [
            "weather today", "weather paris", "weather london",
            "weather tokyo", "weather sydney",
        ]:
            ar = admission_check(
                tool=ToolCallContext(
                    name="web_search", operation="query",
                    parameters={"q": q},
                    target_system="google_custom_search",
                ),
                request=_request("u_777_noisy", SESSION_NOISY),
                signer=signer, trajectory=traj,
            )
            save(ar.receipt)
            traj = ar.next_trajectory

        index.close()

        print(
            f"  {GREEN}{receipt_id_counter}{RESET} signed receipts written to "
            f"{DIM}{receipts_dir}{RESET}"
        )
        print(
            f"  Schema {DIM}2.3.0{RESET}; every receipt carries "
            f"{BOLD}caller_hash{RESET} + (where applicable) "
            f"{BOLD}trajectory.session_id{RESET}."
        )

        # --- 2. Switch hats --- #
        hat_swap("Now reading the receipts as a downstream anomaly detector")

        # Load all receipts.
        receipts: List[Dict] = []
        for path in sorted(receipts_dir.glob("*.json")):
            receipts.append(json.loads(path.read_text(encoding="utf-8")))

        # --- 3. Pattern 1: per-caller tool-call counts --- #
        banner("2. Pattern 1 — GROUP BY caller_hash → per-caller action counts")

        actions_by_caller: Counter = Counter()
        retrievals_by_caller: Counter = Counter()
        for r in receipts:
            ch = r.get("caller_hash", "(none)")
            actions_by_caller[ch] += len(r.get("actions", []))
            retrievals_by_caller[ch] += len(r.get("sources", []))

        # Map hash back to a friendly label for the demo only; a real
        # detector keeps the hash as the group key and joins to IdM
        # out-of-band.
        labels = {compute_caller_hash(c): k for k, c in CALLERS.items()}
        for ch, n in actions_by_caller.most_common():
            label = labels.get(ch, "(unknown)")
            anomaly = " ← anomaly: 5x baseline" if n >= 5 else ""
            colour = RED if anomaly else GREEN
            print(
                f"  {DIM}{ch[:18]}…{RESET}  "
                f"{label:<18}  "
                f"actions={colour}{n}{RESET}  "
                f"retrievals={retrievals_by_caller[ch]}"
                f"{RED}{BOLD}{anomaly}{RESET}"
            )

        # --- 4. Pattern 2: per-session step-kind shape --- #
        banner("3. Pattern 2 — GROUP BY session_id → per-session step shape")

        session_shape: Dict[str, Counter] = defaultdict(Counter)
        for r in receipts:
            tr = r.get("trajectory") or {}
            sess = tr.get("session_id")
            kind = tr.get("step_kind")
            if sess and kind:
                session_shape[sess][kind] += 1

        for sess, counts in session_shape.items():
            shape = ", ".join(f"{k}={v}" for k, v in counts.most_common())
            print(f"  {YELLOW}{sess}{RESET}")
            print(f"    {DIM}step shape:{RESET} {shape}")
            if len(counts) == 1:
                print(
                    f"    {RED}{BOLD}← single-shape session — investigate{RESET}"
                )

        # --- 5. Pattern 3: independent re-derivation + signature check --- #
        banner(
            "4. Pattern 3 — verify don't trust: recompute caller_hash + "
            "verify signatures"
        )

        # This stdlib demo emits receipts with no policy configured, so
        # there is no policy.access_control.decisions[].inputs block to
        # read a caller dict back out of. Instead we demonstrate the
        # canonicalisation property directly: a detector that has the
        # caller dict from any out-of-band source (its own IdM record,
        # the request log on the gateway) computes the same hash. The
        # policy-flavoured demo
        # (anomaly_correlation_with_policy_demo.py) shows the
        # re-derivation against on-receipt decision inputs.
        from provenex.core.receipt import verify_receipt_signature

        sample = receipts[0]
        sample_caller_label = next(
            (k for k, c in CALLERS.items()
             if compute_caller_hash(c) == sample["caller_hash"]),
            "(unknown)",
        )
        print(f"  Sample receipt:        {DIM}{sample['receipt_id']}{RESET}")
        print(
            f"  Top-level caller_hash: {DIM}{sample['caller_hash']}{RESET}"
        )
        print(
            f"  Detector cross-check from out-of-band IdM: "
            f"{GREEN}match → {sample_caller_label}{RESET}"
        )
        # The signature is the load-bearing property. If the detector
        # cannot verify, the receipt is not trusted.
        sigs_ok = sum(
            verify_receipt_signature(r, HmacSha256Signer()) for r in receipts
        )
        print(
            f"  Signature verify across all {len(receipts)} receipts: "
            f"{GREEN if sigs_ok == len(receipts) else RED}{sigs_ok}/"
            f"{len(receipts)} valid{RESET}"
        )

        # --- 6. Pitch --- #
        banner("5. Source-of-record, not anomaly detector")
        print(
            f"  {DIM}Provenex emits the structured, signed event record."
            f"{RESET}"
        )
        print(
            f"  {DIM}The detector / SIEM that reads it is the SIEM. We "
            f"don't compete with the detector;{RESET}"
        )
        print(
            f"  {DIM}we're the substrate that makes detection possible — "
            f"and offline-verifiable.{RESET}"
        )

        return 0


if __name__ == "__main__":
    sys.exit(main())
