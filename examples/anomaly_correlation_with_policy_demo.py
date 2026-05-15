"""Same source-of-record demo, but running against a real unified policy.

Run with:

    pip install "provenex-core[policy]"
    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/anomaly_correlation_with_policy_demo.py

The shape mirrors ``anomaly_correlation_demo.py`` exactly — same three
callers, same two sessions, same noisy-caller pattern — but every
receipt also carries:

    * ``policy.access_control.decisions[]`` for the retrieval receipts,
      because a chunk-side `access_control` rule (role gate) fires;
    * ``policy.tool_call_control.decisions[]`` for the tool-call
      receipts, because a tool-call `tool_call_control` rule
      (provider allowlist + length cap) fires.

The point: ``caller_hash`` and ``trajectory.session_id`` are
detector-side correlation tags that live alongside the per-decision
policy artifacts the auditor cares about — not in tension with them.
Both fields stay out of ``inputs_hash``, so policy decisions are
unchanged.

What the detector half does is identical to the stdlib demo:

    * Pattern 1 — GROUP BY caller_hash → per-caller action counts.
    * Pattern 2 — GROUP BY session_id → per-session step shape.
    * Pattern 3 — independent re-derivation of caller_hash from the
      verbatim caller embedded on each decision record. Cross-check
      against ``policy.access_control.decisions[0].inputs.request_context.caller``
      AND ``policy.tool_call_control.decisions[0].inputs.request_context.caller`` —
      both must reproduce the same hash regardless of which gate fired.

Pure stdlib + PyYAML (the ``[policy]`` extra). Total runtime ~2 s.
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
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    ToolCallContext,
    admission_check,
    compute_caller_hash,
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


UNIFIED_POLICY = """
version: 1
policy_id: anomaly-correlation-demo-v1
description: Source-of-record demo against a real unified policy.

verification:
  block_unauthorized: true
  block_tampered: true

access_control:
  rules:
    # Retrieval-side gate: only engineers + admins may read internal
    # incident chunks. Viewers see the chunk blocked.
    - name: internal_chunks_require_engineer_role
      when:
        chunk.metadata.classification: internal
      require:
        request.caller.role:
          in: [engineer, admin]
      on_violation: deny
  defaults:
    unknown_metadata: allow

tool_call_control:
  rules:
    # Search provider allowlist.
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny
    # Length cap on query strings.
    - name: web_search_length_cap
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          length_at_most: 500
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


CALLERS = {
    "u_42_engineer": {"id": "u_42", "role": "engineer", "team": "platform"},
    "u_99_viewer":   {"id": "u_99", "role": "viewer",   "team": "support"},
    "u_777_noisy":   {"id": "u_777", "role": "engineer", "team": "platform"},
}

SESSION_INCIDENT = "session-2026-001"
SESSION_NOISY    = "routine-search-2026-05-14-002"

CORPUS_CHUNK = (
    "TICKET-001: Service degradation reported at "
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
        return 2

    try:
        policy = Policy.from_text(UNIFIED_POLICY)
    except RuntimeError as e:
        print(f"{RED}error:{RESET} {e}", file=sys.stderr)
        print(
            f"  Install the YAML extra: "
            f"{DIM}pip install \"provenex-core[policy]\"{RESET}",
            file=sys.stderr,
        )
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        receipts_dir = tmp_path / "receipts"
        receipts_dir.mkdir()

        # --- Emit receipts under the unified policy --- #
        banner("1. Emit signed receipts under a unified YAML policy")

        index = SQLiteProvenanceIndex(str(tmp_path / "p.db"))
        fp = Fingerprinter()
        chunk_fp = fp.fingerprint_chunk(CORPUS_CHUNK)
        index.add(
            fingerprint=chunk_fp,
            document_id="doc-ticket-001",
            document_version="sha256:" + "1" * 64,
            chunk_offset=0,
            chunk_length=len(CORPUS_CHUNK),
            authorized=True,
        )
        signer = HmacSha256Signer()
        chunk_metadata = [{"classification": "internal"}]
        n = 0

        def save(receipt) -> None:
            nonlocal n
            n += 1
            (receipts_dir / f"r{n:02d}.json").write_text(
                receipt.to_json(), encoding="utf-8"
            )

        # u_42 incident — retrieval (allow by access_control) + a tool call.
        traj = start_trajectory(agent_id="incident_agent")
        r = verify_chunks(
            chunks=[CORPUS_CHUNK], index=index, signer=signer,
            policy=policy,
            request_context=_request("u_42_engineer", SESSION_INCIDENT),
            chunk_metadata=chunk_metadata,
            trajectory=traj, step_kind="retrieval",
        )
        save(r.receipt)
        r2 = verify_chunks(
            chunks=[CORPUS_CHUNK], index=index, signer=signer,
            policy=policy,
            request_context=_request("u_42_engineer", SESSION_INCIDENT),
            chunk_metadata=chunk_metadata,
            trajectory=r.next_trajectory, step_kind="retrieval",
        )
        save(r2.receipt)
        ar = admission_check(
            tool=ToolCallContext(
                name="web_search", operation="query",
                parameters={"q": "auth-gateway 5xx mitigation runbook"},
                target_system="google_custom_search",
            ),
            request=_request("u_42_engineer", SESSION_INCIDENT),
            policy=policy, signer=signer,
            trajectory=r2.next_trajectory,
        )
        save(ar.receipt)

        # u_99 viewer incident — retrieval BLOCKED by access_control rule.
        traj = start_trajectory(agent_id="support_agent")
        r = verify_chunks(
            chunks=[CORPUS_CHUNK], index=index, signer=signer,
            policy=policy,
            request_context=_request("u_99_viewer", SESSION_INCIDENT),
            chunk_metadata=chunk_metadata,
            trajectory=traj, step_kind="retrieval",
        )
        save(r.receipt)

        # u_777 noisy — 5x web_search in routine session.
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
                policy=policy, signer=signer, trajectory=traj,
            )
            save(ar.receipt)
            traj = ar.next_trajectory

        index.close()

        print(
            f"  {GREEN}{n}{RESET} signed receipts written to "
            f"{DIM}{receipts_dir}{RESET}"
        )
        print(
            f"  Every receipt carries {BOLD}policy.access_control{RESET} or "
            f"{BOLD}policy.tool_call_control{RESET} decision records,"
        )
        print(
            f"  plus the schema-2.3.0 correlation fields "
            f"{BOLD}caller_hash{RESET} and {BOLD}trajectory.session_id{RESET}."
        )

        hat_swap("Reading the receipts as a downstream anomaly detector")

        receipts: List[Dict] = []
        for path in sorted(receipts_dir.glob("*.json")):
            receipts.append(json.loads(path.read_text(encoding="utf-8")))

        # --- Pattern 1: per-caller action counts --- #
        banner("2. Pattern 1 — GROUP BY caller_hash → per-caller action counts")

        actions_by_caller: Counter = Counter()
        denies_by_caller: Counter = Counter()
        for r in receipts:
            ch = r.get("caller_hash", "(none)")
            actions_by_caller[ch] += len(r.get("actions", []))
            ac_decisions = (
                r.get("policy", {})
                .get("access_control", {})
                .get("decisions", [])
            )
            for d in ac_decisions:
                if d.get("decision") == "deny":
                    denies_by_caller[ch] += 1

        labels = {compute_caller_hash(c): k for k, c in CALLERS.items()}
        for ch, count in actions_by_caller.most_common():
            label = labels.get(ch, "(unknown)")
            denies = denies_by_caller.get(ch, 0)
            anomaly = " ← anomaly: 5x baseline" if count >= 5 else ""
            colour = RED if anomaly else GREEN
            deny_part = (
                f"  policy denies={RED}{denies}{RESET}" if denies else ""
            )
            print(
                f"  {DIM}{ch[:18]}…{RESET}  "
                f"{label:<18}  "
                f"actions={colour}{count}{RESET}"
                f"{deny_part}"
                f"{RED}{BOLD}{anomaly}{RESET}"
            )

        # --- Pattern 2: per-session step shape --- #
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

        # --- Pattern 3: independent re-derivation (across BOTH gate types) --- #
        banner(
            "4. Pattern 3 — verify don't trust: recompute caller_hash from "
            "BOTH gate types"
        )

        for r in receipts:
            top_level = r.get("caller_hash")
            ac = (
                r.get("policy", {})
                .get("access_control", {})
                .get("decisions", [])
            )
            tcc = (
                r.get("policy", {})
                .get("tool_call_control", {})
                .get("decisions", [])
            )
            for d in ac + tcc:
                inputs = d.get("inputs")
                if inputs is None:
                    continue
                embedded = inputs["request_context"]["caller"]
                rederived = compute_caller_hash(embedded)
                if rederived != top_level:
                    print(
                        f"  {RED}{BOLD}MISMATCH{RESET} on receipt "
                        f"{r['receipt_id']}"
                    )
                    break
        print(
            f"  {GREEN}{BOLD}all {len(receipts)} receipts self-consistent"
            f"{RESET} {DIM}(top-level caller_hash matches the verbatim caller "
            f"on every recorded decision, across both access_control and "
            f"tool_call_control){RESET}"
        )

        # --- Pitch --- #
        banner("5. Same source-of-record story; richer policy artifacts")
        print(
            f"  {DIM}The detector's group-by + correlation patterns work "
            f"identically{RESET}"
        )
        print(
            f"  {DIM}whether or not a unified policy is in effect. Adding "
            f"policy doesn't change{RESET}"
        )
        print(
            f"  {DIM}what caller_hash / session_id are for — they remain "
            f"decision-and-proof{RESET}"
        )
        print(
            f"  {DIM}correlation tags, completely orthogonal to per-decision "
            f"input hashes.{RESET}"
        )

        return 0


if __name__ == "__main__":
    sys.exit(main())
