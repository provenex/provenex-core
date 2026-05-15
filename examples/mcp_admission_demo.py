"""MCP admission demo (0.6.9+) — Model Context Protocol middleware.

Run with:

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/mcp_admission_demo.py

What it shows, in order:

    1. A toy MCP ``tools/call`` handler — what an MCP server author
       writes today (no Provenex). The handler accepts a JSON-RPC
       request dict and returns a JSON-RPC response dict.

    2. The same handler decorated with ``provenex_mcp_admission``
       — one decorator, zero changes to the handler body. Every
       call now passes through admission first; allow → handler
       runs as normal; deny → ``ToolCallDenied`` raised (or
       ``on_deny`` callback fires) and the handler does not run.

    3. Three live ``tools/call`` requests through the decorated
       handler:
         - engineer calling web_search → ALLOWED → handler runs
         - viewer calling jira.create_issue → DENIED by role gate
         - engineer calling jira.update_issue → ALLOWED

    4. The ``on_deny`` pattern: a custom callback that translates
       the deny into a structured JSON-RPC error response instead
       of raising — useful for MCP servers that emit their own
       error shapes.

    5. Receipt drain: every allow AND every deny produces a signed
       receipt. Drain them via the ``receipts_sink=`` list-append
       parameter (back-compat 0.5+) or the 0.6.6+ ``sink=``
       ReceiptSink — both shown.

The pitch: drop-in MCP middleware. Provenex never holds OAuth
tokens, never proxies the call, never touches the response payload
— it returns a decision and emits a receipt. The MCP server keeps
its own credentials and its own response shape; the decorator is
strictly a wrapper.

Pure stdlib. No actual MCP server library required — we simulate
the JSON-RPC envelope as a dict, which is exactly what every MCP
implementation passes around internally.
"""

from __future__ import annotations

import copy
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    StdoutJSONLSink,
)
from provenex.tool_call.integrations.mcp import (
    ADMISSION_DENIED_ERROR_CODE,
    provenex_mcp_admission,
    wrap_mcp_request,
)


_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
BLUE = "\033[34m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


# A unified policy. The tool_call_control half drives admission;
# rules use the same DSL as the framework-agnostic admission_check.
POLICY_YAML = """
version: 1
policy_id: mcp-demo-v1

tool_call_control:
  rules:
    # Domain allowlist on web_search — only approved providers.
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny

    # Role gate on Jira writes — engineers and admins only.
    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation:
          in: [create_issue, update_issue, delete_issue]
      require:
        request.caller.role:
          in: [engineer, manager, admin]
      on_violation: deny

  defaults:
    unknown_metadata: allow
"""


# ----- The MCP server author's code (untouched by Provenex) ----- #


def my_tools_call_handler(request: Dict[str, Any]) -> Dict[str, Any]:
    """A toy MCP tools/call handler.

    In real MCP this is what you write today. Returns a JSON-RPC
    response dict per the MCP / JSON-RPC 2.0 envelope spec.

    NB: this body does NOT know about Provenex. The decorator runs
    admission first; if admission denies, this body never executes.
    """
    name = request["params"]["name"]
    args = request["params"]["arguments"]
    # Simulated execution result — in real MCP this is where you'd
    # call Jira / your search provider / etc. with YOUR credentials.
    return {
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": f"(simulated) {name}.{args.get('operation', 'invoke')} → ok",
                }
            ]
        },
    }


# ----- The Provenex request-factory: how the MCP envelope maps to
# a Provenex RequestContext. In a real deployment, this reads
# session / IdP / JWT claims off the request. ----- #


def request_factory(request: Dict[str, Any]) -> RequestContext:
    """Pull caller identity from the MCP request envelope.

    Most production MCP servers attach a session token / JWT /
    custom auth claim to the request. The factory's job is to read
    that and produce a Provenex :class:`RequestContext`. Provenex
    does NOT own identity — that's the host application's call.
    """
    caller_info = request["params"]["arguments"].get("__provenex_caller__", {})
    return RequestContext(
        caller=caller_info,
        jurisdiction=request["params"]["arguments"].get("__provenex_jurisdiction__", "US"),
        purpose=request["params"]["arguments"].get("__provenex_purpose__", "tool_call"),
        timestamp=request["params"]["arguments"].get(
            "__provenex_ts__", "2026-05-15T11:30:00Z"
        ),
        session_id=request["params"]["arguments"].get("__provenex_session_id__"),
    )


def banner(s: str) -> None:
    print()
    print(f"{BOLD}{BLUE}=== {s} ==={RESET}")
    print()


def summary(label: str, value: str) -> None:
    print(f"  {DIM}{label:.<28}{RESET} {value}")


def main() -> int:
    if not os.environ.get("PROVENEX_SIGNING_SECRET"):
        print(
            f"{RED}error:{RESET} PROVENEX_SIGNING_SECRET is not set.",
            file=sys.stderr,
        )
        return 2

    policy = Policy.from_text(POLICY_YAML)
    signer = HmacSha256Signer()

    # --- 1. The naked handler --- #
    banner("1. The MCP handler before Provenex")
    print(
        f"  {DIM}A handler that knows nothing about admission. Returns the"
        f"{RESET}"
    )
    print(
        f"  {DIM}standard JSON-RPC 2.0 response envelope. Production MCP{RESET}"
    )
    print(
        f"  {DIM}servers look exactly like this.{RESET}"
    )

    # --- 2. Decorate it with provenex_mcp_admission --- #
    banner("2. Same handler, one decorator added")
    receipts_list: List[Any] = []   # back-compat list-append sink

    # Also wire up a ReceiptSink (0.6.6+) so the receipts also stream
    # to stdout — both sinks work side-by-side.
    streaming_buf = io.StringIO()
    streaming_sink = StdoutJSONLSink(stream=streaming_buf)

    decorated = provenex_mcp_admission(
        policy=policy,
        signer=signer,
        request_factory=request_factory,
        default_target_system=None,
        receipts_sink=receipts_list,    # list.append for back-compat
        sink=streaming_sink,            # 0.6.6+ ReceiptSink for streaming
    )(my_tools_call_handler)

    print(
        f"  {GREEN}@provenex_mcp_admission{RESET}{DIM}(policy=..., signer=..., "
        f"request_factory=...){RESET}\n"
        f"  {GREEN}def handle_tools_call(request):{RESET}\n"
        f"  {GREEN}    return your_existing_handler(request){RESET}"
    )

    # --- 3. Three live tools/call requests --- #
    banner("3. Three live tools/call requests through the decorated handler")

    requests = [
        {
            # Engineer calls web_search → policy allows → handler runs
            "label": "engineer → web_search (google_custom_search)",
            "expect": "ALLOW",
            "request": {
                "jsonrpc": "2.0",
                "id": "req-001",
                "method": "tools/call",
                "params": {
                    "name": "web_search",
                    "arguments": {
                        "q": "auth-gateway 5xx mitigation",
                        "__operation__": "query",
                        "__target_system__": "google_custom_search",
                        "__provenex_caller__": {
                            "id": "u_42", "role": "engineer"
                        },
                        "__provenex_session_id__": "demo-session-001",
                    },
                },
            },
        },
        {
            # Viewer attempts a Jira write → policy denies → handler skipped
            "label": "viewer → jira.create_issue",
            "expect": "DENY",
            "request": {
                "jsonrpc": "2.0",
                "id": "req-002",
                "method": "tools/call",
                "params": {
                    "name": "jira",
                    "arguments": {
                        "project": "INC",
                        "summary": "demo issue",
                        "__operation__": "create_issue",
                        "__target_system__": "acme.atlassian.net",
                        "__provenex_caller__": {
                            "id": "u_99", "role": "viewer"
                        },
                        "__provenex_session_id__": "demo-session-001",
                    },
                },
            },
        },
        {
            # Engineer's Jira update → policy allows
            "label": "engineer → jira.update_issue",
            "expect": "ALLOW",
            "request": {
                "jsonrpc": "2.0",
                "id": "req-003",
                "method": "tools/call",
                "params": {
                    "name": "jira",
                    "arguments": {
                        "issue_key": "TICKET-001",
                        "transition": "in_progress",
                        "__operation__": "update_issue",
                        "__target_system__": "acme.atlassian.net",
                        "__provenex_caller__": {
                            "id": "u_42", "role": "engineer"
                        },
                        "__provenex_session_id__": "demo-session-001",
                    },
                },
            },
        },
    ]

    from provenex import ToolCallDenied

    for spec in requests:
        label = spec["label"]
        expect = spec["expect"]
        try:
            # NB: deep-copy the request because the MCP decoder pops
            # the ``__operation__`` / ``__target_system__`` /
            # ``__invocation_id__`` keys out of arguments during
            # decoding. A real MCP server doesn't reuse request
            # dicts, so this isn't observable in production — but
            # in this demo we re-send the same dict in section 4,
            # so a per-call deep-copy keeps the demo self-consistent.
            response = decorated(copy.deepcopy(spec["request"]))
            colour = GREEN
            outcome = "ALLOW (handler ran)"
            print(
                f"  {colour}✓{RESET} {label:<50} → {colour}{outcome}{RESET}"
            )
            summary("Handler output", response["result"]["content"][0]["text"])
        except ToolCallDenied as e:
            colour = RED
            outcome = f"DENY ({e.result.policy_id}, rules: {','.join(e.result.rules_fired)})"
            print(
                f"  {colour}✗{RESET} {label:<50} → {colour}{outcome}{RESET}"
            )
            summary("Receipt id", e.result.receipt.receipt_id)
        # Sanity-check vs expectation.
        actual = "ALLOW" if "(handler ran)" in outcome else "DENY"
        assert actual == expect, f"expected {expect}, got {actual} for {label}"

    # --- 4. The on_deny pattern: structured JSON-RPC error response --- #
    banner("4. on_deny pattern — return a JSON-RPC error response on deny")

    def deny_to_jsonrpc_error(result: Any, original_request: Any) -> Dict[str, Any]:
        """Translate a Provenex deny into a JSON-RPC 2.0 error envelope.

        MCP servers that emit their own structured error shapes use
        on_deny to translate. The receipt is still appended to the
        list / streamed via sink for audit.
        """
        return {
            "jsonrpc": "2.0",
            "id": original_request.get("id"),
            "error": {
                "code": ADMISSION_DENIED_ERROR_CODE,
                "message": f"denied by policy {result.policy_id}",
                "data": {
                    "receipt_id": result.receipt.receipt_id,
                    "rules_fired": result.rules_fired,
                },
            },
        }

    decorated_with_on_deny = provenex_mcp_admission(
        policy=policy,
        signer=signer,
        request_factory=request_factory,
        receipts_sink=receipts_list,
        on_deny=deny_to_jsonrpc_error,
    )(my_tools_call_handler)

    # Same viewer + jira.create_issue request → returns error response
    # instead of raising. Deep-copy as above.
    err_response = decorated_with_on_deny(copy.deepcopy(requests[1]["request"]))
    print(f"  {RED}{BOLD}Deny → structured JSON-RPC error:{RESET}")
    print("    " + json.dumps(err_response, indent=2).replace("\n", "\n    "))

    # --- 5. Receipt drain --- #
    banner("5. Receipt drain — every allow AND deny produces a signed receipt")

    print(
        f"  Receipts collected via receipts_sink list: "
        f"{GREEN}{len(receipts_list)}{RESET}"
    )
    for i, r in enumerate(receipts_list):
        d = r.to_dict()
        action = d.get("actions", [{}])[0]
        decision = (
            d.get("policy", {})
            .get("tool_call_control", {})
            .get("decisions", [{}])[0]
            .get("decision", "n/a")
        )
        colour = GREEN if decision == "allow" else RED
        print(
            f"    {i+1}. {DIM}{r.receipt_id[:20]}…{RESET}  "
            f"{action.get('name', '?'):<12} {action.get('operation', '?'):<14} "
            f"→ {colour}{decision}{RESET}"
        )

    # Stream side: the ReceiptSink also got each receipt as JSONL.
    lines = [line for line in streaming_buf.getvalue().splitlines() if line]
    print(
        f"\n  Receipts streamed via ``sink=StdoutJSONLSink(...)`` (0.6.6+): "
        f"{GREEN}{len(lines)}{RESET} JSON lines."
    )
    print(
        f"  {DIM}(streaming captured to in-memory buffer for this demo; "
        f"in production point at Kafka / SQS / S3 / Pub/Sub / a file){RESET}"
    )

    # --- 6. Lower-level wrap_mcp_request (no decorator) --- #
    banner("6. wrap_mcp_request — lower-level (no decorator)")
    print(
        f"  {DIM}For MCP servers that don't decorate handlers (e.g. routers "
        f"that dispatch{RESET}"
    )
    print(
        f"  {DIM}across multiple handler styles), call wrap_mcp_request "
        f"directly:{RESET}"
    )

    direct_result = wrap_mcp_request(
        request=copy.deepcopy(requests[0]["request"]),   # the allowed web_search
        policy=policy,
        signer=signer,
        request_factory=request_factory,
    )
    summary("Decision", f"{GREEN}{direct_result.decision.upper()}{RESET}")
    summary("Receipt id", direct_result.receipt.receipt_id)
    summary("Rules fired", ", ".join(direct_result.rules_fired) or "(none)")

    # --- 7. Pitch --- #
    banner("7. Decision and proof, not execution")
    print(
        f"  {DIM}Provenex returns a decision and emits a signed receipt. The"
        f"{RESET}"
    )
    print(
        f"  {DIM}MCP handler executes the actual tool call with its own"
        f"{RESET}"
    )
    print(
        f"  {DIM}credentials and own response shape. We never hold OAuth"
        f"{RESET}"
    )
    print(
        f"  {DIM}tokens; we never proxy traffic; we never touch the response"
        f"{RESET}"
    )
    print(
        f"  {DIM}payload. One decorator, drop-in. Denies are auditable too."
        f"{RESET}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
