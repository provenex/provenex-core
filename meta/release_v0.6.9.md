# Release notes — v0.6.9

**Headline.** Two new runnable framework demos: MCP middleware and LangGraph admission nodes. No code changes, no schema changes — these fill out the demos catalogue for the framework integrations that already shipped. Examples-only release.

## What's new since 0.6.8

### New: `examples/mcp_admission_demo.py`

Runnable end-to-end MCP integration demo. Shows:

- A naked MCP `tools/call` handler — a stand-in for what an MCP server author writes today.
- That same handler decorated with `provenex_mcp_admission(...)` — one decorator, zero changes to the handler body.
- Three live JSON-RPC `tools/call` requests through the decorated handler:
    - engineer → `web_search(google_custom_search)` → ALLOW (handler runs)
    - viewer → `jira.create_issue` → DENY (handler skipped; `ToolCallDenied` raised)
    - engineer → `jira.update_issue` → ALLOW
- The `on_deny` callback pattern translating a Provenex deny into a structured JSON-RPC error response (`{"jsonrpc": "2.0", "id": ..., "error": {"code": -32099, "message": ..., "data": {"receipt_id": ..., "rules_fired": [...]}}}`).
- Receipt drain via both the `receipts_sink=` list-append parameter (back-compat) and the 0.6.6+ `sink=` `ReceiptSink` (`StdoutJSONLSink` shown).
- The lower-level `wrap_mcp_request(...)` API for MCP routers that don't decorate.

Pure stdlib — no actual MCP server library required. The JSON-RPC envelope is simulated as a dict, which is exactly what every MCP implementation passes around internally.

### New: `examples/langgraph_admission_node_demo.py`

Runnable end-to-end LangGraph integration demo. Shows:

- The factory pattern — `provenex_admission_node(...)` produces a callable that fits LangGraph's node signature `(state) → state_delta`.
- The conditional-edge pattern — the admission node writes `tool_admitted` / `tool_decision` / `tool_rules_fired` into state; a conditional edge routes to either an `execute_jira_node` (on allow) or a `denied_handler_node` (on deny). **The admission node never invokes the underlying tool** — routing the actual call is the graph's responsibility.
- Two end-to-end scenarios:
    - engineer creates a Jira issue → admit → execute → done
    - viewer attempts to create a Jira issue → admit → deny → handler (receipt still emitted)
- Per-scenario trajectory audit via `audit_trajectory_dag`.

Pure stdlib — the Provenex LangGraph integration imports nothing from `langgraph` (the package is just plain callables), so this demo runs without the optional `[langgraph]` extra. The demo's tiny state-machine runner is semantically identical to LangGraph's conditional-edge model, so the wiring transplants directly into a real `StateGraph`.

### Docs cross-links

- `README.md` and `docs/quickstart.md` Path G now link to both new demos alongside `agentic_admission_demo.py`. Evaluators who skim the README for "does it work with MCP / LangGraph?" find runnable code in one click.

### Internal finding (demo's deep-copy comment)

While writing the MCP demo, I noticed `_decode_tools_call_request` in `provenex/tool_call/integrations/mcp.py` mutates the request dict (pops `__operation__` / `__target_system__` / `__invocation_id__` out of `arguments`). In a real MCP server this doesn't matter — request dicts aren't reused across handler invocations — but the demo re-sends the same request through two different decorators, so the demo does a per-call `copy.deepcopy(request)`. The behaviour is documented inline.

Not a bug worth fixing in code (every real MCP framework I know constructs fresh request dicts per call), but worth noting for anyone building bespoke MCP routing logic that might recycle dicts.

## Compatibility

- **No code changes.** Every entrypoint, every framework wrapper, every receipt behaves identically.
- **No schema bump.** Wire format stays at 2.3.0.
- **No new tests** — the demos exercise existing, already-tested integration paths end-to-end. **572 tests still passing.**
- **All 13 example demos green** against 0.6.9.

## Install

```bash
pip install provenex-core==0.6.9
pip install "provenex-core[policy]==0.6.9"        # YAML DSL — required for both new demos
```

The MCP and LangGraph demos depend only on the stdlib core + `[policy]` extra. No framework libraries (`langgraph`, `mcp`, etc.) are required to run them.
