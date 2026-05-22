# MCP integration deep-dive

The Model Context Protocol (MCP) is the JSON-RPC-based protocol agents use to call tools published by servers. Provenex's MCP integration lives at [provenex.tool_call.integrations.mcp](../provenex/tool_call/integrations/mcp.py): one decorator that wraps a `tools/call` handler with admission semantics, one lower-level function for routers that prefer not to decorate, and a small set of conventions for MCP server authors who want to publish provenance-aware tools.

This doc is the operational deep-dive on the MCP surface. The general tool-call admission story is in [policy.md](policy.md); the schema for the receipts produced is in [receipt_format.md](receipt_format.md).

## What the integration provides

Two public entry points:

| Entry point | Use when |
| --- | --- |
| `provenex_mcp_admission(policy=..., signer=..., request_factory=...)` | You write your own `tools/call` handler and want admission to run before the handler body executes. The decorator is the recommended path. |
| `wrap_mcp_request(request, policy=..., signer=..., request_factory=...)` | You write a router that dispatches `tools/call` requests to different handlers per tool, and want admission to run at the router level before dispatch. |

Both produce the same receipt shape; the difference is where in the request lifecycle admission fires.

## What the receipt looks like

A successful MCP admission produces a receipt with `trajectory.step_kind="tool_call"`, one entry in `actions[]`, and one entry in `policy.tool_call_control.decisions[]`. Illustrative shape (trimmed):

```json
{
  "receipt_id": "prx_...",
  "schema_version": "2.5.0",
  "issuer": "provenex-core/0.10.1",
  "caller_hash": "sha256:7a2bf01...",
  "request_binding": { ... },
  "actions": [
    {
      "action_index": 0,
      "name": "jira",
      "operation": "create_issue",
      "parameters_hash": "sha256:...",
      "parameters": {"project": "INC", "summary": "...", "description": "..."},
      "target_system": "acme.atlassian.net",
      "invocation_id": "rpc-2026-001"
    }
  ],
  "policy": {
    "verification": {"...": "..."},
    "tool_call_control": {
      "evaluator": "native_yaml",
      "policy_id": "agent-policy-v2",
      "policy_version_hash": "sha256:...",
      "policy_in_transparency_log": false,
      "decisions": [
        {
          "action_index": 0,
          "decision": "allow",
          "rules_fired": ["jira_writes_require_role"],
          "inputs_hash": "sha256:...",
          "inputs": { "tool_parameters": {...}, "request_context": {...} }
        }
      ]
    }
  },
  "summary": { "total_actions": 1, "actions_allowed": 1, "actions_denied": 0,
                "overall_status": "PASS" },
  "trajectory": { "step_kind": "tool_call", "...": "..." },
  "signature": { "algorithm": "hmac-sha256", "value": "..." }
}
```

The `parameters` field on the action carries the verbatim JSON-RPC parameters by default; redaction is opt-in via `redact_parameters=True`. The `parameters_hash` is always present and verifies against the original values whether `parameters` is recorded or not. Deny receipts carry the same shape with `decision: "deny"` and `summary.actions_denied: 1`.

## The decorator pattern

The canonical MCP integration: decorate your `tools/call` handler.

```python
from provenex import HmacSha256Signer, Policy, RequestContext
from provenex.tool_call.integrations.mcp import provenex_mcp_admission

POLICY = Policy.from_yaml("agent_policy.yaml")
SIGNER = HmacSha256Signer()

def build_request_context(request):
    # The MCP transport carries caller identity in your server's session,
    # an auth token, a JWT in the JSON-RPC envelope, etc. Provenex never
    # owns this; the request_factory pulls from wherever it lives.
    user = your_auth_layer.user_from_request(request)
    return RequestContext(
        caller={"id": user.id, "role": user.role},
        jurisdiction=user.jurisdiction,
        purpose="agent_tool_call",
        timestamp=request_timestamp(request),
    )

@provenex_mcp_admission(
    policy=POLICY,
    signer=SIGNER,
    request_factory=build_request_context,
    default_target_system="acme.atlassian.net",
)
def handle_tools_call(request):
    # On allow: this runs.
    # On deny: ToolCallDenied is raised before the body runs.
    tool_name = request["params"]["name"]
    arguments = request["params"].get("arguments", {})
    return your_existing_tool_handler(tool_name, arguments)
```

The decorator wraps `handle_tools_call` with the admission check. Each call:

1. Decodes the MCP request shape (tool name, arguments, optional invocation ID) into a `ToolCallContext`.
2. Builds a `RequestContext` via the caller-supplied `request_factory`.
3. Runs `admission_check(...)` against the policy and signer.
4. On allow, calls the wrapped handler with the original `request`.
5. On deny, raises `ToolCallDenied` (or invokes `on_deny` if supplied).

The receipt is emitted regardless of outcome. If you wired a sink, the receipt lands there; if you wired a `receipts_sink` list, the receipt is appended.

**Non-`tools/call` methods bypass admission.** The decorator inspects `request["method"]` (or the `method` attribute on duck-typed objects). Anything other than `"tools/call"` (e.g. `"resources/list"`, `"prompts/get"`, `"initialize"`) is forwarded to the wrapped handler unchanged, with no admission check and no receipt. This is deliberate: those methods carry no tool name or arguments to evaluate a policy against, and decoding them as `tools/call` would either always allow or fire the wrong rule. Apply the decorator to a `tools/call`-specific handler when you want fine-grained control, or to the dispatcher when you want the passthrough.

## The `on_deny` callback (JSON-RPC error responses)

By default, a deny raises `ToolCallDenied`. The MCP server is expected to translate that into a JSON-RPC error response. The cleaner path is to supply an `on_deny` callback that produces the JSON-RPC error directly:

```python
@provenex_mcp_admission(
    policy=POLICY,
    signer=SIGNER,
    request_factory=build_request_context,
    on_deny=lambda result, request: {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "error": {
            "code": -32099,           # application-defined; -32099 is a common choice
            "message": "tool call denied by policy",
            "data": {
                "receipt_id": result.receipt.receipt_id,
                "policy_id": result.policy_id,
                "rules_fired": result.rules_fired,
            },
        },
    },
)
def handle_tools_call(request):
    ...
```

The decorated handler now returns either the original handler's response (on allow) or the JSON-RPC error object (on deny). The client sees a structured error with the receipt ID it can use for follow-up audit.

The receipt is still emitted to the sink on deny; the `on_deny` callback does not replace the audit trail, only the wire response.

## The router pattern (`wrap_mcp_request`)

Some MCP servers route requests through a switch table rather than per-handler decoration. Run admission at the router level:

```python
from provenex.tool_call.integrations.mcp import wrap_mcp_request

def route_tools_call(request):
    result = wrap_mcp_request(
        request,
        policy=POLICY,
        signer=SIGNER,
        request_factory=build_request_context,
    )
    save_receipt(result.receipt)   # store regardless of allow/deny

    if not result.allowed:
        return {"jsonrpc": "2.0", "id": request.get("id"),
                "error": {"code": -32099, "message": "denied",
                           "data": {"receipt_id": result.receipt.receipt_id}}}

    tool_name = request["params"]["name"]
    handler = TOOL_HANDLERS[tool_name]
    return handler(request)
```

Same receipt shape as the decorator pattern; the dispatcher controls when admission fires.

## Streaming and async considerations

**Async handlers.** The integration is synchronous by design. `provenex_mcp_admission` decorates synchronous callables; for an async handler, wrap the call yourself:

```python
async def handle_tools_call_async(request):
    result = wrap_mcp_request(request, policy=POLICY, signer=SIGNER,
                              request_factory=build_request_context)
    save_receipt(result.receipt)
    if not result.allowed:
        return {"jsonrpc": "2.0", "id": request.get("id"),
                "error": {"code": -32099, "message": "denied"}}
    return await async_tool_handler(request)
```

The admission check itself is fast (sub-millisecond against an in-memory policy) and synchronous; the async-aware wrapper is around your async handler.

**Async generators / streaming responses.** Some MCP tools return streamed responses (server-sent events, long-running operations). The admission decision is made once, before the stream starts. If the stream is allowed, it runs to completion under the operator's existing streaming infrastructure; the Provenex receipt records the decision to start the stream, not the streamed content.

If you need to record decisions about individual chunks of a streamed response, emit separate receipts per chunk via `verify_chunks` or `admit_memory_write` from inside your stream loop. Each chunk's receipt links to the parent admission receipt via the trajectory cursor.

**Cancellation.** If an MCP request is cancelled by the client mid-stream, the admission receipt is still on disk (or in the sink); the cancellation is the operator's responsibility to record. Provenex does not track request lifecycle beyond the admission moment.

## Patterns for MCP server authors

If you are writing an MCP server that wants to publish provenance-aware tools, the rough shape:

1. Author a unified policy YAML for the tools your server exposes. Use `tool.name` to identify the tool (`"jira"`, `"slack"`, the MCP server-and-tool path). Use `tool.operation` for the verb (`"create_issue"`, `"send_message"`). Use `tool.parameters.<key>` for parameter constraints.

2. Build a `request_factory` that pulls caller identity from your MCP transport. Common sources: JWT in the JSON-RPC envelope, server-side session, MCP capabilities exchange handshake.

3. Decorate your `tools/call` handler with `provenex_mcp_admission`. Pass the policy, signer, and factory.

4. Configure a sink so receipts flow to your audit system. `FileJSONLSink` for local development; `KafkaSink`, `S3AppendSink`, or `PubSubSink` for production.

5. Document for clients that calls are admission-controlled. The receipt's `receipt_id` is the audit reference; clients should preserve it on each call for later forensic queries.

6. Surface admission errors to clients via a structured JSON-RPC error (the `on_deny` pattern). Include the `receipt_id` in the error so the client can request an audit.

## Worked example: a minimal MCP Jira server

A small MCP server exposing one Jira tool (`create_issue`) with admission control end-to-end. The example does not depend on a real MCP server library; the JSON-RPC envelope is simulated as a dict, mirroring what every MCP implementation passes around internally.

```python
from provenex import (
    HmacSha256Signer, Policy, RequestContext,
    FileJSONLSink,
)
from provenex.tool_call.integrations.mcp import (
    provenex_mcp_admission, ToolCallDenied,
)


POLICY_YAML = """
version: 1
policy_id: mcp-jira-server-v1

tool_call_control:
  rules:
    - name: jira_writes_require_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue, update_issue, delete_issue] }
      require:
        request.caller.role: { in: [engineer, manager, admin] }
      on_violation: deny
    - name: project_allowlist
      when:
        tool.name: jira
        tool.operation: create_issue
      require:
        tool.parameters.project: { in: [INC, PROD, DEV] }
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""

POLICY = Policy.from_text(POLICY_YAML)
SIGNER = HmacSha256Signer()
SINK = FileJSONLSink("/var/log/provenex/mcp")


def build_request_context(request: dict) -> RequestContext:
    # The MCP transport carries caller identity. Adapt to your auth layer.
    auth = request.get("_session", {})
    return RequestContext(
        caller={"id": auth.get("user_id"), "role": auth.get("role")},
        jurisdiction=auth.get("jurisdiction", "US"),
        purpose="agent_jira_action",
        timestamp=request.get("_timestamp"),
    )


def _deny_response(result, request):
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "error": {
            "code": -32099,
            "message": f"denied by {result.policy_id}",
            "data": {
                "receipt_id": result.receipt.receipt_id,
                "rules_fired": result.rules_fired,
            },
        },
    }


@provenex_mcp_admission(
    policy=POLICY,
    signer=SIGNER,
    request_factory=build_request_context,
    default_target_system="acme.atlassian.net",
    sink=SINK,
    on_deny=_deny_response,
)
def handle_tools_call(request: dict) -> dict:
    tool_name = request["params"]["name"]
    arguments = request["params"].get("arguments", {})

    if tool_name == "jira" and arguments.get("operation") == "create_issue":
        issue = jira_client.create_issue(
            project=arguments["project"],
            summary=arguments["summary"],
        )
        return {"jsonrpc": "2.0", "id": request.get("id"),
                "result": {"issue_key": issue.key}}

    return {"jsonrpc": "2.0", "id": request.get("id"),
            "error": {"code": -32601, "message": f"unknown tool {tool_name}"}}


# --- Test the server ---

# 1. Engineer creates an INC issue: allowed.
allowed_request = {
    "jsonrpc": "2.0", "id": "req-1",
    "method": "tools/call",
    "params": {"name": "jira", "arguments": {"operation": "create_issue",
                                              "project": "INC",
                                              "summary": "Outage in payment service"}},
    "_session": {"user_id": "u_42", "role": "engineer", "jurisdiction": "US"},
    "_timestamp": "2026-05-14T11:30:00Z",
}
response = handle_tools_call(allowed_request)
# response: {"jsonrpc": "2.0", "id": "req-1", "result": {"issue_key": "INC-1234"}}

# 2. Viewer (read-only role) attempts to create an issue: denied.
denied_request = {
    "jsonrpc": "2.0", "id": "req-2",
    "method": "tools/call",
    "params": {"name": "jira", "arguments": {"operation": "create_issue",
                                              "project": "INC",
                                              "summary": "..."}},
    "_session": {"user_id": "u_99", "role": "viewer", "jurisdiction": "US"},
    "_timestamp": "2026-05-14T11:30:01Z",
}
response = handle_tools_call(denied_request)
# response: {"jsonrpc": "2.0", "id": "req-2",
#            "error": {"code": -32099, "message": "denied by mcp-jira-server-v1",
#                      "data": {"receipt_id": "prx_...",
#                                "rules_fired": ["jira_writes_require_role"]}}}

# Receipts for both requests are in /var/log/provenex/mcp/
```

After this code runs, `/var/log/provenex/mcp/` contains one signed JSONL file with two receipts, one allowed and one denied. Either receipt verifies offline via `provenex audit receipt.json`.

## Read next

- [provenex/tool_call/integrations/mcp.py](../provenex/tool_call/integrations/mcp.py): the source.
- [examples/mcp_admission_demo.py](../examples/mcp_admission_demo.py): runnable end-to-end demo of the decorator, the `on_deny` pattern, and the `wrap_mcp_request` API.
- [policy.md](policy.md): the unified policy DSL for tool-call admission.
- [receipt_format.md § actions[]](receipt_format.md#actions-schema-220): the wire schema for the action records the MCP receipts produce.
- [streaming_export_ops.md](streaming_export_ops.md): the operational notes for the sink configuration the example uses.
