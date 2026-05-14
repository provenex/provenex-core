"""Tests for the MCP middleware reference implementation.

Imports nothing from any MCP SDK. MCP requests are JSON-RPC envelopes,
modelled here as plain dicts. If the official MCP SDK lands in the
``[mcp]`` extra later, the same wrapper works without modification.
"""

from __future__ import annotations

from typing import Any, List

import pytest

from provenex import HmacSha256Signer, Policy, RequestContext, ToolCallDenied
from provenex.tool_call.integrations.mcp import (
    ADMISSION_DENIED_ERROR_CODE,
    provenex_mcp_admission,
    wrap_mcp_request,
)


SECRET = b"mcp-middleware-secret"


POLICY_YAML = """
version: 1
policy_id: mcp-test-v1
tool_call_control:
  rules:
    - name: web_search_domain_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search]
      on_violation: deny
    - name: jira_write_role
      when:
        tool.name: jira
        tool.operation: { in: [create_issue] }
      require:
        request.caller.role: { in: [engineer, manager] }
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


def _request_factory(request: Any) -> RequestContext:
    """Extract caller from the JSON-RPC request's `_meta.caller`.

    Real MCP transports carry caller identity in transport-layer auth
    (mTLS cert, bearer token); the official SDK exposes it through
    ``request.context``. For test purposes we tunnel through `_meta`.
    """
    meta = request.get("_meta", {}) if isinstance(request, dict) else {}
    return RequestContext(
        caller=meta.get("caller", {"role": "engineer"}),
        jurisdiction=meta.get("jurisdiction", "US"),
        purpose=meta.get("purpose", "test"),
        timestamp=meta.get("timestamp", "2026-05-14T11:30:00Z"),
    )


def _mcp_request(name: str, arguments: dict, **meta) -> dict:
    """Build a JSON-RPC tools/call request."""
    return {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
        "id": "req-001",
        "_meta": meta,
    }


# --------------------------------------------------------------------------- #
# wrap_mcp_request — direct admission                                         #
# --------------------------------------------------------------------------- #


def test_allow_path_for_mcp_web_search():
    req = _mcp_request(
        "web_search",
        {"q": "weather", "__target_system__": "google_custom_search"},
    )
    result = wrap_mcp_request(
        req,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
    )
    assert result.allowed is True
    assert result.decision == "allow"
    d = result.receipt.to_dict()
    assert d["actions"][0]["name"] == "web_search"
    assert d["actions"][0]["target_system"] == "google_custom_search"
    # The invocation_id picks up the JSON-RPC request id by default.
    assert d["actions"][0]["invocation_id"] == "req-001"


def test_deny_path_for_disallowed_search_provider():
    req = _mcp_request(
        "web_search",
        {"q": "x", "__target_system__": "duckduckgo"},
    )
    result = wrap_mcp_request(
        req,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
    )
    assert result.allowed is False
    assert result.rules_fired == ["web_search_domain_allowlist"]


def test_default_target_system_from_server():
    """A server that fronts exactly one backend doesn't make clients
    pass ``target_system`` per call. The middleware fills it in.
    """
    req = _mcp_request("web_search", {"q": "x"})
    result = wrap_mcp_request(
        req,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
        default_target_system="google_custom_search",
    )
    assert result.allowed is True
    assert (
        result.receipt.to_dict()["actions"][0]["target_system"]
        == "google_custom_search"
    )


def test_operation_extracted_from_arguments():
    """For tools whose operation is encoded in the arguments dict
    (``arguments.operation``), the middleware surfaces it as
    ``tool.operation``.
    """
    req = _mcp_request(
        "jira",
        {"operation": "create_issue", "project": "INC", "summary": "..."},
    )
    result = wrap_mcp_request(
        req,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
    )
    assert result.allowed is True
    assert result.receipt.to_dict()["actions"][0]["operation"] == "create_issue"


def test_jira_role_gate_denies_viewer():
    req = _mcp_request(
        "jira",
        {"operation": "create_issue", "summary": "..."},
        caller={"role": "viewer"},
    )
    result = wrap_mcp_request(
        req,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
    )
    assert result.decision == "deny"
    assert result.rules_fired == ["jira_write_role"]


# --------------------------------------------------------------------------- #
# provenex_mcp_admission — handler decorator                                  #
# --------------------------------------------------------------------------- #


def test_decorator_runs_underlying_handler_on_allow():
    receipts: List[Any] = []
    handler_called_with: List[Any] = []

    @provenex_mcp_admission(
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
        receipts_sink=receipts,
    )
    def handle_tools_call(request):
        handler_called_with.append(request)
        return {"result": "ok"}

    req = _mcp_request(
        "web_search",
        {"q": "x", "__target_system__": "google_custom_search"},
    )
    response = handle_tools_call(req)
    assert response == {"result": "ok"}
    assert handler_called_with == [req]
    assert len(receipts) == 1


def test_decorator_raises_on_deny_by_default():
    receipts: List[Any] = []
    handler_called: List[Any] = []

    @provenex_mcp_admission(
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
        receipts_sink=receipts,
    )
    def handle_tools_call(request):
        handler_called.append(request)
        return {"result": "ok"}

    req = _mcp_request(
        "web_search",
        {"q": "x", "__target_system__": "duckduckgo"},
    )
    with pytest.raises(ToolCallDenied) as exc_info:
        handle_tools_call(req)
    # Underlying handler NEVER ran.
    assert handler_called == []
    # Receipt was still emitted.
    assert len(receipts) == 1
    assert exc_info.value.result.decision == "deny"


def test_decorator_on_deny_callback_returns_jsonrpc_error_shape():
    def to_jsonrpc_error(result, request):
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {
                "code": ADMISSION_DENIED_ERROR_CODE,
                "message": f"denied by policy {result.policy_id}",
                "data": {"receipt_id": result.receipt.receipt_id},
            },
        }

    @provenex_mcp_admission(
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
        on_deny=to_jsonrpc_error,
    )
    def handle_tools_call(request):
        return {"result": "should-not-reach"}

    req = _mcp_request(
        "web_search",
        {"q": "x", "__target_system__": "duckduckgo"},
    )
    response = handle_tools_call(req)
    assert response["error"]["code"] == ADMISSION_DENIED_ERROR_CODE
    assert "denied by policy mcp-test-v1" in response["error"]["message"]
    assert response["error"]["data"]["receipt_id"].startswith("prx_")
