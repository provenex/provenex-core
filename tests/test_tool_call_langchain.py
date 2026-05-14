"""Tests for :class:`ProvenexToolWrapper` (LangChain integration).

The wrapper is duck-typed — these tests use a tiny stand-in tool with a
``.name`` and an ``.invoke(input)``, so they run without the LangChain
extra installed. The real LangChain integration tests
(``test_langchain_integration.py``) cover the retrieval side; this file
covers the tool-call side.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    ToolCallDenied,
)
from provenex.tool_call.integrations.langchain import ProvenexToolWrapper


SECRET = b"langchain-wrapper-secret"


POLICY_YAML = """
version: 1
policy_id: lc-wrapper-test-v1
tool_call_control:
  rules:
    - name: web_search_domain_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search]
      on_violation: deny
  defaults:
    unknown_metadata: deny
"""


class _FakeTool:
    """Duck-typed stand-in for a LangChain BaseTool."""

    def __init__(self, name: str = "web_search") -> None:
        self.name = name
        self.description = "stand-in tool for tests"
        self.invocations: List[Any] = []

    def invoke(self, input: Any) -> str:
        self.invocations.append(input)
        return f"called {self.name} with {input!r}"


def _request_factory(invocation: Any) -> RequestContext:
    """Pulls caller/jurisdiction/etc from the invocation payload."""
    if isinstance(invocation, dict):
        return RequestContext(
            caller=invocation.get("__caller__", {"role": "engineer"}),
            jurisdiction=invocation.get("__jurisdiction__", "US"),
            purpose=invocation.get("__purpose__", "test"),
            timestamp=invocation.get(
                "__timestamp__", "2026-05-14T11:30:00Z"
            ),
        )
    return RequestContext(
        caller={"role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )


# --------------------------------------------------------------------------- #
# Construction validation                                                     #
# --------------------------------------------------------------------------- #


def test_rejects_base_tool_without_name():
    class Bad:
        def invoke(self, input):
            return input

    with pytest.raises(TypeError, match="must expose a .name"):
        ProvenexToolWrapper(
            base_tool=Bad(),
            policy=Policy.from_text(POLICY_YAML),
            request_factory=_request_factory,
        )


def test_rejects_base_tool_without_invoke_or_run():
    class Bad:
        name = "x"

    with pytest.raises(TypeError, match="must expose .invoke"):
        ProvenexToolWrapper(
            base_tool=Bad(),
            policy=Policy.from_text(POLICY_YAML),
            request_factory=_request_factory,
        )


# --------------------------------------------------------------------------- #
# Allow + deny semantics                                                      #
# --------------------------------------------------------------------------- #


def test_allow_path_invokes_underlying_tool_and_logs_receipt():
    tool = _FakeTool(name="web_search")
    w = ProvenexToolWrapper(
        base_tool=tool,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
        operation="query",
        target_system="google_custom_search",
    )
    result = w.invoke({"q": "weather"})
    # Underlying tool ran with cleaned input (no Provenex override keys).
    assert tool.invocations == [{"q": "weather"}]
    assert result == "called web_search with {'q': 'weather'}"
    # Receipt was logged.
    assert len(w.receipts) == 1
    d = w.receipts[0].to_dict()
    assert d["actions"][0]["name"] == "web_search"
    assert d["policy"]["tool_call_control"]["decisions"][0]["decision"] == "allow"


def test_deny_raises_tool_call_denied_and_does_not_invoke():
    tool = _FakeTool(name="web_search")
    w = ProvenexToolWrapper(
        base_tool=tool,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
        operation="query",
        target_system="duckduckgo",  # not allowlisted
    )
    with pytest.raises(ToolCallDenied) as exc_info:
        w.invoke({"q": "x"})
    # Underlying tool was NOT called.
    assert tool.invocations == []
    # Receipt was still emitted (denials are auditable).
    assert len(w.receipts) == 1
    assert exc_info.value.result.decision == "deny"


def test_on_deny_callback_replaces_exception():
    tool = _FakeTool(name="web_search")
    callbacks: List[Any] = []

    def deny_callback(admission_result):
        callbacks.append(admission_result.decision)
        return {"error": "denied", "receipt_id": admission_result.receipt.receipt_id}

    w = ProvenexToolWrapper(
        base_tool=tool,
        policy=Policy.from_text(POLICY_YAML),
        signer=HmacSha256Signer(secret=SECRET),
        request_factory=_request_factory,
        operation="query",
        target_system="duckduckgo",
        on_deny=deny_callback,
    )
    result = w.invoke({"q": "x"})
    assert callbacks == ["deny"]
    assert result["error"] == "denied"
    assert result["receipt_id"].startswith("prx_")


# --------------------------------------------------------------------------- #
# Input handling                                                              #
# --------------------------------------------------------------------------- #


def test_per_call_overrides_via_double_underscore_keys():
    tool = _FakeTool(name="web_search")
    w = ProvenexToolWrapper(
        base_tool=tool,
        policy=Policy.from_text(POLICY_YAML),
        request_factory=_request_factory,
        operation="default_op",
    )
    w.invoke(
        {
            "q": "x",
            "__operation__": "custom_op",
            "__target_system__": "google_custom_search",
            "__invocation_id__": "inv_abc",
        }
    )
    d = w.receipts[0].to_dict()
    assert d["actions"][0]["operation"] == "custom_op"
    assert d["actions"][0]["target_system"] == "google_custom_search"
    assert d["actions"][0]["invocation_id"] == "inv_abc"
    # Override keys are stripped before forwarding to the base tool.
    assert "__operation__" not in tool.invocations[0]


def test_non_dict_input_is_wrapped_as_input_parameter():
    tool = _FakeTool(name="echo")
    w = ProvenexToolWrapper(
        base_tool=tool,
        policy=None,  # no admission policy, default allow
        request_factory=_request_factory,
        operation="invoke",
    )
    w.invoke("just a string")
    d = w.receipts[0].to_dict()
    # Receipt records the parameter under the synthesised key.
    assert d["actions"][0]["parameters"] == {"input": "just a string"}
    # Underlying tool received the original verbatim string.
    assert tool.invocations == ["just a string"]


# --------------------------------------------------------------------------- #
# Cross-framework byte parity (Demo 4)                                        #
# --------------------------------------------------------------------------- #


def test_langchain_wrapper_and_direct_admission_produce_same_canonical_shape():
    """The same (tool, request, policy) routed through the LangChain
    wrapper and through admission_check directly must produce receipts
    that are byte-identical modulo receipt_id, issued_at, and
    trajectory metadata. This is the standard-setting proof.
    """
    from provenex import ToolCallContext, admission_check

    policy = Policy.from_text(POLICY_YAML)
    signer = HmacSha256Signer(secret=SECRET)
    req = RequestContext(
        caller={"role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )

    # Direct.
    direct = admission_check(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "weather"},
            target_system="google_custom_search",
        ),
        req,
        policy=policy,
        signer=signer,
    )

    # Via wrapper.
    tool = _FakeTool(name="web_search")
    w = ProvenexToolWrapper(
        base_tool=tool,
        policy=policy,
        signer=signer,
        request_factory=lambda _i: req,
        operation="query",
        target_system="google_custom_search",
    )
    w.invoke({"q": "weather"})

    d_direct = direct.receipt.to_dict()
    d_wrapped = w.receipts[0].to_dict()

    # Strip the fields that legitimately differ.
    for d in (d_direct, d_wrapped):
        del d["receipt_id"]
        del d["issued_at"]
        del d["signature"]
    # The signed canonical payload is what they share; signatures differ
    # because they cover different (receipt_id, issued_at) tuples. The
    # remaining shape — actions[], policy block, summary — should match.
    assert d_direct == d_wrapped
