"""Reference MCP middleware.

The Model Context Protocol (MCP) defines a JSON-RPC envelope for agent
↔ tool communication. ``tools/call`` is the request that says "the
agent wants to invoke tool X with parameters Y" — exactly the
admission decision point Phase 2 is designed for. Intercepting at the
MCP layer rather than per-framework means one wrapper covers every
agent client and every tool server that speaks the protocol, including
ones that don't exist yet.

This module imports nothing from any MCP SDK. MCP servers are
JSON-RPC handlers; the wrapper is callable. The intercept shape works
with the official Python MCP SDK, with anyone else's Python MCP
implementation, and with a hand-rolled JSON-RPC handler. The receipt
shape and policy DSL are identical to what the LangChain wrapper
emits — that's load-bearing for the standard-setting moat.

Two patterns:

    1. :func:`provenex_mcp_admission` — a function decorator for a
       single ``tools/call`` handler. Use when your server is built
       around explicit handler callables.
    2. :func:`wrap_mcp_request` — a one-shot function that takes a
       parsed JSON-RPC ``tools/call`` request and runs admission. Use
       when your server is built around request-routing inside a
       single handler function.

Both ultimately delegate to :func:`provenex.admission_check`. There is
no MCP-specific receipt shape and no MCP-specific policy DSL.

Decision-not-execution discipline: this middleware NEVER makes the
actual tool call. It returns / raises a decision; the underlying
handler (the one being wrapped) executes the call against the tool
server's own credentials. Provenex does not become an MCP gateway in
this design.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ...core.receipt import ReceiptSigner
from ...core.trajectory import TrajectoryContext
from ...policy.evaluator import RequestContext
from ..admission import AdmissionResult, admission_check
from ..context import ToolCallContext


# A factory that turns an incoming MCP request into a RequestContext.
# Provenex does not own identity — the host application supplies it
# here from the transport (e.g., bearer token, mTLS cert, MCP
# session metadata).
RequestFactory = Callable[[Any], RequestContext]


# JSON-RPC error code Provenex emits on deny. -32000 is reserved for
# application-defined server errors in the JSON-RPC 2.0 spec. -32099
# is the bottom end of that range; we use it as our reserved code so
# Provenex denials don't collide with the tool implementation's own
# application errors (which typically take -32000 through -32050).
ADMISSION_DENIED_ERROR_CODE = -32099


@dataclass
class _CallShape:
    """Decoded shape of an MCP ``tools/call`` request.

    Holds just enough to build a :class:`ToolCallContext`. Defined as a
    dataclass so the request-decoder is unit-testable without
    constructing whole JSON-RPC objects.
    """

    name: str
    operation: str
    parameters: Dict[str, Any]
    target_system: Optional[str]
    invocation_id: Optional[str]


def _decode_tools_call_request(
    request: Any,
    *,
    default_target_system: Optional[str] = None,
) -> _CallShape:
    """Pull the tool-call fields out of a JSON-RPC tools/call request.

    Accepts:
        * Dict-shaped requests (raw JSON-RPC).
        * Duck-typed objects with ``params`` attribute (some MCP SDKs).

    The MCP ``tools/call`` shape is:

        { "method": "tools/call",
          "params": {
              "name": "<tool-name>",
              "arguments": { ... }   // optional, may be missing
          },
          "id": <request-id>
        }

    ``operation`` is not part of the standard MCP ``tools/call``
    request — some tools encode the operation in the ``name``
    (``"jira.create_issue"``), some pass it inside ``arguments``
    (``arguments.operation``), some have one operation per tool. We
    surface what's there with sensible fallbacks; the policy author
    chooses how to gate on it.
    """
    params = _get(request, "params") or {}
    name = _get(params, "name") or ""
    arguments = _get(params, "arguments") or {}
    if not isinstance(arguments, dict):
        # MCP allows arguments to be any JSON value. Wrap non-dict so
        # the receipt has a consistent shape to canonicalise.
        arguments = {"value": arguments}

    operation = arguments.pop("__operation__", arguments.get("operation", "invoke"))
    target_system = (
        arguments.pop("__target_system__", None)
        or _get(params, "target_system")
        or default_target_system
    )
    invocation_id = arguments.pop("__invocation_id__", None) or str(
        _get(request, "id") or ""
    ) or None

    return _CallShape(
        name=name,
        operation=operation,
        parameters=arguments,
        target_system=target_system,
        invocation_id=invocation_id,
    )


def _get(obj: Any, key: str) -> Any:
    """Read ``key`` off ``obj`` whether it's a dict or an attribute carrier."""
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #


def wrap_mcp_request(
    request: Any,
    *,
    policy: Any = None,
    signer: Optional[ReceiptSigner] = None,
    request_factory: RequestFactory,
    trajectory: Optional[TrajectoryContext] = None,
    default_target_system: Optional[str] = None,
    redact_parameters: bool = False,
) -> AdmissionResult:
    """Admission-check one MCP ``tools/call`` request.

    Use as the first step in your server's ``tools/call`` handler:

        def handle_tools_call(request):
            result = wrap_mcp_request(
                request,
                policy=POLICY,
                signer=SIGNER,
                request_factory=build_request_context,
            )
            if not result.allowed:
                raise McpError(
                    code=ADMISSION_DENIED_ERROR_CODE,
                    message=f"denied by policy {result.policy_id}",
                    data={"receipt_id": result.receipt.receipt_id},
                )
            # ... proceed to invoke the actual tool with your own credentials
            save_receipt(result.receipt)

    The receipt is reachable on both allow and deny — store it
    regardless.
    """
    shape = _decode_tools_call_request(
        request, default_target_system=default_target_system
    )
    tool = ToolCallContext(
        name=shape.name,
        operation=shape.operation,
        parameters=shape.parameters,
        target_system=shape.target_system,
        invocation_id=shape.invocation_id,
    )
    return admission_check(
        tool=tool,
        request=request_factory(request),
        policy=policy,
        signer=signer,
        trajectory=trajectory,
        redact_parameters=redact_parameters,
    )


def provenex_mcp_admission(
    *,
    policy: Any,
    signer: Optional[ReceiptSigner] = None,
    request_factory: RequestFactory,
    default_target_system: Optional[str] = None,
    redact_parameters: bool = False,
    on_deny: Optional[Callable[[AdmissionResult, Any], Any]] = None,
    receipts_sink: Optional[List[Any]] = None,
) -> Callable[[Callable[[Any], Any]], Callable[[Any], Any]]:
    """Decorator for an MCP ``tools/call`` handler.

    Wraps a handler ``handle(request) -> response`` so each call passes
    through admission first. Allow path: the wrapped handler runs as
    normal. Deny path: by default, raises a structured exception (the
    server should translate to a JSON-RPC error response); if
    ``on_deny`` is supplied, its return value becomes the handler's
    return value.

    Args:
        policy: The unified :class:`provenex.Policy`. The
            ``tool_call_control`` half drives admission. The other
            halves are recorded on the receipt unchanged.
        signer: Optional :class:`ReceiptSigner`.
        request_factory: Callable ``request → RequestContext``. The MCP
            transport supplies caller identity; this factory extracts
            it. Provenex does not own identity.
        default_target_system: Optional fallback ``target_system`` when
            the request doesn't carry one explicitly. Servers
            advertising a single backend service (one Jira instance,
            one search provider) typically set this.
        redact_parameters: If True, parameters are recorded as ``null``
            on receipts; the hash is unaffected.
        on_deny: Optional callback ``(AdmissionResult, original_request)
            -> Any`` invoked instead of raising on deny. Useful when
            your server emits its own structured JSON-RPC error
            objects.
        receipts_sink: Optional list to append every emitted receipt
            to. Use to drain receipts from the server's request loop
            for downstream persistence. Each receipt is appended after
            admission, before the wrapped handler runs.

    Returns:
        A decorator. Apply to your ``tools/call`` handler.
    """
    from ..admission import ToolCallDenied  # local to keep import cycles tight

    def decorator(handler: Callable[[Any], Any]) -> Callable[[Any], Any]:
        def wrapped(request: Any) -> Any:
            result = wrap_mcp_request(
                request,
                policy=policy,
                signer=signer,
                request_factory=request_factory,
                default_target_system=default_target_system,
                redact_parameters=redact_parameters,
            )
            if receipts_sink is not None:
                receipts_sink.append(result.receipt)
            if not result.allowed:
                if on_deny is not None:
                    return on_deny(result, request)
                raise ToolCallDenied(result)
            return handler(request)

        return wrapped

    return decorator


__all__ = [
    "ADMISSION_DENIED_ERROR_CODE",
    "RequestFactory",
    "provenex_mcp_admission",
    "wrap_mcp_request",
]
