"""LangChain tool wrapper.

Wraps any LangChain tool — anything with a ``.name`` attribute and an
``.invoke(input)`` method (the post-0.2 ``Runnable`` protocol) — so each
invocation passes through Provenex admission before the underlying tool
runs. On deny, the wrapper raises :class:`ToolCallDenied`; agent
frameworks surface this through their normal tool-error path.

LangChain is an optional dependency. This module imports nothing from
``langchain`` itself — wrapping is duck-typed against ``.name`` and
``.invoke``. The ``langchain`` package is required only when the caller
constructs actual LangChain tools to pass in.

Drop-in usage with an existing agent:

    from provenex import Policy, HmacSha256Signer, RequestContext
    from provenex.tool_call.integrations.langchain import ProvenexToolWrapper

    policy = Policy.from_yaml("agent_policy.yaml")
    signer = HmacSha256Signer()

    def make_request(invocation):
        # Build a RequestContext per call. In a real app, identity comes
        # from your auth layer (Okta, Azure AD, etc.) — Provenex does
        # not own identity. This factory is the "not execution" line in
        # framework form.
        return RequestContext(
            caller=invocation.get("caller", {}),
            jurisdiction=invocation.get("jurisdiction"),
            purpose=invocation.get("purpose"),
            timestamp=invocation.get("timestamp"),
        )

    wrapped = ProvenexToolWrapper(
        base_tool=jira_tool,
        policy=policy,
        signer=signer,
        request_factory=make_request,
    )
    agent.tools = [wrapped]   # rest of the agent code unchanged
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from ...core.receipt import ReceiptSigner
from ...core.trajectory import TrajectoryContext
from ...policy.evaluator import RequestContext
from ..admission import AdmissionResult, admission_check
from ..context import ToolCallContext


# A RequestFactory is any callable invocation_payload → RequestContext.
# Provenex does not own identity. The factory is the seam where the
# host application injects caller / jurisdiction / purpose / timestamp.
RequestFactory = Callable[[Any], RequestContext]


class ProvenexToolWrapper:
    """LangChain tool wrapper that admission-checks every invocation.

    Args:
        base_tool: Any object with a ``.name`` attribute and an
            ``.invoke(input)`` method. LangChain ``BaseTool`` instances
            qualify; so do anything that duck-types this protocol.
        policy: The unified :class:`provenex.Policy`. Only the
            ``tool_call_control`` half is consulted for tool calls; the
            verification and access_control halves are recorded
            unchanged on the receipt but do not affect the admission
            decision.
        signer: Optional :class:`ReceiptSigner`. Production should
            always sign.
        request_factory: Callable that turns the LangChain invocation
            payload (typically a dict) into a
            :class:`RequestContext`. Provenex does not own identity —
            the host application supplies it here.
        operation: Optional default operation string. Many LangChain
            tools have only one operation; for those, pass a constant
            like ``"invoke"`` or override per-call via the invocation
            payload's ``"operation"`` key.
        target_system: Optional default target-system string. Same
            semantics as ``operation``.
        redact_parameters: If True, parameters are recorded as ``null``
            on receipts; the ``parameters_hash`` survives.
        on_deny: Optional callback ``(AdmissionResult) -> Any`` invoked
            instead of raising on a denied admission. The callable's
            return value becomes the tool's return value. Use when the
            agent framework expects a structured error rather than an
            exception.

    The wrapper exposes ``name`` (mirroring the base tool's) and
    ``invoke``; that's enough for the LangChain agent runner.
    """

    def __init__(
        self,
        base_tool: Any,
        *,
        policy: Any,
        signer: Optional[ReceiptSigner] = None,
        request_factory: RequestFactory,
        operation: str = "invoke",
        target_system: Optional[str] = None,
        redact_parameters: bool = False,
        on_deny: Optional[Callable[[AdmissionResult], Any]] = None,
    ) -> None:
        if not hasattr(base_tool, "name"):
            raise TypeError(
                "base_tool must expose a .name attribute (LangChain BaseTool "
                "convention or any duck-typed equivalent)"
            )
        if not hasattr(base_tool, "invoke") and not hasattr(base_tool, "run"):
            raise TypeError(
                "base_tool must expose .invoke(input) or .run(input)"
            )
        self._base_tool = base_tool
        self._policy = policy
        self._signer = signer
        self._request_factory = request_factory
        self._operation = operation
        self._target_system = target_system
        self._redact_parameters = redact_parameters
        self._on_deny = on_deny
        # Receipt log surfaced for the application to drain after each
        # agent step. The wrapper does not assume the framework knows
        # about Provenex receipts; the caller is responsible for reading
        # and persisting these.
        self._receipts: List[Any] = []

    # ---- LangChain-facing surface ---- #

    @property
    def name(self) -> str:
        return self._base_tool.name

    @property
    def description(self) -> Optional[str]:
        return getattr(self._base_tool, "description", None)

    @property
    def receipts(self) -> List[Any]:
        """The receipts emitted by this wrapper since construction.

        Returned as the list itself (not a copy) so the caller can clear
        it (e.g. ``wrapper.receipts.clear()``) between agent steps.
        Wrappers used in long-running agents should drain this on a
        regular cadence.
        """
        return self._receipts

    def invoke(
        self,
        input: Any,
        *,
        trajectory: Optional[TrajectoryContext] = None,
    ) -> Any:
        """Admission-check ``input`` and, on allow, invoke the underlying tool.

        ``input`` follows LangChain's tool-input convention: typically a
        dict carrying the parameters plus an embedded caller / context
        payload. The :attr:`request_factory` extracts the
        RequestContext; everything else (modulo recognised override
        keys) becomes the tool parameters.

        Recognised override keys (consumed by the wrapper, not passed
        to the base tool):

            * ``__operation__`` — overrides :attr:`operation`
            * ``__target_system__`` — overrides :attr:`target_system`
            * ``__invocation_id__`` — caller-chosen correlation ID

        Returns the underlying tool's result on allow. On deny: invokes
        :attr:`on_deny` if set; otherwise raises
        :class:`provenex.ToolCallDenied`.
        """
        from ..admission import ToolCallDenied  # local to avoid cycles

        params, operation, target_system, invocation_id = self._split_input(input)

        request = self._request_factory(input)
        tool = ToolCallContext(
            name=self.name,
            operation=operation,
            parameters=params,
            target_system=target_system,
            invocation_id=invocation_id,
        )

        result = admission_check(
            tool=tool,
            request=request,
            policy=self._policy,
            signer=self._signer,
            trajectory=trajectory,
            redact_parameters=self._redact_parameters,
        )
        self._receipts.append(result.receipt)

        if not result.allowed:
            if self._on_deny is not None:
                return self._on_deny(result)
            raise ToolCallDenied(result)

        # Forward to the underlying tool. Prefer .invoke (post-0.2
        # Runnable protocol); fall back to .run (legacy BaseTool).
        forward = (
            getattr(self._base_tool, "invoke", None)
            or getattr(self._base_tool, "run")
        )
        # We pass the *original* input verbatim — the base tool may
        # expect override keys it tolerates (or it may not see them at
        # all because they got popped). Conservative: pass cleaned dict.
        cleaned = self._clean_input(input)
        return forward(cleaned)

    # ---- helpers ---- #

    def _split_input(
        self, input: Any
    ) -> "tuple[Dict[str, Any], str, Optional[str], Optional[str]]":
        if isinstance(input, dict):
            params = {
                k: v
                for k, v in input.items()
                if k
                not in {
                    "__operation__",
                    "__target_system__",
                    "__invocation_id__",
                }
            }
            return (
                params,
                input.get("__operation__", self._operation),
                input.get("__target_system__", self._target_system),
                input.get("__invocation_id__"),
            )
        # Non-dict input: pass as a single "input" parameter so the
        # admission record has something to hash. LangChain tools
        # frequently take a single string.
        return (
            {"input": input},
            self._operation,
            self._target_system,
            None,
        )

    @staticmethod
    def _clean_input(input: Any) -> Any:
        if not isinstance(input, dict):
            return input
        return {
            k: v
            for k, v in input.items()
            if k
            not in {
                "__operation__",
                "__target_system__",
                "__invocation_id__",
            }
        }


__all__ = ["ProvenexToolWrapper", "RequestFactory"]
