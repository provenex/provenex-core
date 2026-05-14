"""The per-call view the tool-call evaluator sees.

This is the Phase 2 sibling of :class:`provenex.policy.evaluator.ChunkContext`.
Both feed the same :class:`PolicyDecision` shape; the discriminator is the
context type, not the decision type.

The fields are deliberately the minimum needed to express the admission
question "can this caller call this tool with these parameters against
this target system." Larger fields (chunk metadata dicts, embeddings,
response bodies) are explicitly out of scope — Provenex is decision and
proof, not execution, and storing or evaluating against response bodies
would put it on the data path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class ToolCallContext:
    """One tool-call attempt as seen by the admission evaluator.

    Field names mirror DSL paths exactly — Phase 1's convention. A rule
    that writes ``tool.name`` reads :attr:`name`; a rule that writes
    ``tool.parameters.q`` walks :attr:`parameters` then indexes ``"q"``.

    Attributes:
        name: Stable tool identifier. For MCP, the convention is the
            server name plus tool path (``"jira/issues"``). For
            framework wrappers, the tool's caller-chosen ``name``
            attribute. Evaluated against the DSL path ``tool.name``.
        operation: The specific operation on the tool (``"create_issue"``,
            ``"query"``, ``"invoke"``). For tools with a single operation,
            callers may pass a constant such as ``"invoke"``. Evaluated
            against ``tool.operation``.
        parameters: Caller-supplied parameter dict. Evaluator reads dotted
            paths ``tool.parameters.<key>`` against this dict. Values may
            be redacted on the emitted receipt (operator opt-in); the
            ``parameters_hash`` always covers the verbatim parameters.
        target_system: Optional logical target. For ``web_search``, the
            search-provider name (``"google_custom_search"``). For
            ``jira``, the workspace/site (``"acme.atlassian.net"``). Used
            by rules that gate on which downstream system the call would
            reach. Evaluated against ``tool.target_system``.
        invocation_id: Caller-chosen opaque ID for cross-referencing with
            the caller's own logs. Not load-bearing; not part of the
            decision input. Convenience field for downstream correlation.

    The class is frozen — once constructed for an admission call, the
    context must not change. Mutating after the decision would mean the
    receipt records a different input than the evaluator saw.
    """

    name: str
    operation: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    target_system: Optional[str] = None
    invocation_id: Optional[str] = None
