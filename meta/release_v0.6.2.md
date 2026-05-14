# Release notes — v0.6.2

**Headline.** First-class Phase 2 admission support for CrewAI sessions. The CrewAI session class now wraps tool callables with admission semantics — denials raise before the tool fires — and the trajectory threads retrieval and tool-call receipts together for one end-to-end audit pass.

## What's new since 0.6.1

- **`ProvenexCrewSession.wrap_tool_admission(tool, name=..., request_factory=...)`.** Phase 2 parallel of the existing `wrap_tool`. Builds a `ToolCallContext` from the call args/kwargs, resolves a `RequestContext` via the supplied factory, runs `admission_check(...)`, raises `ToolCallDenied` on deny (or calls a supplied `on_deny` callback), and invokes the underlying tool with the original arguments on allow. Reserved per-call overrides (`__operation__`, `__target_system__`, `__invocation_id__`) are stripped before forwarding to the tool. Custom `params_extractor` for callers who want explicit parameter shaping.
- **`ProvenexCrewSession.admission_check(tool, request, ...)`.** Lower-level session-aware admission. Threads the session's trajectory cursor, advances it on the result, and appends the receipt to `session.receipts`. Same redaction / step_kind / agent_id options as the framework-agnostic `provenex.admission_check`.
- **Unified `Policy` on session construction.** `ProvenexCrewSession(..., policy=...)` now accepts a unified `Policy` carrying `tool_call_control` (alongside the existing `VerificationPolicy` path for Phase 1 callers). Existing test suites that pass a bare `VerificationPolicy` continue to work — `coerce_policy` wraps the legacy form.
- **`session.policy`** property — read-only access to the unified `Policy` in effect for the session.

## Compatibility

- **Backward compatible.** Phase 1 CrewAI integration tests pass under 0.6.2 with no modifications. Constructors with a bare `VerificationPolicy` continue to work via internal coercion.
- **Trajectory composition unchanged.** A session that intermixes `verify_chunks(...)` and `admission_check(...)` produces one trajectory DAG, validates end-to-end via `audit_trajectory_dag` (and the CLI's `provenex audit --trajectory`), and emits receipts that are distinguishable by `step_kind` (`retrieval` vs `tool_call`).
- **Receipt schema unchanged.** Still 2.2.0. No new fields; only a new integration surface.

## Example

```python
from provenex import HmacSha256Signer, Policy, RequestContext, ToolCallDenied
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.crewai import ProvenexCrewSession

session = ProvenexCrewSession(
    index=SQLiteProvenanceIndex("provenance.db"),
    signer=HmacSha256Signer(),
    policy=Policy.from_yaml("agent_policy.yaml"),
    agent_id="incident_agent",
)

def make_request(*args, **kwargs):
    # Identity comes from the host application, NOT from Provenex.
    return RequestContext(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )

wrapped_web_search = session.wrap_tool_admission(
    web_search_tool,
    name="web_search",
    operation="query",
    target_system="google_custom_search",
    request_factory=make_request,
)

# Pass the wrapped tool to your CrewAI Agent. Each invocation:
#   1. Runs admission_check (signed receipt threaded into session)
#   2. Raises ToolCallDenied if policy denies (caller never executes)
#   3. Invokes web_search_tool with the original args on allow
agent.tools = [wrapped_web_search]
```

After the crew runs, the full retrieval + tool-call DAG is in `session.receipts` and audits via `provenex audit --trajectory ./receipts/`.

## Install

```bash
pip install provenex-core==0.6.2
pip install "provenex-core[policy]==0.6.2"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[crewai]==0.6.2"        # CrewAI session + admission
pip install "provenex-core[ed25519]==0.6.2"       # asymmetric receipt signing
```
