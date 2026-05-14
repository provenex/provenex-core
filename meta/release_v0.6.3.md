# Release notes — v0.6.3

**Headline.** LangGraph gets a first-class Phase 2 admission node; the trajectory audit CLI grows an aggregate summary block; the quickstart guide now covers tool-call admission alongside retrieval.

## What's new since 0.6.2

- **`provenex.integrations.langgraph.provenex_admission_node(...)`.** Phase 2 sibling of `provenex_retrieval_node`. A factory that builds a LangGraph-compatible node which:
    - Reads the pending tool's parameters from state (default key `tool_parameters`; configurable via `state_keys` or `params_extractor`).
    - Resolves a `RequestContext` via a caller-supplied `request_factory(state)` (Provenex never owns identity — the host application supplies caller / jurisdiction / purpose / timestamp).
    - Runs `admission_check(...)`, emits a signed trajectory-linked receipt regardless of outcome.
    - Writes `tool_admitted` / `tool_decision` / `tool_rules_fired` into state so a conditional edge can route execution to the actual tool-call node or to a denial handler. **The admission node never invokes the underlying tool** — that's the load-bearing "decision and proof, not execution" line in graph-node form.
    - Reserved per-step overrides (`__operation__`, `__target_system__`, `__invocation_id__`) on state, mirroring the LangChain wrapper.

- **`provenex audit --trajectory` aggregate summary.** Both human-readable and `--json` output now carry a top-level summary block summing per-receipt counts across the entire trajectory:
    - `total_chunks` plus per-outcome counts (`verified` / `stale` / `unauthorized` / `unverified` / `tampered`).
    - `total_actions` / `actions_allowed` / `actions_denied` — emitted only when the trajectory contains tool-call receipts.
    - `per_step_kind` — receipt count broken down by trajectory step kind (e.g. `{"retrieval": 2, "tool_call": 1}`).
    - `overall_status` — aggregate `PASS` / `PARTIAL` / `FAIL` over the whole trajectory.
  Human-readable output adds a one-line headline so an operator gets the shape of the trajectory without paging through per-receipt detail.

- **`docs/quickstart.md` Path G — tool-call admission.** Walks through the framework-agnostic `admission_check`, the LangChain wrapper, the CrewAI session, the new LangGraph admission node, and the MCP middleware decorator. All point at the same receipt shape and the same demo script.

## Compatibility

- **Backward compatible.** All Phase 1 LangGraph tests pass under 0.6.3 with no modifications. The retrieval-node factory and state helpers are unchanged on the wire.
- **CLI output.** The `audit --trajectory --json` schema gains an optional `summary` key alongside the existing keys; consumers that ignored unknown fields continue to work. Human-readable output adds a few headline lines but the per-receipt detail format is unchanged.
- **No receipt schema change.** Still 2.2.0.

## Example

```python
from provenex import HmacSha256Signer, Policy, RequestContext
from provenex.integrations.langgraph import (
    provenex_admission_node, provenex_retrieval_node, start_trajectory_state,
)

admit_jira = provenex_admission_node(
    name="jira",
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    operation="create_issue",
    target_system="acme.atlassian.net",
    request_factory=lambda state: RequestContext(
        caller=state["caller"], jurisdiction=state["jurisdiction"],
        purpose=state["purpose"], timestamp=state["timestamp"],
    ),
)

# In a LangGraph state machine:
# graph.add_node("admit_jira", admit_jira)
# graph.add_node("execute_jira", _your_actual_jira_node)
# graph.add_conditional_edges(
#     "admit_jira",
#     lambda s: "execute_jira" if s["tool_admitted"] else "denied_handler",
# )
```

After the graph runs, `provenex audit --trajectory ./receipts/` shows the aggregate at a glance:

```
Trajectory: trj_a3f1c0d2...
Receipts:   4
Steps:      2 retrieval, 2 tool_call
Chunks:     6 (5 verified)
Actions:    2 (1 allowed, 1 denied)
```

## Install

```bash
pip install provenex-core==0.6.3
pip install "provenex-core[policy]==0.6.3"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[langgraph]==0.6.3"     # LangGraph nodes (retrieval + admission)
pip install "provenex-core[crewai]==0.6.3"        # CrewAI session + admission
pip install "provenex-core[langchain]==0.6.3"     # LangChain retriever + admission wrapper
pip install "provenex-core[ed25519]==0.6.3"       # asymmetric receipt signing
```
