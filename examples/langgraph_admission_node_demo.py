"""LangGraph admission-node demo (0.6.9+).

Run with:

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/langgraph_admission_node_demo.py

What it shows, in order:

    1. The factory pattern. ``provenex_admission_node(...)`` produces
       a callable that fits LangGraph's node signature ``(state) →
       state_delta``. Drop it into any state graph.

    2. The conditional-edge pattern. The admission node writes
       ``tool_admitted`` / ``tool_decision`` / ``tool_rules_fired``
       into state. A conditional edge reads those keys and routes
       to either an ``execute_jira_node`` (on allow) or a
       ``denied_handler_node`` (on deny). **The admission node
       NEVER invokes the underlying tool.** That's the load-bearing
       "decision and proof, not execution" line, in graph form:
       routing the actual call is the graph's responsibility.

    3. Two end-to-end scenarios:
         - engineer creates a Jira issue → admit → execute → done
         - viewer attempts to create a Jira issue → admit → deny → handler

    4. The trajectory threads through state automatically. After the
       graph runs, ``provenex audit --trajectory`` validates the
       whole flow.

Pure stdlib. We simulate a minimal LangGraph state-machine loop —
the Provenex integration imports nothing from langgraph by design
(it produces plain callables), so the demo runs without the
optional ``[langgraph]`` extra.

In a real LangGraph deployment, the wiring is::

    from langgraph.graph import StateGraph

    graph = StateGraph(MyState)
    graph.add_node("admit_jira", provenex_admission_node(name="jira", ...))
    graph.add_node("execute_jira", _your_jira_node)
    graph.add_node("denied_handler", _denied_handler_node)
    graph.add_conditional_edges(
        "admit_jira",
        lambda s: "execute_jira" if s["tool_admitted"] else "denied_handler",
    )
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
)
from provenex.integrations.langgraph import (
    provenex_admission_node,
    start_trajectory_state,
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


POLICY_YAML = """
version: 1
policy_id: langgraph-demo-v1

tool_call_control:
  rules:
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


# ----- A minimal in-process state-machine runner --- #
#
# In a real deployment you'd use ``langgraph.graph.StateGraph`` here.
# For demo purposes we run a tiny loop that conditionally routes
# between nodes based on a predicate callback. The behaviour is
# semantically identical to LangGraph's conditional-edge model.

NodeFn = Callable[[Mapping[str, Any]], Dict[str, Any]]


def run_graph(
    initial_state: Dict[str, Any],
    nodes: Dict[str, NodeFn],
    edges: Dict[str, Any],     # node_name -> next_node_name OR a callable predicate -> name
    entry: str,
    terminal: str,
) -> Dict[str, Any]:
    """Run a tiny state graph until the terminal node.

    ``edges`` values:
      - a string ``"next_node"`` → unconditional transition
      - a callable ``state → str`` → conditional edge (returns the next node name)
    """
    state = dict(initial_state)
    current = entry
    while current != terminal:
        delta = nodes[current](state)
        state.update(delta)
        edge = edges[current]
        current = edge(state) if callable(edge) else edge
    state.update(nodes[terminal](state))
    return state


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

    # --- Define the application's own nodes (NOT Provenex's) --- #
    # These are the nodes a LangGraph application author writes. They
    # do NOT know about Provenex. The application's responsibility is
    # to (a) shape state for the admission node, (b) route based on
    # the admission outcome, and (c) actually execute the tool on
    # the allow branch.

    def shape_request_node(state: Mapping[str, Any]) -> Dict[str, Any]:
        """Stage the tool parameters and the operation onto state.

        In real apps this is where the planner / LLM emits the
        next-tool-call structure.
        """
        return {
            "tool_parameters": state["pending_tool_args"],
            "__operation__": state["pending_tool_op"],
            "__target_system__": "acme.atlassian.net",
        }

    def execute_jira_node(state: Mapping[str, Any]) -> Dict[str, Any]:
        """Pretend to call Jira. The host application's credentials,
        the host application's response shape. Provenex was never
        on this code path.
        """
        action = (
            state["receipts"][-1].to_dict()["actions"][0]
            if state.get("receipts")
            else {}
        )
        return {
            "execution_result": (
                f"(simulated) jira.{action.get('operation','?')} "
                f"on {action.get('target_system','?')} → ok"
            )
        }

    def denied_handler_node(state: Mapping[str, Any]) -> Dict[str, Any]:
        """On deny, emit a structured error and continue.

        Real apps might page on-call, write to the audit log, etc.
        Note: the admission *receipt* is in ``state["receipts"]``
        regardless of the deny — denies are auditable.
        """
        rules = state.get("tool_rules_fired", [])
        return {
            "execution_result": (
                f"DENIED by policy ({','.join(rules)}). "
                f"Receipt: {state['receipts'][-1].receipt_id}"
            )
        }

    def end_node(state: Mapping[str, Any]) -> Dict[str, Any]:
        # No-op terminal.
        return {}

    # --- The Provenex admission node --- #
    # One factory call. Plugs into the graph like any other node.

    admit_jira = provenex_admission_node(
        name="jira",
        policy=policy,
        signer=signer,
        # Default operation; per-step override comes from state.
        operation="invoke",
        request_factory=lambda state: RequestContext(
            caller=state["caller"],
            jurisdiction=state["jurisdiction"],
            purpose=state["purpose"],
            timestamp=state["timestamp"],
            session_id=state.get("session_id"),
        ),
    )

    # --- Wire the graph --- #
    nodes = {
        "shape_request": shape_request_node,
        "admit_jira": admit_jira,
        "execute_jira": execute_jira_node,
        "denied_handler": denied_handler_node,
        "END": end_node,
    }
    edges = {
        "shape_request": "admit_jira",
        # The conditional edge — this is the load-bearing pattern:
        # Provenex never invokes the tool; the graph routes on the
        # boolean ``tool_admitted`` flag the admission node wrote
        # into state.
        "admit_jira": lambda s: "execute_jira" if s["tool_admitted"] else "denied_handler",
        "execute_jira": "END",
        "denied_handler": "END",
    }

    banner("1. Graph topology")
    print(f"  {DIM}shape_request → admit_jira{RESET}")
    print(
        f"  {DIM}admit_jira ─ (admitted) ─→ execute_jira → END{RESET}"
    )
    print(
        f"  {DIM}admit_jira ─ (denied)   ─→ denied_handler → END{RESET}"
    )
    print(
        f"  {YELLOW}NB:{RESET} {DIM}admit_jira NEVER invokes Jira directly. "
        f"It writes a decision into state{RESET}"
    )
    print(
        f"     {DIM}and the graph routes on the boolean. Decision and "
        f"proof, not execution.{RESET}"
    )

    # --- Scenario 1: engineer creates a Jira issue → admit → execute --- #
    banner("2. Scenario 1 — engineer → jira.create_issue (expect: ALLOW)")

    state1 = {
        # Application data
        "caller": {"id": "u_42", "role": "engineer"},
        "jurisdiction": "US",
        "purpose": "incident_response",
        "timestamp": "2026-05-15T11:30:00Z",
        "session_id": "incident-2026-05-15-001",
        # Pending tool-call to admit
        "pending_tool_op": "create_issue",
        "pending_tool_args": {"project": "INC", "summary": "auth-gateway 5xx"},
    }
    # Seed the trajectory state (one-time, at flow start).
    state1.update(start_trajectory_state(agent_id="incident_agent"))

    final1 = run_graph(state1, nodes, edges, entry="shape_request", terminal="END")
    summary("Admitted?", f"{GREEN if final1['tool_admitted'] else RED}{final1['tool_admitted']}{RESET}")
    summary("Decision", final1["tool_decision"])
    summary("Rules fired", ", ".join(final1["tool_rules_fired"]) or "(none)")
    summary("Execution result", final1["execution_result"])
    summary("Receipts collected", str(len(final1["receipts"])))
    summary("Receipt id", final1["receipts"][-1].receipt_id)

    # --- Scenario 2: viewer attempts a Jira write → admit → deny --- #
    banner("3. Scenario 2 — viewer → jira.create_issue (expect: DENY)")

    state2 = {
        "caller": {"id": "u_99", "role": "viewer"},
        "jurisdiction": "US",
        "purpose": "incident_response",
        "timestamp": "2026-05-15T11:30:00Z",
        "session_id": "incident-2026-05-15-001",
        "pending_tool_op": "create_issue",
        "pending_tool_args": {"project": "INC", "summary": "viewer attempt"},
    }
    state2.update(start_trajectory_state(agent_id="incident_agent"))

    final2 = run_graph(state2, nodes, edges, entry="shape_request", terminal="END")
    summary("Admitted?", f"{GREEN if final2['tool_admitted'] else RED}{final2['tool_admitted']}{RESET}")
    summary("Decision", final2["tool_decision"])
    summary("Rules fired", ", ".join(final2["tool_rules_fired"]) or "(none)")
    summary("Execution result", final2["execution_result"])
    summary("Receipts collected", str(len(final2["receipts"])))
    summary(
        "Note",
        f"{DIM}Receipt was still recorded — denies are auditable.{RESET}",
    )

    # --- Audit both trajectories --- #
    banner("4. Trajectory audit — provenex audit --trajectory")

    with tempfile.TemporaryDirectory() as tmp:
        receipts_dir = Path(tmp) / "receipts"
        receipts_dir.mkdir()
        # Write all the receipts from both scenarios.
        all_receipts = final1["receipts"] + final2["receipts"]
        for i, r in enumerate(all_receipts):
            (receipts_dir / f"r{i:02d}.json").write_text(
                r.to_json(), encoding="utf-8"
            )

        # Validate per-trajectory: each scenario is its own DAG.
        from provenex import audit_trajectory_dag
        import json as _json

        for scenario_name, scenario_receipts in [
            ("Scenario 1 (engineer)", final1["receipts"]),
            ("Scenario 2 (viewer)", final2["receipts"]),
        ]:
            audit = audit_trajectory_dag(
                [r.to_dict() for r in scenario_receipts]
            )
            colour = GREEN if audit.ok else RED
            print(
                f"  {scenario_name}: "
                f"{colour}{'PASS' if audit.ok else 'FAIL'}{RESET}  "
                f"{DIM}({audit.receipt_count} receipts, "
                f"trajectory_id={audit.trajectory_id}){RESET}"
            )

    # --- Pitch --- #
    banner("5. The shape of a LangGraph Provenex integration")
    print(
        f"  {DIM}One factory call (``provenex_admission_node(...)``) produces"
        f"{RESET}"
    )
    print(
        f"  {DIM}a node. The graph's conditional edge routes on the boolean"
        f"{RESET}"
    )
    print(
        f"  {DIM}flag the admission node wrote into state. The actual tool"
        f"{RESET}"
    )
    print(
        f"  {DIM}invocation lives in a separate node the graph routes to on"
        f"{RESET}"
    )
    print(
        f"  {DIM}allow — never inside Provenex. Two graph patterns, one"
        f"{RESET}"
    )
    print(
        f"  {DIM}signed audit trail, denies auditable, no token holding.{RESET}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
