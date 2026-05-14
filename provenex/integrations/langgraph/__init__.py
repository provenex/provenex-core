"""LangGraph integration: trajectory-aware retrieval nodes.

LangGraph orchestrates stateful, possibly branching agent flows as a DAG of
nodes. This integration supplies a retrieval-node factory that emits
trajectory-linked Provenex receipts as the flow runs, plus state helpers
that thread the trajectory context through the graph's state object.

The integration does NOT import ``langgraph`` itself — LangGraph nodes are
just callables ``(state) -> state_delta`` and our integration only needs
that contract. Install ``provenex-core[langgraph]`` for the discovery
hint, but the runtime requirement is just LangGraph's node-shape (any
callable that takes and returns a dict-like state).
"""

from .node import (
    provenex_admission_node,
    provenex_retrieval_node,
    record_step_receipt,
    start_trajectory_state,
)

__all__ = [
    "provenex_admission_node",
    "provenex_retrieval_node",
    "start_trajectory_state",
    "record_step_receipt",
]
