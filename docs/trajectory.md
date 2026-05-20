# Agentic trajectories: deep dive

A Provenex trajectory is a verifiable DAG of per-step receipts. Every step an agent takes (retrieval, tool call, memory read, memory write, model inference) emits its own signed receipt; the receipts link via `trajectory.parent_step_ids` into a single audit object. One CLI command (`provenex audit --trajectory <dir>`) validates the whole run.

This doc is for the engineer building the agent and the auditor reading the resulting receipts. The schema reference for the trajectory block is in [receipt_format.md § trajectory](receipt_format.md#trajectory); this doc covers the modelling and the worked example.

## The DAG model

Every receipt produced inside a trajectory carries:

```json
{
  "trajectory": {
    "trajectory_id": "trj_a3f1c0d2e419bf48a8b7d54f9c01ea73",
    "step_index": 2,
    "parent_step_ids": ["prx_c5d8e1f203a497bd5a6e0c2b48f7d519"],
    "step_kind": "tool_call",
    "agent_id": "incident_agent",
    "trajectory_started_at": "2026-05-13T10:00:00.000Z",
    "session_id": "session-2026-001"
  }
}
```

| Field | Meaning |
| --- | --- |
| `trajectory_id` | Globally unique. Prefix `trj_` plus 32 hex characters. Shared by every receipt in the trajectory. |
| `step_index` | 0-based ordinal within the trajectory. In DAG shapes (parallel branches), sibling steps may share an index; uniqueness is along the parent chain. |
| `parent_step_ids` | Array of `receipt_id` values for the parent steps. Empty for the root step. **An array**, not a scalar, so DAG shapes (LangGraph branches, CrewAI parallel agents) round-trip. |
| `step_kind` | One of `retrieval`, `tool_call`, `memory_read`, `memory_write`, `model_inference`, `compilation`. Free-form for forward compatibility. |
| `agent_id` | Caller-chosen opaque identifier for the emitting agent. Useful in multi-agent flows. Do not encode PII. |
| `trajectory_started_at` | ISO-8601 UTC with millisecond precision. Same value on every receipt in the trajectory. |
| `session_id` | Optional. Caller-chosen opaque string for multi-trajectory correlation (a chat session, an incident-response engagement, a multi-day investigation). |

The whole trajectory block is covered by the receipt signature. Tampering with any field invalidates the signature.

## The five step kinds

Each kind uses the same signed-receipt shape; the discriminator is the `trajectory.step_kind` field. The differences are in which other fields are present on the receipt.

### `retrieval`

Produced by `verify_chunks(...)` or any framework retrieval wrapper. Carries `sources[]` with verification outcomes; carries `policy.access_control` if a chunk evaluator is configured. No `actions[]`.

```python
result = verify_chunks(chunks=..., index=index, signer=signer,
                       request_context=request, trajectory=trj)
# result.receipt.trajectory.step_kind == "retrieval"
```

The receipt records what came back from retrieval and which chunks survived the verification gate plus the access-control gate. See [how_it_works.md § Verification](how_it_works.md#3-verification).

### `tool_call`

Produced by `admission_check(...)` or any framework admission wrapper. Carries `actions[]` with the tool-call records; carries `policy.tool_call_control` with the per-action decisions. No `sources[]` for pure tool-call receipts.

```python
result = admission_check(tool=ToolCallContext(name="jira", operation="create_issue", ...),
                         request=request, policy=policy, signer=signer,
                         trajectory=trj)
# result.receipt.trajectory.step_kind == "tool_call"
```

The receipt records the admission decision. The actual tool call is made by your code on the allow branch; Provenex returns a decision, not an execution. See [policy.md § Tool-call admission](policy.md#tool_call_control-subsection---native-yaml-dsl).

### `memory_read`

Produced by `verify_memory(...)`. Same shape as a retrieval receipt; the `sources[].content_source` field reads `memory_store` so an auditor distinguishes a corpus retrieval from a memory read.

```python
result = verify_memory(memory_chunks=[...], index=memory_index, signer=signer,
                       request_context=request, trajectory=trj)
# result.receipt.trajectory.step_kind == "memory_read"
# result.receipt.sources[i].content_source == "memory_store"
```

UNVERIFIED on a `memory_read` reads as "memory miss" to a downstream detector, distinct from "corpus miss."

### `memory_write`

Produced by `admit_memory_write(memory_key, value, ...)`. Admission-shaped: `actions[]` with one entry where `name="memory.write"` and `operation=<memory_key>`. The verbatim value is redacted by default (`redact_value=True`); `value_hash` is always present.

```python
result = admit_memory_write(memory_key="user_profile", value={"theme": "dark"},
                            request=request, store_id="crewai_memory", signer=signer,
                            trajectory=trj)
# result.receipt.trajectory.step_kind == "memory_write"
# result.receipt.actions[0].name == "memory.write"
# result.receipt.actions[0].operation == "user_profile"
```

Policy rules gate memory writes by key via `when: { tool.name: memory.write, tool.operation: <key> }`. See [cookbook.md § Gate memory writes by key](cookbook.md#14-gate-memory-writes-by-key).

### `model_inference`

Produced by `admit_model_inference(model_name, prompt, ...)`. Admission-shaped: `actions[]` with one entry where `name=<model_name>`, `operation=<verb>` (`complete`, `stream`, `embed`, `chat`), `target_system=<provider>`. Verbatim prompt is redacted by default; `prompt_hash` is always present.

```python
result = admit_model_inference(model_name="claude-opus-4-7",
                               prompt=[{"role": "user", "content": "..."}],
                               request=request, target_provider="anthropic",
                               extra_parameters={"max_tokens": 4000},
                               signer=signer, trajectory=trj)
# result.receipt.trajectory.step_kind == "model_inference"
# result.receipt.actions[0].name == "claude-opus-4-7"
# result.receipt.actions[0].target_system == "anthropic"
```

Detectors group by `caller_hash + actions[0].name` for per-model usage baselines.

### `compilation`

Reserved for a future release covering compiled-artifact provenance. Currently produces no receipts; the value is in the recognised-kinds list for forward compatibility.

## Building a trajectory in code

The framework-agnostic API:

```python
from provenex import start_trajectory

trj = start_trajectory(
    agent_id="incident_agent",
    session_id="incident-2026-001",
)

r0 = verify_chunks(..., trajectory=trj)
r1 = admission_check(..., trajectory=r0.next_trajectory)
r2 = verify_chunks(..., trajectory=r1.next_trajectory)
```

Each `result.next_trajectory` advances the cursor so the next call's receipt records the previous receipt as its parent. The chain is sequential by default. For DAG shapes (parallel branches), construct the cursor explicitly:

```python
from provenex.core.trajectory import TrajectoryContext

branch_a_cursor = TrajectoryContext(
    trajectory_id=trj.trajectory_id, step_index=1,
    parent_step_ids=[r0.receipt.receipt_id], agent_id="research_branch_a",
    trajectory_started_at=trj.trajectory_started_at,
)
branch_b_cursor = TrajectoryContext(
    trajectory_id=trj.trajectory_id, step_index=1,
    parent_step_ids=[r0.receipt.receipt_id], agent_id="research_branch_b",
    trajectory_started_at=trj.trajectory_started_at,
)

r1a = verify_chunks(..., trajectory=branch_a_cursor)
r1b = verify_chunks(..., trajectory=branch_b_cursor)

# Both branches feed into one merge step:
merge_cursor = TrajectoryContext(
    trajectory_id=trj.trajectory_id, step_index=2,
    parent_step_ids=[r1a.receipt.receipt_id, r1b.receipt.receipt_id],
    agent_id="merge", trajectory_started_at=trj.trajectory_started_at,
)
r2 = verify_chunks(..., trajectory=merge_cursor)
```

The `parent_step_ids` array on `r2` carries both branches; the audit DAG check sees a fan-in and validates it.

## Multi-agent and multi-session linking

`agent_id` and `session_id` are independent correlation axes.

**Multi-agent.** A trajectory with multiple agents (a research agent fetches sources, a writer agent drafts an answer, a reviewer agent checks the draft) uses one `trajectory_id` across all agents. Each receipt carries the agent that emitted it under `trajectory.agent_id`. A detector groups by `(trajectory_id, agent_id)` to see per-agent step distributions.

**Multi-session.** A `session_id` correlates receipts *across* trajectories. A chat conversation with multiple turns is one session; each turn is its own trajectory. A detector groups by `session_id` to see per-session shape:

```python
import json
from collections import Counter
from pathlib import Path

per_session = Counter()
for path in Path("./receipts").glob("*.json"):
    r = json.loads(path.read_text())
    sess = r.get("trajectory", {}).get("session_id")
    kind = r.get("trajectory", {}).get("step_kind")
    if sess:
        per_session[(sess, kind)] += 1
```

`session_id` is not a policy input; it does not appear under `request.*` in any rule. It is a receipt-side correlation tag. See [policy.md § Receipt block reference](policy.md#receipt-block-reference) for the design rationale.

## Auditing a trajectory

```bash
provenex audit --trajectory ./receipts/ --public-key audit.pub
```

The trajectory audit runs three layers:

1. **Per-receipt audit.** Each receipt's signature is verified; each per-source inclusion proof is verified against the receipt's `transparency_log.tree_root`.
2. **DAG checks.** Every receipt shares the same `trajectory_id`; the DAG formed by `parent_step_ids` is acyclic; every referenced parent resolves to a receipt in the set; at least one root step exists.
3. **Aggregate summary.** Total chunks by outcome, total actions by decision, per-step-kind breakdown, aggregate `PASS` / `PARTIAL` / `FAIL`.

The CLI's human-readable output puts the headline at the top, then per-receipt detail, then the DAG checks, then the aggregate. `--json` produces a machine-readable equivalent with the same keys.

## Worked example: a five-step agentic flow

An incident-response agent: read corpus, read memory, call a model, write to memory, call an external tool. Five receipts under one trajectory.

```python
from provenex import (start_trajectory, RequestContext,
                      verify_chunks, verify_memory, admit_memory_write,
                      admit_model_inference, admission_check,
                      ToolCallContext, HmacSha256Signer)

trj = start_trajectory(agent_id="incident_agent", session_id="incident-001")
signer = HmacSha256Signer()
request = RequestContext(
    caller={"id": "u_42", "role": "engineer"}, jurisdiction="US",
    purpose="incident_response", timestamp="2026-05-14T11:30:00Z",
    session_id="incident-001",
)

# Step 0: corpus retrieval
r0 = verify_chunks(
    chunks=corpus_chunks, index=corpus_index, signer=signer,
    request_context=request, request_text="incident runbook",
    trajectory=trj,
)

# Step 1: memory read
r1 = verify_memory(
    memory_chunks=["last user message: where is the runbook?"],
    index=memory_index, signer=signer,
    request_context=request, trajectory=r0.next_trajectory,
)

# Step 2: model inference (summarise the runbook + memory)
r2 = admit_model_inference(
    model_name="claude-opus-4-7", prompt=[...],
    request=request, target_provider="anthropic",
    signer=signer, trajectory=r1.next_trajectory,
)

# Step 3: memory write (persist the summary)
r3 = admit_memory_write(
    memory_key="incident_summary", value={"summary": "..."},
    request=request, store_id="crewai_memory",
    signer=signer, trajectory=r2.next_trajectory,
)

# Step 4: tool call (open a Jira ticket)
r4 = admission_check(
    tool=ToolCallContext(name="jira", operation="create_issue",
                         parameters={"project": "INC", "summary": "..."},
                         target_system="acme.atlassian.net"),
    request=request, policy=policy, signer=signer,
    trajectory=r3.next_trajectory,
)
```

The resulting DAG:

```
r0 (retrieval)
 └─> r1 (memory_read)
      └─> r2 (model_inference)
           └─> r3 (memory_write)
                └─> r4 (tool_call)
```

Save each receipt to a directory:

```python
import json
for r in (r0, r1, r2, r3, r4):
    with open(f"./run/{r.receipt.receipt_id}.json", "w") as f:
        f.write(r.receipt.to_json())
```

Audit the whole run:

```bash
provenex audit --trajectory ./run/ --public-key audit.pub
```

Expected output (illustrative):

```
Trajectory: trj_a3f1c0d2...
Receipts:   5
Steps:      1 retrieval, 1 memory_read, 1 model_inference, 1 memory_write, 1 tool_call
Chunks:     6 (6 verified)
Actions:    3 (3 allowed, 0 denied)

  [OK] step #0   prx_...   (retrieval)
  [OK] step #1   prx_...   (memory_read)
  [OK] step #2   prx_...   (model_inference)
  [OK] step #3   prx_...   (memory_write)
  [OK] step #4   prx_...   (tool_call)

  Trajectory DAG checks:
    [OK] shared_trajectory_id: all 5 receipts share trj_a3f1c0d2...
    [OK] acyclic: DAG is acyclic
    [OK] no_dangling_parents: every parent_step_id resolves
    [OK] has_root: 1 root step (step #0)

  Overall: PASS
```

The same audit produces a `--json` blob the operator's CI gate consumes.

## Branching trajectories

A LangGraph flow with a conditional edge produces a branching trajectory. The admission node's decision routes execution to the execute-tool node or the denied-handler node. Both branches emit their own receipts:

```
r0 (retrieval)
 └─> r1 (admission node, tool_call)
      ├─> r2_a (execute_jira)        // allow branch
      └─> r2_b (denied_handler)       // deny branch
```

Only one of `r2_a` and `r2_b` exists per run (the conditional edge selects one). The trajectory DAG always has one parent for `r2_a` or `r2_b` (`r1`), so the DAG audit validates either branch. See [examples/langgraph_admission_node_demo.py](../examples/langgraph_admission_node_demo.py) for the runnable version.

## Multi-agent fan-out

A CrewAI flow with multiple agents working in parallel produces a fan-out trajectory:

```
r0 (root retrieval)
 ├─> r1_a (agent A's tool call)
 ├─> r1_b (agent B's tool call)
 └─> r1_c (agent C's tool call)
      └─> r2 (merge / report)        // parents = [r1_a, r1_b, r1_c]
```

The merge step's `parent_step_ids` carries all three branches. The audit's "no_dangling_parents" check sees the fan-in and validates it.

## Read next

- [receipt_format.md § trajectory](receipt_format.md#trajectory): the wire-schema for the trajectory block.
- [examples/agentic_admission_demo.py](../examples/agentic_admission_demo.py): a runnable end-to-end trajectory with mixed retrieval and tool-call steps.
- [examples/memory_and_model_inference_demo.py](../examples/memory_and_model_inference_demo.py): a runnable end-to-end trajectory with all five step kinds.
- [anomaly_detection.md](anomaly_detection.md): detection patterns over the trajectory stream.
- [policy.md § What the native DSL deliberately doesn't do](policy.md#what-the-native-dsl-deliberately-doesnt-do-and-why): why trajectory-level rules live downstream in your detector, not in the per-decision admission engine.
