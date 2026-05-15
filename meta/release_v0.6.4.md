# Release notes — v0.6.4

**Headline.** Schema 2.3.0 — receipts gain top-level `caller_hash` and optional `trajectory.session_id`. Two correlation fields a downstream anomaly detector or SIEM uses to bucket events by caller and session without crawling per-decision input blobs. Two new runnable demos show the source-of-record story end-to-end.

## What's new since 0.6.3

- **Schema 2.3.0** — additive minor over 2.2.0.
    - Top-level **`caller_hash`** (`"sha256:<hex>"`). SHA-256 over the canonical JSON of `request_context.caller`. Computed automatically by the receipt emission path; emitted on every receipt produced with a `RequestContext` in scope (`verify_chunks` with a request, `admission_check`, all framework wrappers).
    - Optional **`trajectory.session_id`** — caller-chosen opaque string for multi-trajectory correlation (a chat session, an incident-response engagement, a multi-day investigation).

- **`provenex.compute_caller_hash(caller)`** — public helper exposing the same canonicalisation the emission path uses (`json.dumps(caller, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` → SHA-256). A downstream consumer can independently re-derive the hash from the raw caller dict embedded in a decision record and confirm the receipt is self-consistent.

- **`RequestContext.session_id`** — new optional field; flows into the emitted receipt's trajectory block. Excluded from `inputs_hash` by design — the deterministic-per-evaluation contract on `PolicyEvaluator` is preserved. Two requests differing only in `session_id` produce identical decisions and identical input hashes. Silently dropped on calls without a trajectory in scope (single-shot calls aren't sessions).

- **`TrajectoryContext.session_id`** + **`start_trajectory(session_id=...)`** — for the framework-agnostic case. The cursor carries the session forward through `next_step()`. When the request also carries a `session_id`, the request wins per emission and propagates onward.

- **Two new examples**:
    - `examples/anomaly_correlation_demo.py` — pure stdlib. Generates 9 signed receipts across three callers and two sessions, then switches hats and reads them as a downstream anomaly detector — `GROUP BY caller_hash` (one caller pops out as 5x the baseline), `GROUP BY session_id` (per-session step-kind shape), and signature verification across the stream.
    - `examples/anomaly_correlation_with_policy_demo.py` — same shape, but emitted against a unified YAML policy so every receipt also carries `policy.access_control.decisions[]` and `policy.tool_call_control.decisions[]`. Adds a third pattern: re-derive `caller_hash` from the verbatim caller embedded on every decision record across both gate types.

## Compatibility

- **Backward compatible.** A 2.2.0 receipt is a valid 2.3.0 receipt; a 2.2.0 verifier that ignores unknown fields validates a 2.3.0 receipt unchanged. No signing-format change — the existing canonical JSON rule covers the new fields.
- **`RequestContext`** gains `session_id` at the end of its frozen dataclass; existing positional / keyword construction unaffected.
- **`TrajectoryContext`** gains `session_id` at the end; existing construction unaffected.
- **`ReceiptBuilder.finalize`** gains an optional `caller_hash` kwarg; existing callers unaffected.
- **No policy / DSL change.** `caller_hash` and `session_id` are receipt-side correlation tags, NOT policy inputs. They never resolve under `request.*` in a rule's `when` or `require` clause.

## Example

```python
from provenex import (
    HmacSha256Signer, Policy, RequestContext, ToolCallContext,
    admission_check, start_trajectory,
)

trj = start_trajectory(
    agent_id="incident_agent",
    session_id="incident-2026-05-14-customer-success-001",
)
request = RequestContext(
    caller={"id": "u_42", "role": "engineer"},
    jurisdiction="US",
    purpose="incident_response",
    timestamp="2026-05-14T11:30:00Z",
    session_id="incident-2026-05-14-customer-success-001",
)
result = admission_check(
    tool=ToolCallContext(name="jira", operation="create_issue", parameters={...}),
    request=request,
    policy=Policy.from_yaml("agent_policy.yaml"),
    signer=HmacSha256Signer(),
    trajectory=trj,
)

# A downstream consumer reads:
d = result.receipt.to_dict()
print(d["caller_hash"])                # sha256:7a2b...  → group key
print(d["trajectory"]["session_id"])   # incident-…001  → session key
```

## Install

```bash
pip install provenex-core==0.6.4
pip install "provenex-core[policy]==0.6.4"        # YAML DSL (chunk + tool-call)
pip install "provenex-core[langgraph]==0.6.4"     # LangGraph nodes (retrieval + admission)
pip install "provenex-core[crewai]==0.6.4"        # CrewAI session + admission
pip install "provenex-core[langchain]==0.6.4"     # LangChain retriever + admission wrapper
pip install "provenex-core[ed25519]==0.6.4"       # asymmetric receipt signing
```
