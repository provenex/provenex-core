"""Integration tests for the CrewAI session.

CrewAI tools are ultimately callables; our wrapper preserves the callable
shape. These tests stand in for real CrewAI Agents by directly calling
the wrapped tools, the same way an Agent's tool-call resolver would.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature
from provenex.core.trajectory import audit_trajectory_dag
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.crewai import ProvenexCrewSession, VerifiedChunks
from provenex.integrations.langchain import ProvenexIngestor
from provenex.policy.policy import VerificationPolicy


SECRET = b"crewai-test-secret"


@dataclass
class StubDoc:
    """Duck-typed Document — works for the chunk coercion."""

    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def _seeded_index() -> tuple[SQLiteProvenanceIndex, List[str]]:
    """Index pre-populated with two authorized chunks; returns the chunk texts."""
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    chunk_texts = [
        "Encryption policy requires AES-256 for data at rest.",
        "Key-encryption keys must be rotated quarterly.",
    ]
    ingestor.ingest(
        [StubDoc(page_content=t) for t in chunk_texts],
        doc_id="policy_v4",
        authorized=True,
    )
    return index, chunk_texts


# --------------------------------------------------------------------------- #
# Session basics                                                              #
# --------------------------------------------------------------------------- #


def test_session_starts_with_fresh_trajectory():
    index, _ = _seeded_index()
    session = ProvenexCrewSession(index=index, agent_id="researcher")
    assert session.trajectory.step_index == 0
    assert session.trajectory.agent_id == "researcher"
    assert session.trajectory_id.startswith("trj_")
    assert session.receipts == []


def test_session_receipts_property_returns_snapshot_not_live_list():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    session.verify_chunks(texts[0])
    snapshot = session.receipts
    session.verify_chunks(texts[1])
    # The snapshot must not have grown.
    assert len(snapshot) == 1
    assert len(session.receipts) == 2


# --------------------------------------------------------------------------- #
# verify_chunks                                                               #
# --------------------------------------------------------------------------- #


def test_verify_chunks_accepts_string_input():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    result = session.verify_chunks(texts[0])
    assert isinstance(result, VerifiedChunks)
    assert result.kept == [texts[0]]
    assert result.blocked == []
    assert "trajectory" in result.receipt.to_dict()


def test_verify_chunks_accepts_list_of_strings():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    result = session.verify_chunks(texts)
    assert set(result.kept) == set(texts)


def test_verify_chunks_accepts_list_of_documents():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    docs = [StubDoc(page_content=t) for t in texts]
    result = session.verify_chunks(docs)
    assert set(result.kept) == set(texts)


def test_verify_chunks_accepts_list_of_dicts():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    dict_chunks = [{"content": t} for t in texts]
    result = session.verify_chunks(dict_chunks)
    assert set(result.kept) == set(texts)


def test_verify_chunks_rejects_unrecognized_types():
    """Session.verify_chunks delegates to provenex.verify_chunks for chunk
    coercion, so the error wording matches the shared helper."""
    index, _ = _seeded_index()
    session = ProvenexCrewSession(index=index)
    try:
        session.verify_chunks(42)
    except TypeError as exc:
        assert "must be str or list" in str(exc)
    else:
        raise AssertionError("expected TypeError for int input")


def test_verify_chunks_rejects_list_with_unrecognized_item():
    index, _ = _seeded_index()
    session = ProvenexCrewSession(index=index)
    try:
        session.verify_chunks([{"no_text_field": "x"}])
    except TypeError as exc:
        assert "missing recognized text field" in str(exc)
    else:
        raise AssertionError("expected TypeError for dict without text field")


# --------------------------------------------------------------------------- #
# Trajectory advancement                                                      #
# --------------------------------------------------------------------------- #


def test_verify_chunks_advances_trajectory():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    session.verify_chunks(texts[0])
    assert session.trajectory.step_index == 1
    session.verify_chunks(texts[1])
    assert session.trajectory.step_index == 2


def test_three_calls_form_linked_chain():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    r1 = session.verify_chunks(texts[0]).receipt
    r2 = session.verify_chunks(texts[1]).receipt
    r3 = session.verify_chunks(texts[0]).receipt

    d1 = r1.to_dict()["trajectory"]
    d2 = r2.to_dict()["trajectory"]
    d3 = r3.to_dict()["trajectory"]
    assert d1["trajectory_id"] == d2["trajectory_id"] == d3["trajectory_id"]
    assert d1["step_index"] == 0
    assert d2["step_index"] == 1
    assert d3["step_index"] == 2
    assert d1["parent_step_ids"] == []
    assert d2["parent_step_ids"] == [r1.receipt_id]
    assert d3["parent_step_ids"] == [r2.receipt_id]


def test_session_advance_skips_a_step_without_a_receipt():
    """For pure reasoning steps that don't touch chunks, advance() leaves
    a gap in the trajectory cursor without emitting a receipt."""
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    r1 = session.verify_chunks(texts[0]).receipt
    # No receipt at step 1; advance the cursor to step 2.
    session.advance(step_kind="reasoning")
    r3 = session.verify_chunks(texts[1]).receipt
    # The receipt at the second emission should have step_index=2,
    # not step_index=1, because we advanced in between.
    assert r3.to_dict()["trajectory"]["step_index"] == 2
    assert r3.to_dict()["trajectory"]["parent_step_ids"] == [r1.receipt_id]


# --------------------------------------------------------------------------- #
# Tool wrapping                                                               #
# --------------------------------------------------------------------------- #


def test_wrap_tool_preserves_callable_shape_and_emits_receipt():
    """Wrapped tool: same signature, but each call emits a session receipt."""
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))

    def my_tool(query: str) -> str:
        """Original tool — returns a verbatim authorized chunk."""
        return texts[0]

    wrapped = my_tool
    wrapped = session.wrap_tool(my_tool, step_kind="retrieval")
    # functools.wraps preserves name and docstring.
    assert wrapped.__name__ == "my_tool"
    assert "Original tool" in (wrapped.__doc__ or "")

    out = wrapped("anything")
    assert out == texts[0]
    assert len(session.receipts) == 1
    assert session.receipts[0].to_dict()["trajectory"]["step_kind"] == "retrieval"


def test_wrap_tool_list_in_list_out():
    index, texts = _seeded_index()
    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))

    def tool_returning_list(q: str) -> List[str]:
        return list(texts)

    wrapped = session.wrap_tool(tool_returning_list, step_kind="retrieval")
    out = wrapped("q")
    assert isinstance(out, list)
    assert set(out) == set(texts)


def test_wrap_tool_drops_blocked_by_default():
    """Unauthorized chunks are removed from the tool output by default."""
    index, _ = _seeded_index()
    # Add an unauthorized chunk.
    ingestor = ProvenexIngestor(index=index)
    ingestor.ingest(
        [StubDoc(page_content="confidential pricing memo body.")],
        doc_id="memo_v1",
        authorized=False,
    )

    session = ProvenexCrewSession(
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        policy=VerificationPolicy(block_unauthorized=True),
    )

    def tool(q: str) -> str:
        return "confidential pricing memo body."

    wrapped = session.wrap_tool(tool)
    out = wrapped("q")
    assert out == ""  # blocked → dropped → empty join
    # Receipt still records that we saw it.
    rec = session.receipts[0].to_dict()
    src = rec["sources"][0]
    assert src["verification_outcome"] == "UNAUTHORIZED"


def test_wrap_tool_return_blocked_keeps_redacted_visibility():
    """With return_blocked=True, the model sees the blocked content too
    (e.g. so the answer can refuse explicitly), but the receipt still
    records the block."""
    index, _ = _seeded_index()
    ingestor = ProvenexIngestor(index=index)
    ingestor.ingest(
        [StubDoc(page_content="confidential pricing memo body.")],
        doc_id="memo_v1",
        authorized=False,
    )

    session = ProvenexCrewSession(
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        policy=VerificationPolicy(block_unauthorized=True),
    )

    def tool(q: str) -> str:
        return "confidential pricing memo body."

    wrapped = session.wrap_tool(tool, return_blocked=True)
    out = wrapped("q")
    assert "confidential pricing memo body." in out


# --------------------------------------------------------------------------- #
# End-to-end                                                                  #
# --------------------------------------------------------------------------- #


def test_session_receipts_pass_full_trajectory_audit():
    """End-to-end: three tool calls produce receipts that audit cleanly."""
    index, texts = _seeded_index()
    session = ProvenexCrewSession(
        index=index, signer=HmacSha256Signer(secret=SECRET), agent_id="agent"
    )

    def tool_a(q: str) -> str:
        return texts[0]

    def tool_b(q: str) -> str:
        return texts[1]

    wa = session.wrap_tool(tool_a, step_kind="retrieval")
    wb = session.wrap_tool(tool_b, step_kind="retrieval")

    wa("q1")
    wb("q2")
    wa("q3")

    assert len(session.receipts) == 3

    verifier = HmacSha256Signer(secret=SECRET)
    for r in session.receipts:
        assert verify_receipt_signature(r.to_dict(), verifier) is True

    result = audit_trajectory_dag([r.to_dict() for r in session.receipts])
    assert result.ok is True
    assert result.receipt_count == 3
    assert result.trajectory_id == session.trajectory_id


def test_memory_pattern_ingest_then_verify_via_session():
    """The documented memory pattern: write content with the ingestor
    (treated as memory_write), read it back via session.verify_chunks
    (step_kind=memory_read). The trajectory captures both kinds of
    steps via step_kind."""
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    # Simulate a memory write.
    ingestor.ingest(
        [StubDoc(page_content="user said they prefer python.")],
        doc_id="memory_user_pref_001",
        authorized=True,
    )

    session = ProvenexCrewSession(index=index, signer=HmacSha256Signer(secret=SECRET))
    # Simulate a memory read.
    result = session.verify_chunks(
        "user said they prefer python.", step_kind="memory_read"
    )
    assert result.kept == ["user said they prefer python."]
    assert (
        session.receipts[0].to_dict()["trajectory"]["step_kind"] == "memory_read"
    )
