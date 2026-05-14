"""Tests for the framework-agnostic ``provenex.verify_chunks`` API.

This is the escape hatch for users not on LangChain, LangGraph, LlamaIndex,
or CrewAI — and it's also the function every wrapper ultimately delegates
to. These tests cover the public contract: accepted chunk shapes, policy
threading, trajectory linkage, and the ``next_trajectory`` return field
that lets callers chain calls without managing the cursor manually.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

import provenex
from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature
from provenex.core.trajectory import audit_trajectory_dag, start_trajectory
from provenex.core.verify import VerifiedChunks, verify_chunks
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor
from provenex.policy.policy import VerificationPolicy


SECRET = b"verify-public-api-secret"


@dataclass
class StubDoc:
    """Duck-typed Document for chunk coercion tests."""

    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def _seeded_index() -> tuple[SQLiteProvenanceIndex, list[str]]:
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    texts = [
        "Encryption policy requires AES-256 for data at rest.",
        "Key-encryption keys must be rotated quarterly.",
    ]
    ingestor.ingest(
        [StubDoc(page_content=t) for t in texts],
        doc_id="policy_v4",
        authorized=True,
    )
    return index, texts


# --------------------------------------------------------------------------- #
# Public API surface                                                          #
# --------------------------------------------------------------------------- #


def test_verify_chunks_is_exposed_at_top_level():
    """``provenex.verify_chunks`` is part of the documented public API."""
    assert provenex.verify_chunks is verify_chunks
    assert provenex.VerifiedChunks is VerifiedChunks


def test_start_trajectory_is_exposed_at_top_level():
    assert provenex.start_trajectory is start_trajectory


def test_audit_trajectory_dag_is_exposed_at_top_level():
    assert provenex.audit_trajectory_dag is audit_trajectory_dag


# --------------------------------------------------------------------------- #
# Single-call behaviour                                                       #
# --------------------------------------------------------------------------- #


def test_verify_chunks_accepts_string():
    index, texts = _seeded_index()
    result = verify_chunks(texts[0], index=index)
    assert isinstance(result, VerifiedChunks)
    assert result.kept == [texts[0]]
    assert result.blocked == []
    assert result.next_trajectory is None  # no trajectory was supplied


def test_verify_chunks_accepts_list_of_strings():
    index, texts = _seeded_index()
    result = verify_chunks(texts, index=index)
    assert set(result.kept) == set(texts)


def test_verify_chunks_accepts_list_of_documents():
    index, texts = _seeded_index()
    docs = [StubDoc(page_content=t) for t in texts]
    result = verify_chunks(docs, index=index)
    assert set(result.kept) == set(texts)


def test_verify_chunks_accepts_list_of_dicts():
    index, texts = _seeded_index()
    result = verify_chunks([{"content": t} for t in texts], index=index)
    assert set(result.kept) == set(texts)


def test_verify_chunks_rejects_unknown_input_shape():
    index, _ = _seeded_index()
    try:
        verify_chunks(42, index=index)
    except TypeError as exc:
        assert "must be str or list" in str(exc)
    else:
        raise AssertionError("expected TypeError for int input")


def test_verify_chunks_emits_signed_receipt_when_signer_given():
    index, texts = _seeded_index()
    signer = HmacSha256Signer(secret=SECRET)
    result = verify_chunks(texts[0], index=index, signer=signer)
    parsed = result.receipt.to_dict()
    assert "signature" in parsed
    assert verify_receipt_signature(parsed, signer) is True


def test_verify_chunks_emits_unsigned_receipt_without_signer():
    index, texts = _seeded_index()
    result = verify_chunks(texts[0], index=index)
    assert "signature" not in result.receipt.to_dict()


def test_verify_chunks_records_output_hash():
    import hashlib

    index, texts = _seeded_index()
    result = verify_chunks(texts[0], index=index, output_text="the answer")
    expected = "sha256:" + hashlib.sha256(b"the answer").hexdigest()
    assert result.receipt.output_hash == expected


# --------------------------------------------------------------------------- #
# Policy                                                                      #
# --------------------------------------------------------------------------- #


def test_verify_chunks_threads_policy_to_blocked():
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    ingestor = ProvenexIngestor(index=index)
    ingestor.ingest(
        [StubDoc(page_content="confidential memo about pricing.")],
        doc_id="memo_v1",
        authorized=False,
    )
    result = verify_chunks(
        "confidential memo about pricing.",
        index=index,
        policy=VerificationPolicy(block_unauthorized=True),
    )
    assert result.kept == []
    assert result.blocked == ["confidential memo about pricing."]
    # Receipt still records the blocked chunk.
    assert result.receipt.to_dict()["sources"][0]["verification_outcome"] == "UNAUTHORIZED"


# --------------------------------------------------------------------------- #
# Trajectory threading                                                        #
# --------------------------------------------------------------------------- #


def test_verify_chunks_without_trajectory_returns_none_next():
    """No trajectory in → no next_trajectory out, no trajectory block on receipt."""
    index, texts = _seeded_index()
    result = verify_chunks(texts[0], index=index)
    assert result.next_trajectory is None
    assert "trajectory" not in result.receipt.to_dict()


def test_verify_chunks_with_trajectory_emits_block_and_returns_next_cursor():
    index, texts = _seeded_index()
    traj = start_trajectory(agent_id="agent")
    result = verify_chunks(texts[0], index=index, trajectory=traj)
    d = result.receipt.to_dict()
    assert "trajectory" in d
    assert d["trajectory"]["trajectory_id"] == traj.trajectory_id
    assert d["trajectory"]["step_index"] == 0
    # next_trajectory is advanced one step and references this receipt.
    assert result.next_trajectory is not None
    assert result.next_trajectory.step_index == 1
    assert result.next_trajectory.parent_step_ids == (result.receipt.receipt_id,)


def test_verify_chunks_chains_via_next_trajectory():
    """The ergonomic chaining pattern: pass the previous result's
    next_trajectory in as the next call's trajectory."""
    index, texts = _seeded_index()
    signer = HmacSha256Signer(secret=SECRET)
    traj = start_trajectory(agent_id="agent")

    r1 = verify_chunks(texts[0], index=index, signer=signer, trajectory=traj)
    r2 = verify_chunks(
        texts[1], index=index, signer=signer, trajectory=r1.next_trajectory
    )
    r3 = verify_chunks(
        texts[0],
        index=index,
        signer=signer,
        trajectory=r2.next_trajectory,
        output_text="final answer",
    )

    d1 = r1.receipt.to_dict()
    d2 = r2.receipt.to_dict()
    d3 = r3.receipt.to_dict()
    assert d1["trajectory"]["trajectory_id"] == d2["trajectory"]["trajectory_id"]
    assert d2["trajectory"]["trajectory_id"] == d3["trajectory"]["trajectory_id"]
    assert d1["trajectory"]["step_index"] == 0
    assert d2["trajectory"]["step_index"] == 1
    assert d3["trajectory"]["step_index"] == 2
    assert d2["trajectory"]["parent_step_ids"] == [r1.receipt.receipt_id]
    assert d3["trajectory"]["parent_step_ids"] == [r2.receipt.receipt_id]

    # Audit the resulting chain end-to-end.
    audit = audit_trajectory_dag([d1, d2, d3])
    assert audit.ok is True


def test_step_kind_override_does_not_mutate_caller_cursor():
    """Passing step_kind to verify_chunks affects only the emitted receipt,
    not the trajectory cursor the caller still holds."""
    index, texts = _seeded_index()
    traj = start_trajectory(agent_id="agent", step_kind="retrieval")
    result = verify_chunks(
        texts[0], index=index, trajectory=traj, step_kind="memory_read"
    )
    # The receipt records the overridden step_kind.
    assert result.receipt.to_dict()["trajectory"]["step_kind"] == "memory_read"
    # The caller's original cursor is unchanged (frozen dataclass).
    assert traj.step_kind == "retrieval"


def test_agent_id_override_propagates_to_next_cursor():
    """A per-call agent_id override carries forward to next_trajectory —
    useful for multi-agent handoff."""
    index, texts = _seeded_index()
    traj = start_trajectory(agent_id="planner")
    result = verify_chunks(
        texts[0], index=index, trajectory=traj, agent_id="researcher"
    )
    assert result.receipt.to_dict()["trajectory"]["agent_id"] == "researcher"
    assert result.next_trajectory.agent_id == "researcher"


# --------------------------------------------------------------------------- #
# Custom fingerprinter / policy / index types                                 #
# --------------------------------------------------------------------------- #


def test_verify_chunks_uses_supplied_fingerprinter():
    """A custom Fingerprinter is honoured (round-trip with the same one)."""
    from provenex.core.fingerprinter import Fingerprinter, FingerprinterConfig

    fp = Fingerprinter(FingerprinterConfig(window_size=64, stride=32))
    index = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    # Ingest with the same fingerprinter so chunks resolve.
    text = "a custom fingerprinter test chunk."
    result_fp = fp.fingerprint(text)
    index.add(
        fingerprint=fp.fingerprint_chunk(text),
        document_id="d1",
        document_version=result_fp.document_version,
        chunk_offset=0,
        chunk_length=len(text),
        authorized=True,
    )

    result = verify_chunks(text, index=index, fingerprinter=fp)
    assert result.kept == [text]
    assert (
        result.receipt.to_dict()["sources"][0]["verification_outcome"]
        == "VERIFIED"
    )
