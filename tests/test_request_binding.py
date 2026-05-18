"""Tests for the v0.8.0 request-to-receipt binding.

The binding ties a signed receipt cryptographically to *the specific
request that produced it*: the query/prompt text and the resolved
request_context. Without this, the receipt's link to the triggering
query is implicit and operator-controlled (a receipt could be presented
as evidence for any query). With it, an auditor re-derives the
``request_hash`` from the original query and request_context and
confirms a match.

The binding is part of the canonical signing payload, so an attacker
who edits any of the binding fields invalidates the receipt signature.
"""

from __future__ import annotations

import hashlib
import json

from provenex import (
    HmacSha256Signer,
    RequestContext,
    SQLiteProvenanceIndex,
    compute_request_binding,
    verify_chunks,
    verify_receipt_signature,
)


SECRET = b"binding-secret-32-bytes-or-more!"


def _new_request() -> RequestContext:
    return RequestContext(
        caller={"id": "u_42", "role": "engineer"},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )


def test_binding_emitted_when_request_text_supplied(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", "rs")
    monkeypatch.setenv("PROVENEX_INDEX_SECRET", "is")
    index = SQLiteProvenanceIndex(str(tmp_path / "idx.db"))
    request = _new_request()

    result = verify_chunks(
        chunks=["a chunk that does not exist in the index"],
        index=index,
        signer=HmacSha256Signer(secret=SECRET),
        request_context=request,
        request_text="What is the encryption rotation policy?",
    )
    d = result.receipt.to_dict()
    assert "request_binding" in d
    rb = d["request_binding"]
    assert rb["algorithm"] == "sha256"
    assert rb["query_hash"].startswith("sha256:")
    assert rb["request_context_hash"].startswith("sha256:")
    assert rb["request_hash"].startswith("sha256:")


def test_binding_query_hash_matches_independent_recomputation(tmp_path, monkeypatch):
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", "rs")
    monkeypatch.setenv("PROVENEX_INDEX_SECRET", "is")
    index = SQLiteProvenanceIndex(str(tmp_path / "idx.db"))
    request = _new_request()
    query = "What is the encryption rotation policy?"

    result = verify_chunks(
        chunks=["c"], index=index,
        signer=HmacSha256Signer(secret=SECRET),
        request_context=request,
        request_text=query,
    )
    d = result.receipt.to_dict()
    expected_query_hash = (
        "sha256:" + hashlib.sha256(query.encode("utf-8")).hexdigest()
    )
    assert d["request_binding"]["query_hash"] == expected_query_hash


def test_binding_context_hash_excludes_session_id():
    """session_id is excluded from the context hash by design.

    Two requests differing only in session_id must produce the same
    request_context_hash, because the binding tracks the policy-shaping
    subset of the request (the same subset that flows into inputs_hash).
    """
    a = RequestContext(
        caller={"id": "u_42"}, jurisdiction="US",
        purpose="x", timestamp="2026-01-01T00:00:00Z",
        session_id="session-A",
    )
    b = RequestContext(
        caller={"id": "u_42"}, jurisdiction="US",
        purpose="x", timestamp="2026-01-01T00:00:00Z",
        session_id="session-B",
    )
    ba = compute_request_binding(request_context=a)
    bb = compute_request_binding(request_context=b)
    assert ba["request_context_hash"] == bb["request_context_hash"]
    # Same request_hash too (no query, same context hash).
    assert ba["request_hash"] == bb["request_hash"]


def test_binding_block_covered_by_signature(tmp_path, monkeypatch):
    """Tamper with the binding -> signature fails.

    The whole point of the binding is that the receipt cryptographically
    commits to the triggering request. Editing the recorded request_hash
    must invalidate the signature.
    """
    monkeypatch.setenv("PROVENEX_RECEIPT_SECRET", "rs")
    monkeypatch.setenv("PROVENEX_INDEX_SECRET", "is")
    index = SQLiteProvenanceIndex(str(tmp_path / "idx.db"))
    request = _new_request()
    signer = HmacSha256Signer(secret=SECRET)

    result = verify_chunks(
        chunks=["c"], index=index, signer=signer,
        request_context=request,
        request_text="original query",
    )
    receipt_dict = result.receipt.to_dict()
    assert verify_receipt_signature(receipt_dict, signer)

    # Forge: claim the receipt was for a DIFFERENT query.
    forged = json.loads(json.dumps(receipt_dict))
    forged["request_binding"]["query_hash"] = (
        "sha256:" + "f" * 64
    )
    assert not verify_receipt_signature(forged, signer), (
        "tampering with request_binding.query_hash must invalidate the "
        "receipt signature"
    )


def test_binding_omitted_when_neither_input_supplied():
    """compute_request_binding returns None when nothing is bindable."""
    assert compute_request_binding() is None
    assert compute_request_binding(request_text=None,
                                   request_context=None) is None


def test_binding_records_null_for_missing_half():
    """Absence is explicit, not implicit.

    Supplying request_context but not request_text records query_hash
    as null so an auditor sees that the binding is incomplete.
    """
    rb = compute_request_binding(request_context=_new_request())
    assert rb["query_hash"] is None
    assert rb["request_context_hash"] is not None
    assert rb["request_hash"] is not None
