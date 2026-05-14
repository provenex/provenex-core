"""End-to-end tests for verify_chunks with a unified Policy.

Schema 2.0.0: the caller passes a :class:`Policy` (carrying verification
config + an optional :class:`PolicyEvaluator`) to ``verify_chunks``. A
chunk reaches ``kept`` only if BOTH gates allow it. The receipt records
both verdicts under the unified top-level ``policy`` block.
"""

from __future__ import annotations

import os

import pytest

from provenex import Policy, verify_chunks
from provenex.core.receipt import HmacSha256Signer
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.policy.evaluator import RequestContext


SIMPLE_DENY_POLICY = """
version: 1
policy_id: deny-secret

verification:
  block_unauthorized: true
  block_tampered: true

access_control:
  rules:
    - name: classification_gate
      when:
        chunk.metadata.classification: secret
      require:
        chunk.metadata.classification:
          in: [public]
      on_violation: deny
"""


def _make_index(tmp_path):
    db = tmp_path / "idx.db"
    os.environ.setdefault("PROVENEX_SIGNING_SECRET", "test-secret")
    return SQLiteProvenanceIndex(str(db))


def _ingest_two_chunks(index):
    from provenex.core.fingerprinter import Fingerprinter

    fp = Fingerprinter()
    texts = ["public document about widgets", "secret roadmap details"]
    fingerprints = []
    for i, t in enumerate(texts):
        cfp = fp.fingerprint_chunk(t)
        result = fp.fingerprint(t)
        index.add(
            fingerprint=cfp,
            document_id=f"d{i}",
            document_version=result.document_version,
            chunk_offset=0,
            chunk_length=len(t),
            authorized=True,
        )
        fingerprints.append(cfp)
    return texts, fingerprints


def _request(jurisdiction="EU"):
    return RequestContext(
        caller={"role": "user"},
        jurisdiction=jurisdiction,
        purpose="test",
        timestamp="2026-05-13T00:00:00Z",
    )


# --------------------------------------------------------------------------- #
# verify_chunks with no policy: default Policy with verification only         #
# --------------------------------------------------------------------------- #


def test_no_policy_argument_uses_default(tmp_path):
    index = _make_index(tmp_path)
    texts, _ = _ingest_two_chunks(index)
    result = verify_chunks(
        chunks=texts,
        index=index,
        signer=HmacSha256Signer(),
    )
    assert result.receipt.schema_version == "2.1.0"
    # No access control configured → block omitted.
    assert result.receipt.access_control is None
    d = result.receipt.to_dict()
    assert "access_control" not in d["policy"]
    assert d["policy"]["verification"]["block_unauthorized"] is True
    index.close()


# --------------------------------------------------------------------------- #
# Policy that denies one chunk and allows another                             #
# --------------------------------------------------------------------------- #


def test_policy_blocks_some_chunks_and_records_decisions(tmp_path):
    index = _make_index(tmp_path)
    texts, fps = _ingest_two_chunks(index)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)

    result = verify_chunks(
        chunks=texts,
        index=index,
        signer=HmacSha256Signer(),
        policy=policy,
        request_context=_request(),
        chunk_metadata=[
            {"classification": "public"},
            {"classification": "secret"},
        ],
    )
    # The public chunk reaches `kept`; the secret one is blocked.
    assert texts[0] in result.kept
    assert texts[1] in result.blocked

    receipt = result.receipt
    assert receipt.schema_version == "2.1.0"
    d = receipt.to_dict()
    ac = d["policy"]["access_control"]
    assert ac["evaluator"] == "native_yaml"
    assert ac["policy_id"] == "deny-secret"
    assert ac["policy_in_transparency_log"] is False
    assert len(ac["decisions"]) == 2

    d0, d1 = ac["decisions"]
    assert d0["chunk_fingerprint"] == fps[0]
    assert d0["decision"] == "allow"
    assert d1["chunk_fingerprint"] == fps[1]
    assert d1["decision"] == "deny"
    assert "classification_gate" in d1["rules_fired"]
    index.close()


# --------------------------------------------------------------------------- #
# Verification gate and access-control gate are independent                   #
# --------------------------------------------------------------------------- #


def test_verified_chunk_can_be_policy_denied(tmp_path):
    index = _make_index(tmp_path)
    texts, _ = _ingest_two_chunks(index)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)

    result = verify_chunks(
        chunks=[texts[1]],
        index=index,
        signer=HmacSha256Signer(),
        policy=policy,
        request_context=_request(),
        chunk_metadata=[{"classification": "secret"}],
    )
    assert result.kept == []
    assert result.blocked == [texts[1]]
    source = result.receipt.sources[0]
    assert source.verification_outcome.value == "VERIFIED"
    d = result.receipt.to_dict()
    assert d["policy"]["access_control"]["decisions"][0]["decision"] == "deny"
    index.close()


def test_unverified_chunk_can_be_policy_allowed(tmp_path):
    index = _make_index(tmp_path)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)
    text = "random text never seen by the index"

    result = verify_chunks(
        chunks=[text],
        index=index,
        signer=HmacSha256Signer(),
        policy=policy,
        request_context=_request(),
        chunk_metadata=[{"classification": "public"}],
    )
    source = result.receipt.sources[0]
    d = result.receipt.to_dict()
    decision = d["policy"]["access_control"]["decisions"][0]
    assert source.verification_outcome.value == "UNVERIFIED"
    assert decision["decision"] == "allow"
    index.close()


# --------------------------------------------------------------------------- #
# Eager validation of evaluator + request combo                               #
# --------------------------------------------------------------------------- #


def test_access_control_without_request_context_raises(tmp_path):
    index = _make_index(tmp_path)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)
    with pytest.raises(ValueError, match="request_context"):
        verify_chunks(
            chunks=["x"],
            index=index,
            policy=policy,
            request_context=None,
        )
    index.close()


def test_mismatched_chunk_metadata_length_raises(tmp_path):
    index = _make_index(tmp_path)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)
    with pytest.raises(ValueError, match="chunk_metadata length"):
        verify_chunks(
            chunks=["a", "b"],
            index=index,
            policy=policy,
            request_context=_request(),
            chunk_metadata=[{"x": 1}],
        )
    index.close()


# --------------------------------------------------------------------------- #
# Backward-compat: passing a bare VerificationPolicy works                    #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# metadata_binding (schema 2.1.0)                                              #
# --------------------------------------------------------------------------- #


def test_metadata_binding_defaults_to_at_evaluate(tmp_path):
    """Default binding for chunk_metadata is at_evaluate — the caller built
    the metadata list at retrieval time, so by default we record that the
    decision is only as trustworthy as that retrieval-time lookup was."""
    index = _make_index(tmp_path)
    texts, _ = _ingest_two_chunks(index)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)
    result = verify_chunks(
        chunks=[texts[0]],
        index=index,
        signer=HmacSha256Signer(),
        policy=policy,
        request_context=_request(),
        chunk_metadata=[{"classification": "public"}],
    )
    d = result.receipt.to_dict()
    decision = d["policy"]["access_control"]["decisions"][0]
    assert decision["metadata_binding"] == {
        "chunk_metadata": "at_evaluate",
        "request_context": "at_evaluate",
    }
    index.close()


def test_metadata_binding_at_ingest_when_declared(tmp_path):
    """When the operator declares chunk_metadata_binding='at_ingest', the
    receipt records it. This is the strong-trust case: tags live in the
    signed index row and an auditor knows it from the receipt alone."""
    index = _make_index(tmp_path)
    texts, _ = _ingest_two_chunks(index)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)
    result = verify_chunks(
        chunks=[texts[0]],
        index=index,
        signer=HmacSha256Signer(),
        policy=policy,
        request_context=_request(),
        chunk_metadata=[{"classification": "public"}],
        chunk_metadata_binding="at_ingest",
    )
    d = result.receipt.to_dict()
    decision = d["policy"]["access_control"]["decisions"][0]
    assert decision["metadata_binding"]["chunk_metadata"] == "at_ingest"
    # request_context is always at_evaluate — the caller dict is built fresh.
    assert decision["metadata_binding"]["request_context"] == "at_evaluate"
    index.close()


def test_invalid_metadata_binding_raises(tmp_path):
    """Typos fail loud, not silently."""
    index = _make_index(tmp_path)
    policy = Policy.from_text(SIMPLE_DENY_POLICY)
    with pytest.raises(ValueError, match="chunk_metadata_binding"):
        verify_chunks(
            chunks=["x"],
            index=index,
            policy=policy,
            request_context=_request(),
            chunk_metadata_binding="at_ingestion",  # typo
        )
    index.close()


def test_bare_verification_policy_is_accepted_for_backcompat(tmp_path):
    """Existing callers that pass a VerificationPolicy keep working —
    we wrap it in a Policy(verification=that) internally."""
    from provenex import VerificationPolicy

    index = _make_index(tmp_path)
    texts, _ = _ingest_two_chunks(index)
    result = verify_chunks(
        chunks=texts,
        index=index,
        signer=HmacSha256Signer(),
        policy=VerificationPolicy(block_stale=True),
    )
    assert result.receipt.schema_version == "2.1.0"
    d = result.receipt.to_dict()
    assert d["policy"]["verification"]["block_stale"] is True
    index.close()
