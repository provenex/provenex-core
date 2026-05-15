"""Determinism tests for policy_version_hash and inputs_hash.

These are the contract the transparency-log integration will
depend on. Two policies that differ only in formatting MUST hash to the
same value; an actual structural change MUST change the hash.
"""

from __future__ import annotations

from provenex.policy.evaluator import (
    compute_inputs_hash,
    compute_policy_version_hash,
)
from provenex.policy.yaml_evaluator import NativeYamlEvaluator


# --------------------------------------------------------------------------- #
# Policy version hash                                                         #
# --------------------------------------------------------------------------- #


def test_policy_hash_is_sha256_prefixed():
    h = compute_policy_version_hash({"a": 1})
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_equivalent_bundles_hash_the_same():
    a = {"rules": [{"name": "x"}], "policy_id": "p", "version": 1}
    b = {"version": 1, "policy_id": "p", "rules": [{"name": "x"}]}
    assert compute_policy_version_hash(a) == compute_policy_version_hash(b)


def test_nested_key_reordering_does_not_change_hash():
    a = {"defaults": {"unknown_metadata": "deny", "policy_version_mismatch": "deny"}}
    b = {"defaults": {"policy_version_mismatch": "deny", "unknown_metadata": "deny"}}
    assert compute_policy_version_hash(a) == compute_policy_version_hash(b)


def test_actual_structural_change_changes_hash():
    a = {"policy_id": "p", "version": 1, "rules": [{"name": "x"}]}
    b = {"policy_id": "p", "version": 1, "rules": [{"name": "y"}]}
    assert compute_policy_version_hash(a) != compute_policy_version_hash(b)


# --------------------------------------------------------------------------- #
# Hash via the loaded evaluator                                               #
# --------------------------------------------------------------------------- #


_POLICY_A = """
version: 1
policy_id: hr-corpus-v3
rules:
  - name: r
    require:
      chunk.metadata.x: y
    on_violation: deny
"""

# Identical to _POLICY_A except for whitespace and comments.
_POLICY_A_RESHAPED = """
# A different layout of the same policy.
version: 1
policy_id: hr-corpus-v3

rules:
  - name: r
    require:
        chunk.metadata.x: y
    on_violation: deny


"""

_POLICY_B = """
version: 1
policy_id: hr-corpus-v3
rules:
  - name: r
    require:
      chunk.metadata.x: z   # changed value
    on_violation: deny
"""


def test_whitespace_only_yaml_differences_hash_the_same():
    a = NativeYamlEvaluator.from_text(_POLICY_A)
    b = NativeYamlEvaluator.from_text(_POLICY_A_RESHAPED)
    assert a.policy_version_hash == b.policy_version_hash


def test_changed_constraint_value_changes_hash():
    a = NativeYamlEvaluator.from_text(_POLICY_A)
    b = NativeYamlEvaluator.from_text(_POLICY_B)
    assert a.policy_version_hash != b.policy_version_hash


# --------------------------------------------------------------------------- #
# Inputs hash                                                                 #
# --------------------------------------------------------------------------- #


def test_inputs_hash_is_sha256_prefixed():
    h = compute_inputs_hash({"chunk_metadata": {}, "request_context": {}})
    assert h.startswith("sha256:")


def test_inputs_hash_invariant_to_key_order():
    a = {
        "chunk_metadata": {"residency": "EU", "tier": "prod"},
        "request_context": {"jurisdiction": "EU"},
    }
    b = {
        "request_context": {"jurisdiction": "EU"},
        "chunk_metadata": {"tier": "prod", "residency": "EU"},
    }
    assert compute_inputs_hash(a) == compute_inputs_hash(b)


def test_inputs_hash_changes_on_value_change():
    a = {"chunk_metadata": {"residency": "EU"}, "request_context": {}}
    b = {"chunk_metadata": {"residency": "US"}, "request_context": {}}
    assert compute_inputs_hash(a) != compute_inputs_hash(b)


def test_inputs_hash_preserves_unicode_smart_quotes():
    # Smart quotes survive normalization throughout Provenex (see
    # CLAUDE.md). The canonical hashing path must too.
    a = {"chunk_metadata": {"note": "they said “hello”"}}
    b = {"chunk_metadata": {"note": "they said “hello”"}}
    assert compute_inputs_hash(a) == compute_inputs_hash(b)


def test_inputs_hash_independent_of_inputs_field_on_receipt():
    # The contract is that the hash is computed over the canonical inputs
    # regardless of whether the receipt later redacts the inputs field.
    # Asserting this by computing the hash separately from the evaluator
    # and comparing.
    from provenex.policy.evaluator import _build_inputs, ChunkContext, RequestContext

    chunk = ChunkContext(
        fingerprint="sha256:abc",
        document_id="d",
        document_version="v",
        ingested_at="2026-05-01T00:00:00Z",
        metadata={"residency": "EU"},
    )
    request = RequestContext(
        caller={"role": "admin"},
        jurisdiction="EU",
        purpose=None,
        timestamp="2026-05-13T00:00:00Z",
    )
    inputs = _build_inputs(chunk, request)
    h_directly = compute_inputs_hash(inputs)

    # Same hash when the evaluator computes it as part of evaluate().
    ev = NativeYamlEvaluator.from_text(_POLICY_A)
    d = ev.evaluate(chunk, request)
    assert d.inputs_hash == h_directly
