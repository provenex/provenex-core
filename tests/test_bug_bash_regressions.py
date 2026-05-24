"""Regression coverage for the 2026-05-23 bug-bash round.

Each test pins a specific failure mode that used to slip through and would
silently re-emerge if the fix is ever reverted. Covered:

    * canonical payloads reject non-RFC-8259 floats (NaN/Inf) so cross-
      language verifiers do not get unparseable JSON
    * SQLite index enforces foreign keys, so a documents-row delete
      cannot leave an orphan fingerprint behind that verifies as
      UNVERIFIED instead of being prevented
    * empty access_control / tool_call_control rules block emits a
      warning (silent allow-all is a refactoring footgun)
    * a single require constraint dict combining multiple operators is
      rejected at parse time (the evaluator short-circuits on the first)
    * a bare-root path (no '.' segment) is rejected at parse time so
      typo'd ``when: { chunk: ... }`` cannot silently no-op the rule
    * set_authorization / supersede raise on a missing document_id so a
      typo'd revocation cannot appear to succeed
    * _build_inputs uses the index-derived ingested_at / content_source
      directly, never letting caller-supplied metadata shadow them
    * compute_parameters_hash surfaces non-JSON parameter types with a
      clear ValueError naming the fix

Each assertion is small and self-contained; the fixes are documented in
the file paths referenced from the test bodies.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import textwrap
import warnings
from datetime import datetime, timedelta, timezone

import pytest


# --------------------------------------------------------------------------- #
# Fix 1: canonical_payload + sibling JSON sites reject NaN / Inf              #
# --------------------------------------------------------------------------- #


def test_compute_caller_hash_rejects_nan_in_caller():
    """A caller dict carrying a NaN must raise rather than silently
    producing a non-RFC-8259 SHA-256 input that no strict third-party
    verifier (Go, Rust, browser JSON.parse) could re-derive.
    """
    from provenex.core.receipt import compute_caller_hash

    with pytest.raises(ValueError, match="not JSON-serial"):
        compute_caller_hash({"score": float("nan"), "sub": "alice"})


def test_compute_value_hash_rejects_infinity():
    from provenex.core.receipt import compute_value_hash

    with pytest.raises(ValueError) as info:
        compute_value_hash({"weight": float("inf")})
    # Make sure the message names the offending float rather than
    # propagating a bare TypeError.
    assert "inf" in str(info.value).lower() or "json" in str(info.value).lower()


def test_canonical_payload_round_trip_strict_parser_accepts():
    """Regression for the silent NaN drift: a receipt with only RFC-8259
    floats must canonicalise to bytes that ``json.loads`` and any strict
    third-party parser can re-load without losing fidelity.
    """
    from provenex.core.receipt import (
        HmacSha256Signer,
        ReceiptBuilder,
    )
    from provenex.policy.policy import VerificationPolicy
    from provenex.index.base import IndexEntry, VerificationOutcome

    builder = ReceiptBuilder(policy=VerificationPolicy())
    builder.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=IndexEntry(
            fingerprint="sha256:" + "a" * 64,
            document_id="d1",
            document_version="sha256:" + "b" * 64,
            chunk_offset=0,
            chunk_length=100,
            ingested_at="2026-05-23T00:00:00.000Z",
            authorized=True,
            superseded=False,
            signature="sha256:" + "c" * 64,
        ),
        normalization_applied=[],
    )
    receipt = builder.finalize(
        output_text="hello",
        signer=HmacSha256Signer(b"x" * 32),
    )
    payload = receipt.canonical_payload()
    # Strict re-parse must succeed and must not produce NaN/Inf surprises.
    loaded = json.loads(payload)
    assert loaded["receipt_id"] == receipt.receipt_id


# --------------------------------------------------------------------------- #
# Fix 2: SQLite foreign-key enforcement is on                                  #
# --------------------------------------------------------------------------- #


def test_sqlite_index_enforces_foreign_keys():
    """An attempt to DELETE a documents row whose fingerprints exist
    must fail with the FK constraint, so verify() never sees an
    orphaned-fingerprint UNVERIFIED that used to mask tamper.
    """
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    db = tempfile.mktemp(suffix=".db")
    idx = SQLiteProvenanceIndex(db, signing_secret=b"x" * 32)
    idx.add(
        fingerprint="sha256:" + "a" * 64,
        document_id="d1",
        document_version="sha256:" + "b" * 64,
        chunk_offset=0,
        chunk_length=100,
    )
    # Side-channel into the same DB; FK enforcement must reject the
    # DELETE that would otherwise leave the fingerprint orphaned.
    side = sqlite3.connect(db)
    side.execute("PRAGMA foreign_keys = ON")
    with pytest.raises(sqlite3.IntegrityError):
        side.execute("DELETE FROM documents WHERE document_id = ?", ("d1",))
    side.close()


# --------------------------------------------------------------------------- #
# Fix 3: empty rules block emits a warning                                     #
# --------------------------------------------------------------------------- #


def test_empty_access_control_rules_warns():
    """An access_control block whose rules list is empty is almost always
    a refactoring accident — silently allow-all would let the operator
    ship a gateless policy with no signal. Warn at parse time.
    """
    from provenex.policy.unified import Policy

    yaml_text = textwrap.dedent(
        """
        policy_id: empty
        version: 1
        access_control:
          rules: []
        """
    ).strip()
    fp = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
    fp.write(yaml_text)
    fp.close()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Policy.from_yaml(fp.name)
    msgs = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
    assert any("'rules' is empty" in m for m in msgs), msgs


# --------------------------------------------------------------------------- #
# Fix 4: multi-operator constraints rejected at parse time                     #
# --------------------------------------------------------------------------- #


def test_multi_operator_constraint_rejected():
    """``require: { path: { in: [..], not_older_than: 30d } }`` used to
    silently drop ``not_older_than`` because the evaluator short-circuits
    on the first operator key. Force authors to split into separate rules
    so the AND-semantics they want is actually enforced.
    """
    from provenex.policy.evaluator import PolicyParseError
    from provenex.policy.unified import Policy

    yaml_text = textwrap.dedent(
        """
        policy_id: multi_op
        version: 1
        access_control:
          rules:
            - name: multi
              require:
                chunk.metadata.region:
                  in: [EU]
                  not_older_than: 30d
        """
    ).strip()
    fp = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
    fp.write(yaml_text)
    fp.close()
    with pytest.raises(PolicyParseError, match="combines multiple operators"):
        Policy.from_yaml(fp.name)


# --------------------------------------------------------------------------- #
# Fix 5: bare-root paths rejected at parse time                                #
# --------------------------------------------------------------------------- #


def test_bare_root_path_rejected():
    """A ``when: { chunk: ... }`` (no dotted segment) resolved to the
    whole context object at evaluation time and never matched any scalar
    RHS, silently no-op'ing the rule. Reject at parse time.
    """
    from provenex.policy.evaluator import PolicyParseError
    from provenex.policy.unified import Policy

    yaml_text = textwrap.dedent(
        """
        policy_id: typo_path
        version: 1
        access_control:
          rules:
            - name: deny_secrets
              when:
                chunk: EU
              require:
                chunk.metadata.classification:
                  not_in: [secret]
        """
    ).strip()
    fp = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
    fp.write(yaml_text)
    fp.close()
    with pytest.raises(PolicyParseError, match=r"no '\.' segment"):
        Policy.from_yaml(fp.name)


# --------------------------------------------------------------------------- #
# Fix 6: revocation surfaces missing document                                  #
# --------------------------------------------------------------------------- #


def test_set_authorization_raises_on_missing_doc():
    """A typo in the document_id passed to a revocation call used to be a
    silent no-op (UPDATE matched zero rows). Surface a KeyError so the
    operator's revocation cannot quietly fail.
    """
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    db = tempfile.mktemp(suffix=".db")
    idx = SQLiteProvenanceIndex(db, signing_secret=b"x" * 32)
    with pytest.raises(KeyError):
        idx.set_authorization("does-not-exist", False)


def test_supersede_raises_on_missing_doc():
    from provenex.index.sqlite_index import SQLiteProvenanceIndex

    db = tempfile.mktemp(suffix=".db")
    idx = SQLiteProvenanceIndex(db, signing_secret=b"x" * 32)
    with pytest.raises(KeyError):
        idx.supersede("does-not-exist", "sha256:" + "b" * 64)


# --------------------------------------------------------------------------- #
# Fix 7: trusted index fields are not shadowable by caller metadata            #
# --------------------------------------------------------------------------- #


def test_build_inputs_uses_index_ingested_at_not_caller_metadata():
    """Caller-supplied ``metadata.ingested_at`` used to shadow the
    index-derived value via ``setdefault``. Trust direction is index ->
    caller; the index value must always win.
    """
    from provenex.policy.evaluator import (
        ChunkContext,
        RequestContext,
        _build_inputs,
    )

    chunk = ChunkContext(
        fingerprint="sha256:" + "a" * 64,
        document_id="d1",
        document_version="sha256:" + "b" * 64,
        ingested_at="2026-05-23T00:00:00Z",
        metadata={"ingested_at": "1970-01-01T00:00:00Z"},
        content_source="index",
    )
    req = RequestContext(
        caller={"sub": "a"},
        jurisdiction=None,
        purpose=None,
        timestamp="2026-05-23T00:00:00Z",
    )
    inputs = _build_inputs(chunk, req)
    assert inputs["chunk_metadata"]["ingested_at"] == "2026-05-23T00:00:00Z"
    assert inputs["chunk_metadata"]["content_source"] == "index"


# --------------------------------------------------------------------------- #
# Fix 8: parameters_hash surfaces non-JSON types clearly                       #
# --------------------------------------------------------------------------- #


def test_explicit_null_metadata_collapses_to_missing_for_constraints():
    """An explicit ``classification: null`` in chunk metadata used to
    pass a ``not_in: [secret]`` require because ``None not in [...]`` is
    True. Collapsing null to missing routes it through
    ``defaults.unknown_metadata`` (default-deny), matching the trust
    direction: caller-supplied None is no more authoritative than the
    key being absent.
    """
    import textwrap
    import tempfile
    from datetime import datetime, timezone

    from provenex.policy.evaluator import ChunkContext, RequestContext
    from provenex.policy.unified import Policy

    yaml_text = textwrap.dedent(
        """
        policy_id: null_test
        version: 1
        access_control:
          defaults:
            unknown_metadata: deny
          rules:
            - name: block_secrets
              require:
                chunk.metadata.classification:
                  not_in: [secret, top_secret]
        """
    ).strip()
    fp = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
    fp.write(yaml_text)
    fp.close()
    pol = Policy.from_yaml(fp.name)

    chunk = ChunkContext(
        fingerprint="sha256:" + "a" * 64,
        document_id="d1",
        document_version="sha256:" + "b" * 64,
        ingested_at=None,
        metadata={"classification": None},
        content_source=None,
    )
    req = RequestContext(
        caller={"sub": "a"},
        jurisdiction=None,
        purpose=None,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    decision = pol.access_control.evaluate(chunk, req)
    assert decision.decision == "deny", (
        f"explicit None should collapse to missing -> default-deny, "
        f"got {decision.decision} (rules_fired={decision.rules_fired})"
    )


def test_compute_parameters_hash_surfaces_non_json_value():
    """A LangChain / MCP tool call carrying ``bytes`` / ``datetime`` /
    ``set`` parameters used to crash admission with a bare TypeError.
    Surface a ValueError with concrete guidance so the operator knows to
    coerce inputs to JSON primitives before the admission boundary.
    """
    from provenex.tool_call.evaluator import compute_parameters_hash

    with pytest.raises(ValueError, match="not JSON-serial"):
        compute_parameters_hash({"blob": b"raw bytes"})

    with pytest.raises(ValueError, match="not JSON-serial"):
        compute_parameters_hash({"score": float("nan")})
