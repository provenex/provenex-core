"""Precedence among the five verification outcomes (v0.8.0).

An auditor reasoning about a denied chunk needs to know which condition
shadowed which when multiple could apply. This test pins the order down
in code so a future refactor cannot drift the semantics quietly.

Order: TAMPERED > UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED.

UNVERIFIED is the absent-entry sentinel: when no row matches at all,
none of the others can apply. The other four are properties of a row
that exists; precedence lets one row produce only one outcome even
when several would individually evaluate true.
"""

from __future__ import annotations

import hmac
from hashlib import sha256

from provenex.index.base import (
    OUTCOME_PRECEDENCE,
    VerificationOutcome,
    reduce_outcomes,
)
from provenex.index.sqlite_index import (
    SQLiteProvenanceIndex,
    _canonical_payload,
    _sign,
)


SECRET = b"prec-test-secret-32-bytes-please!"


def test_precedence_constant_matches_the_documented_order():
    """The constant is what the docs and how_it_works.md cite."""
    assert OUTCOME_PRECEDENCE == (
        VerificationOutcome.TAMPERED,
        VerificationOutcome.PURGED,
        VerificationOutcome.UNAUTHORIZED,
        VerificationOutcome.STALE,
        VerificationOutcome.UNVERIFIED,
        VerificationOutcome.VERIFIED,
    )


def test_reduce_outcomes_picks_the_winner():
    """reduce_outcomes() collapses a candidate set to the dominant outcome."""
    cases = [
        # All five together: TAMPERED wins.
        ({
            VerificationOutcome.VERIFIED,
            VerificationOutcome.STALE,
            VerificationOutcome.UNAUTHORIZED,
            VerificationOutcome.TAMPERED,
            VerificationOutcome.UNVERIFIED,
        }, VerificationOutcome.TAMPERED),
        # Sig OK but both unauthorised AND stale: UNAUTHORIZED wins.
        ({VerificationOutcome.STALE, VerificationOutcome.UNAUTHORIZED},
         VerificationOutcome.UNAUTHORIZED),
        # Sig OK, authorised, but stale: STALE.
        ({VerificationOutcome.STALE, VerificationOutcome.VERIFIED},
         VerificationOutcome.STALE),
        # Nothing flagged: VERIFIED (neutral element).
        (set(), VerificationOutcome.VERIFIED),
    ]
    for candidates, expected in cases:
        got = reduce_outcomes(candidates)
        assert got == expected, f"{candidates} -> expected {expected}, got {got}"


def test_chunk_satisfying_multiple_conditions_resolves_to_tampered():
    """Construct a row that is simultaneously tampered AND unauthorised.

    A real index row with the signature column rewritten to garbage AND
    documents.authorized flipped to False must verify as TAMPERED, not
    UNAUTHORIZED. The signature check happens first because a row whose
    integrity is broken cannot be trusted to say anything about
    authorisation either.
    """
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    chunk_fp = "sha256:" + sha256(b"the-chunk-text").hexdigest()
    doc_version = "sha256:" + sha256(b"v1").hexdigest()
    idx.add(
        fingerprint=chunk_fp,
        document_id="doc1",
        document_version=doc_version,
        chunk_offset=0,
        chunk_length=14,
    )
    # Tamper: rewrite the signature AND mark unauthorised.
    idx._conn.execute(
        "UPDATE fingerprints SET signature = 'deadbeef' "
        "WHERE fingerprint = ?", (chunk_fp,))
    idx._conn.execute(
        "UPDATE documents SET authorized = 0 WHERE document_id = ?",
        ("doc1",))
    idx._conn.commit()

    assert idx.verify(chunk_fp) == VerificationOutcome.TAMPERED
    idx.close()


def test_chunk_unauthorized_and_stale_resolves_to_unauthorized():
    """Unauthorised wins over stale.

    Authorisation revocation is more important than version supersession:
    a revoked document should not retrieve at all, regardless of which
    version of it would otherwise be current.
    """
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    chunk_fp = "sha256:" + sha256(b"original").hexdigest()
    new_chunk_fp = "sha256:" + sha256(b"updated").hexdigest()
    v1 = "sha256:" + sha256(b"v1").hexdigest()
    v2 = "sha256:" + sha256(b"v2").hexdigest()
    idx.add(chunk_fp, "doc1", v1, 0, 8, authorized=True)
    # Second add with a different version supersedes v1's row.
    idx.add(new_chunk_fp, "doc1", v2, 0, 7, authorized=True)
    # Now revoke authorisation for the whole document.
    idx.set_authorization("doc1", False)

    # Original chunk_fp is now (a) on a superseded row AND (b) under an
    # unauthorised document. UNAUTHORIZED must dominate.
    assert idx.verify(chunk_fp) == VerificationOutcome.UNAUTHORIZED
    idx.close()


def test_chunk_stale_resolves_to_stale_when_authorised():
    """Plain old supersession on an authorised document = STALE."""
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    chunk_fp = "sha256:" + sha256(b"v1-bytes").hexdigest()
    new_chunk_fp = "sha256:" + sha256(b"v2-bytes").hexdigest()
    v1 = "sha256:" + sha256(b"docv1").hexdigest()
    v2 = "sha256:" + sha256(b"docv2").hexdigest()
    idx.add(chunk_fp, "doc1", v1, 0, 8)
    idx.add(new_chunk_fp, "doc1", v2, 0, 8)
    assert idx.verify(chunk_fp) == VerificationOutcome.STALE
    idx.close()


def test_absent_entry_yields_unverified():
    """The absent-entry sentinel.

    UNVERIFIED applies when no row matches; once it does, none of the
    other four conditions can apply because there is nothing to apply
    them to. This is why UNVERIFIED sits below the others in
    OUTCOME_PRECEDENCE.
    """
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    assert idx.verify("sha256:" + "0" * 64) == VerificationOutcome.UNVERIFIED
    idx.close()
