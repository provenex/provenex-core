"""Tests for the peppered fingerprint mode (v0.8.0).

The pepper is a per-deployment secret that turns the content hash into
HMAC-SHA256 instead of plain SHA-256. Mitigates the confirmation /
dictionary attack on low-entropy corpora (HR templates, policy boilerplate)
where an attacker who guesses the plaintext can recompute the unpeppered
SHA-256 and confirm the content is in the index. With a pepper, the
attacker also needs the pepper bytes.

Properties under test:
    1. Same text + same pepper -> same fingerprint (verify still works).
    2. Same text + different pepper -> different fingerprint
       (per-deployment unlinkability).
    3. Peppered fingerprints differ from unpeppered fingerprints of the
       same text (i.e. the pepper is actually being applied).
    4. The output prefix is still "sha256:" so downstream tooling reads
       unchanged.
"""

from __future__ import annotations

from provenex import (
    ENTRY_KIND_WHOLE_CHUNK,
    SQLiteProvenanceIndex,
    VerificationOutcome,
)
from provenex.core.fingerprinter import Fingerprinter, FingerprinterConfig


PEPPER_A = b"deployment-A-pepper-32-bytes-OK!"
PEPPER_B = b"deployment-B-pepper-32-bytes-OK!"


def test_same_pepper_produces_stable_fingerprint():
    fp = Fingerprinter(FingerprinterConfig(pepper=PEPPER_A))
    text = "Employment contract section: confidentiality clause."
    h1 = fp.fingerprint_chunk(text)
    h2 = fp.fingerprint_chunk(text)
    assert h1 == h2
    assert h1.startswith("sha256:")


def test_different_pepper_produces_different_fingerprint():
    """Per-deployment unlinkability for low-entropy content."""
    fp_a = Fingerprinter(FingerprinterConfig(pepper=PEPPER_A))
    fp_b = Fingerprinter(FingerprinterConfig(pepper=PEPPER_B))
    text = "Common HR boilerplate any attacker could guess."
    assert fp_a.fingerprint_chunk(text) != fp_b.fingerprint_chunk(text)


def test_peppered_differs_from_unpeppered():
    """The pepper is actually being applied, not silently dropped."""
    text = "A predictable plaintext."
    bare = Fingerprinter()
    peppered = Fingerprinter(FingerprinterConfig(pepper=PEPPER_A))
    assert bare.fingerprint_chunk(text) != peppered.fingerprint_chunk(text)


def test_peppered_fingerprint_roundtrips_through_the_index(tmp_path):
    """Ingest with pepper, verify with same pepper -> VERIFIED."""
    db = str(tmp_path / "idx.db")
    fp = Fingerprinter(FingerprinterConfig(pepper=PEPPER_A))
    idx = SQLiteProvenanceIndex(db, signing_secret=b"i" * 32)
    chunk = "An authorised HR chunk."
    chunk_fp = fp.fingerprint_chunk(chunk)
    idx.add(
        fingerprint=chunk_fp,
        document_id="doc1",
        document_version=fp.fingerprint(chunk).document_version,
        chunk_offset=0,
        chunk_length=len(chunk),
        entry_kind=ENTRY_KIND_WHOLE_CHUNK,
    )
    # Re-fingerprint with the same pepper at verify time.
    fp2 = Fingerprinter(FingerprinterConfig(pepper=PEPPER_A))
    assert idx.verify(fp2.fingerprint_chunk(chunk)) == (
        VerificationOutcome.VERIFIED
    )
    idx.close()


def test_window_fingerprints_also_use_the_pepper():
    """The pepper has to apply to every window, not just whole-chunk."""
    text = "x" * 500  # long enough to produce multiple windows
    fp_a = Fingerprinter(FingerprinterConfig(pepper=PEPPER_A))
    fp_b = Fingerprinter(FingerprinterConfig(pepper=PEPPER_B))
    a_wins = [w.fingerprint for w in fp_a.fingerprint(text).fingerprints]
    b_wins = [w.fingerprint for w in fp_b.fingerprint(text).fingerprints]
    assert len(a_wins) == len(b_wins) and len(a_wins) >= 2
    for a, b in zip(a_wins, b_wins):
        assert a != b  # Each window's peppered hash differs by deployment.
