"""Red-team coverage for the window-aligned splice control (v0.8.0).

Pre-v0.8.0, the CLI ingest path wrote both the whole-document SHA-256
and every sliding-window fingerprint into the same ``fingerprints``
table, with identical semantics at verify time. That made any
128-codepoint substring of an authorized document promote to VERIFIED
on its own, even though no operator ever authorized it as a discrete
chunk. The fix: the index distinguishes ``whole_chunk`` entries
(VERIFIED-eligible) from ``window`` entries (locators only, never
promote). ``entry_kind`` is in the canonical signing payload so the
classification is tamper-evident.

These tests assert the security property directly: bytes that didn't
land in the index as a whole-chunk authorized record can't promote
themselves to VERIFIED, regardless of how they line up with windows.
"""

from __future__ import annotations

from provenex.core.fingerprinter import Fingerprinter
from provenex.core.normalizer import TextNormalizer
from provenex.index.base import (
    ENTRY_KIND_WHOLE_CHUNK,
    ENTRY_KIND_WINDOW,
    VerificationOutcome,
)
from provenex.index.sqlite_index import SQLiteProvenanceIndex


SECRET = b"redteam-secret-32-bytes-or-better"


def _ingest_like_cli(idx: SQLiteProvenanceIndex, fp: Fingerprinter,
                     text: str, doc_id: str, authorized: bool = True) -> None:
    """Replicate the v0.8.0 CLI ingest semantics exactly.

    Whole-document hash gets entry_kind=whole_chunk. Every sliding
    window gets entry_kind=window. Window fingerprints are NEVER
    VERIFIED-eligible at verify time.
    """
    result = fp.fingerprint(text)
    whole_fp = fp.fingerprint_chunk(text)
    idx.add(
        fingerprint=whole_fp,
        document_id=doc_id,
        document_version=result.document_version,
        chunk_offset=0,
        chunk_length=len(text),
        authorized=authorized,
        entry_kind=ENTRY_KIND_WHOLE_CHUNK,
    )
    for window in result.fingerprints:
        if window.fingerprint == whole_fp:
            continue
        idx.add(
            fingerprint=window.fingerprint,
            document_id=doc_id,
            document_version=result.document_version,
            chunk_offset=window.offset,
            chunk_length=window.length,
            authorized=authorized,
            entry_kind=ENTRY_KIND_WINDOW,
        )


def test_single_window_substring_does_not_promote_to_verified():
    """The "one window from one authorized doc" case.

    Pre-v0.8.0 this returned VERIFIED. Now it must return UNVERIFIED.
    """
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    fp = Fingerprinter()
    doc = (
        "Section A: Confidentiality. The employee shall not disclose "
        "proprietary information to third parties. Section B: "
        "Non-compete. The employee agrees not to engage in competing "
        "business activity for 12 months following separation."
    )
    _ingest_like_cli(idx, fp, doc, doc_id="employment_contract")

    # Pick any indexed window and ask for its bytes as a whole chunk.
    normalized = TextNormalizer().normalize(doc).text
    full_result = fp.fingerprint(doc)
    # Take a middle window so we know it's not the whole-doc hash.
    window = full_result.fingerprints[len(full_result.fingerprints) // 2]
    window_text = normalized[window.offset : window.offset + window.length]
    assert window_text  # sanity
    window_chunk_fp = fp.fingerprint_chunk(window_text)
    assert window_chunk_fp == window.fingerprint  # window match exists

    outcome = idx.verify(window_chunk_fp)
    assert outcome == VerificationOutcome.UNVERIFIED, (
        f"window-aligned chunk must NOT promote to VERIFIED; got {outcome}. "
        f"This is the splice gap that v0.8.0 closes."
    )
    idx.close()


def test_spliced_windows_from_two_docs_are_unverified():
    """The headline red-team: concatenate authentic windows across two docs.

    The resulting chunk's whole-chunk SHA-256 does not match any
    single indexed window (different bytes), AND it does not match
    any whole-chunk entry (no operator ever ingested the splice as
    a chunk). The outcome must be UNVERIFIED.
    """
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    fp = Fingerprinter()

    doc_a = (
        "Document A header. Encryption keys MUST be rotated every 90 days. "
        "All keys are managed by the central KMS and access is logged. "
        "Backup keys are stored offline in a hardware security module. "
        "Long-running batch jobs that need access to the key material "
        "must request a short-lived service token from the KMS. Service "
        "tokens expire after one hour and are not refreshable without "
        "re-authentication against the central identity provider."
    )
    doc_b = (
        "Document B header. Approved contractors may access employee "
        "training records for engagement-relevant purposes only. "
        "Records are deleted within 30 days of engagement end. "
        "Contractors are NOT permitted to download bulk training datasets "
        "and may only retrieve individual records pertinent to a named "
        "active engagement. Access events are written to the central "
        "audit log with the contractor identity and the record identifier."
    )
    _ingest_like_cli(idx, fp, doc_a, doc_id="security_policy")
    _ingest_like_cli(idx, fp, doc_b, doc_id="contractor_policy")

    # Build a splice: a window from A + a window from B, concatenated.
    norm_a = TextNormalizer().normalize(doc_a).text
    norm_b = TextNormalizer().normalize(doc_b).text
    win_a = fp.fingerprint(doc_a).fingerprints[1]
    win_b = fp.fingerprint(doc_b).fingerprints[1]
    splice = (
        norm_a[win_a.offset : win_a.offset + win_a.length]
        + norm_b[win_b.offset : win_b.offset + win_b.length]
    )

    splice_fp = fp.fingerprint_chunk(splice)
    outcome = idx.verify(splice_fp)
    assert outcome == VerificationOutcome.UNVERIFIED, (
        f"spliced chunk from two authorized documents must NOT verify; "
        f"got {outcome}"
    )
    idx.close()


def test_whole_chunk_path_still_promotes_to_verified():
    """Sanity: the legitimate path still works.

    A chunk text the operator explicitly ingested as a whole chunk
    must still return VERIFIED.
    """
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    fp = Fingerprinter()
    chunk = "Approved chunk text the operator authorized as a discrete unit."
    chunk_fp = fp.fingerprint_chunk(chunk)
    chunk_version = "sha256:" + "0" * 64
    idx.add(
        fingerprint=chunk_fp,
        document_id="op_chunk_1",
        document_version=chunk_version,
        chunk_offset=0,
        chunk_length=len(chunk),
        entry_kind=ENTRY_KIND_WHOLE_CHUNK,
    )
    assert idx.verify(chunk_fp) == VerificationOutcome.VERIFIED
    idx.close()


def test_window_entry_is_signed_so_kind_is_tamper_evident():
    """Flipping a row's entry_kind from window to whole_chunk must TAMPER.

    The classification is part of the canonical signing payload, so a
    storage-layer attacker who flips the column without knowing the
    index secret cannot promote a locator row to VERIFIED-eligible.
    """
    idx = SQLiteProvenanceIndex(":memory:", signing_secret=SECRET)
    fp = Fingerprinter()
    doc = (
        "Operator did NOT authorize this 128-codepoint substring as a "
        "chunk; it only exists in the index because it appears inside a "
        "larger authorized document at a sliding-window offset. Padding "
        "to force enough windows: lorem ipsum dolor sit amet consectetur "
        "adipiscing elit sed do eiusmod tempor incididunt ut labore et "
        "dolore magna aliqua ut enim ad minim veniam quis nostrud."
    )
    _ingest_like_cli(idx, fp, doc, doc_id="locator_doc")

    # Find a window row and flip its kind to whole_chunk via raw SQL,
    # leaving the signature alone (an attacker without the secret).
    win_fp = fp.fingerprint(doc).fingerprints[1].fingerprint
    idx._conn.execute(
        "UPDATE fingerprints SET entry_kind = 'whole_chunk' "
        "WHERE fingerprint = ?",
        (win_fp,),
    )
    idx._conn.commit()

    outcome = idx.verify(win_fp)
    assert outcome == VerificationOutcome.TAMPERED, (
        f"flipping entry_kind out-of-band must trigger TAMPERED; got "
        f"{outcome}. The classification must be in the canonical signing "
        f"payload."
    )
    idx.close()
