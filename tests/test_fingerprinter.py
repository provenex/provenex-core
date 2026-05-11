"""Tests for the high-level fingerprinter."""

from __future__ import annotations

from provenex.core.fingerprinter import Fingerprinter, FingerprinterConfig
from provenex.core.normalizer import NormalizationOptions


def test_fingerprint_deterministic():
    fp = Fingerprinter()
    a = fp.fingerprint("The quick brown fox jumps over the lazy dog.")
    b = fp.fingerprint("The quick brown fox jumps over the lazy dog.")
    assert [f.fingerprint for f in a.fingerprints] == [
        f.fingerprint for f in b.fingerprints
    ]
    assert a.document_version == b.document_version


def test_fingerprint_records_normalization_applied():
    fp = Fingerprinter()
    result = fp.fingerprint("hello")
    assert "unicode_nfc" in result.normalization_applied


def test_fingerprint_chunk_matches_full_text_when_short():
    """fingerprint_chunk on short text == fingerprint() single window."""
    fp = Fingerprinter(
        FingerprinterConfig(window_size=1000, stride=500)  # huge window
    )
    text = "short"
    result = fp.fingerprint(text)
    single = fp.fingerprint_chunk(text)
    assert len(result.fingerprints) == 1
    assert result.fingerprints[0].fingerprint == single


def test_different_text_different_fingerprints():
    fp = Fingerprinter()
    a = fp.fingerprint("Hello world")
    b = fp.fingerprint("Goodbye world")
    a_set = {f.fingerprint for f in a.fingerprints}
    b_set = {f.fingerprint for f in b.fingerprints}
    # They might share some windows of overlap; require at least one different.
    assert a_set != b_set


def test_normalization_makes_equivalent_inputs_match():
    """Whitespace variations should produce identical fingerprints."""
    fp = Fingerprinter()
    a = fp.fingerprint("Hello   world").fingerprints[0].fingerprint
    b = fp.fingerprint("Hello world").fingerprints[0].fingerprint
    assert a == b


def test_document_version_changes_with_content():
    fp = Fingerprinter()
    a = fp.fingerprint("document v1 content")
    b = fp.fingerprint("document v2 content")
    assert a.document_version != b.document_version


def test_case_fold_off_by_default():
    fp = Fingerprinter()
    a = fp.fingerprint("Hello").fingerprints[0].fingerprint
    b = fp.fingerprint("hello").fingerprints[0].fingerprint
    assert a != b


def test_case_fold_enabled_unifies():
    fp = Fingerprinter(
        FingerprinterConfig(
            window_size=128,
            stride=64,
            normalization=NormalizationOptions(case_fold=True),
        )
    )
    a = fp.fingerprint("HELLO WORLD")
    b = fp.fingerprint("hello world")
    # Both should produce the same single window fingerprint.
    assert a.document_version == b.document_version


def test_empty_text_produces_no_fingerprints():
    fp = Fingerprinter()
    result = fp.fingerprint("")
    assert result.fingerprints == []
