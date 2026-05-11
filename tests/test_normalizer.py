"""Tests for the text normalization pipeline."""

from __future__ import annotations

from provenex.core.normalizer import NormalizationOptions, TextNormalizer


def test_default_options_apply_nfc_and_whitespace():
    n = TextNormalizer()
    result = n.normalize("Hello   world\n\nfoo")
    assert result.text == "Hello world foo"
    assert "unicode_nfc" in result.applied
    assert "whitespace_collapse" in result.applied


def test_default_does_not_case_fold():
    n = TextNormalizer()
    result = n.normalize("Hello World")
    assert result.text == "Hello World"
    assert "case_fold" not in result.applied


def test_case_fold_when_enabled():
    n = TextNormalizer(NormalizationOptions(case_fold=True))
    result = n.normalize("Hello WORLD")
    assert result.text == "hello world"
    assert "case_fold" in result.applied


def test_nfc_unifies_precomposed_vs_decomposed():
    # 'é' as one codepoint vs 'e' + combining acute. NFC should equalize.
    precomposed = "caf\u00e9"
    decomposed = "cafe\u0301"
    n = TextNormalizer()
    a = n.normalize(precomposed).text
    b = n.normalize(decomposed).text
    assert a == b


def test_strip_zero_width():
    n = TextNormalizer()
    # ZWSP between letters should be removed.
    result = n.normalize("ev\u200bil")
    assert result.text == "evil"
    assert "strip_zero_width" in result.applied


def test_disabling_zero_width_strip_preserves_them():
    n = TextNormalizer(
        NormalizationOptions(strip_zero_width=False, whitespace_collapse=False)
    )
    result = n.normalize("ev\u200bil")
    assert "\u200b" in result.text


def test_normalization_is_deterministic():
    n = TextNormalizer()
    text = "  Hello\tWORLD\n\nfoo bar  "
    assert n.normalize(text).text == n.normalize(text).text


def test_empty_string():
    n = TextNormalizer()
    result = n.normalize("")
    assert result.text == ""


def test_only_whitespace_collapses_to_empty():
    n = TextNormalizer()
    result = n.normalize("   \n\t  \n  ")
    assert result.text == ""
