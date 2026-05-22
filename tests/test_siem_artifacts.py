"""Regression tests for the shipped SIEM artifacts under siem/.

These aren't running KQL or SPL; they're catching the kinds of drift
the field-path audit caught (rules referencing receipt fields that
don't exist on schema 2.5.0). Each test loads the relevant file and
asserts (or refuses) specific substrings.

Update the allow/deny lists when the receipt schema changes or when
new artifacts ship.
"""

from __future__ import annotations

import json
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent
_SIEM_ROOT = _REPO_ROOT / "siem"


# Field paths that DO NOT exist on a schema 2.5.0 receipt and have
# caused SIEM rules to silently match zero rows in prior versions.
# Any SIEM artifact referencing these strings is a regression.
_DEAD_FIELD_PATHS = (
    # action.admission.decision was an early shape; current schema
    # joins actions[] to policy.tool_call_control.decisions[] by
    # action_index, with the decision living on the latter.
    "action.admission.decision",
    "actions{}.admission.decision",
    "actions[*].admission.decision",
    # request_binding holds only hashes; the verbatim request_context
    # lives at policy.access_control.decisions[].inputs.request_context.
    "request_binding.request_context",
    "request_binding_s).request_context",
)


def _all_siem_files():
    for p in _SIEM_ROOT.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".kql", ".conf", ".json", ".xml", ".md"}:
            yield p


def test_no_siem_artifact_references_dead_field_paths():
    """Catch the field-path drift that broke tool-call deny detection
    and jurisdiction grouping in earlier versions. Add new entries to
    _DEAD_FIELD_PATHS when removing a path from the schema.
    """
    offenders: list[tuple[Path, str, int]] = []
    for path in _all_siem_files():
        text = path.read_text(encoding="utf-8")
        for needle in _DEAD_FIELD_PATHS:
            if needle in text:
                # Find the first line number for the message.
                idx = text.find(needle)
                line_no = text.count("\n", 0, idx) + 1
                offenders.append((path.relative_to(_REPO_ROOT), needle, line_no))
    assert not offenders, (
        "SIEM artifacts reference dead receipt field paths "
        f"(would match zero rows on real receipts): "
        + "; ".join(
            f"{p}:{ln} -> {needle!r}" for p, needle, ln in offenders
        )
    )


def test_splunk_app_version_matches_provenex_release():
    """The Splunk app's version string is a coarse signal of support
    parity with the SDK. Bump it when bumping the package version.
    """
    import re

    app_conf = (_SIEM_ROOT / "splunk" / "default" / "app.conf").read_text()
    match = re.search(r"^version\s*=\s*(\S+)\s*$", app_conf, re.MULTILINE)
    assert match is not None, "splunk/default/app.conf missing 'version = ...' line"
    app_version = match.group(1)

    init = (_REPO_ROOT / "provenex" / "__init__.py").read_text()
    sdk_match = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.MULTILINE)
    assert sdk_match is not None, "provenex/__init__.py missing __version__"
    sdk_version = sdk_match.group(1)

    assert app_version == sdk_version, (
        f"Splunk app version {app_version!r} differs from SDK version "
        f"{sdk_version!r}; bump siem/splunk/default/app.conf when "
        f"releasing a new package version."
    )


def test_splunk_props_time_format_matches_receipt_timestamp_shape():
    """Receipts emit issued_at with millisecond precision
    (e.g. '2026-05-22T14:32:07.441Z'). Splunk TIME_FORMAT without
    %3N would parse the prefix and drop the milliseconds (or fail
    on stricter Splunk versions).
    """
    props_conf = (_SIEM_ROOT / "splunk" / "default" / "props.conf").read_text()
    # Both sourcetypes should specify millisecond precision.
    assert "%3N" in props_conf, (
        "splunk/default/props.conf TIME_FORMAT should include %3N for "
        "millisecond precision; receipts emit ISO-8601 with .nnnZ tail."
    )


def test_sentinel_analytics_rules_are_valid_json():
    """Catch JSON syntax regressions in Sentinel rule files."""
    for path in (_SIEM_ROOT / "sentinel" / "analytics_rules").glob("*.json"):
        text = path.read_text(encoding="utf-8")
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"{path.relative_to(_REPO_ROOT)} is not valid JSON: {exc}"
            ) from exc
