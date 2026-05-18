#!/usr/bin/env python3
"""Catch schema-version / issuer drift across docs.

Treats ``provenex/core/receipt.py``'s ``SCHEMA_VERSION`` and ``ISSUER``
as the source of truth. Verifies every current-schema mention in the
README, the receipt-format spec, the OCSF mapping doc, the package
``__version__``, and ``pyproject.toml`` agrees with them.

Distinguishes two classes of version mention:

    * **Current-schema / current-issuer mentions** - must agree with
      the source of truth (e.g. the README headline receipt's
      ``"schema_version": "..."``, the receipt-format header's "the
      current schema version is ..."). These are what this lint
      enforces.
    * **Landing-version markers** - "(schema 2.0.0+)" next to a
      feature description, recording when that feature first
      appeared. These are stable history, NOT current-state claims,
      and are deliberately left alone by this lint.

Exit code:
    0  every current-state mention matches the source of truth.
    1  one or more drifts detected; a structured diff is printed to
       stderr.

Designed to run pre-release (``python scripts/check_docs_consistency.py``)
and from CI (covered by ``tests/test_docs_consistency.py``).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Tuple


REPO = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Source of truth
# ---------------------------------------------------------------------------

def _read_source_of_truth() -> Tuple[str, str]:
    """Return ``(schema_version, issuer)`` from provenex/core/receipt.py."""
    text = (REPO / "provenex" / "core" / "receipt.py").read_text()
    m = re.search(r'^SCHEMA_VERSION\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m is None:
        raise RuntimeError("provenex/core/receipt.py: SCHEMA_VERSION not found")
    schema = m.group(1)
    m = re.search(r'^ISSUER\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m is None:
        raise RuntimeError("provenex/core/receipt.py: ISSUER not found")
    issuer = m.group(1)
    return schema, issuer


def _issuer_version(issuer: str) -> str:
    """Extract X.Y.Z from ``provenex-core/X.Y.Z``."""
    if "/" not in issuer:
        raise RuntimeError(f"ISSUER {issuer!r} has no '/' separator")
    return issuer.split("/", 1)[1]


# ---------------------------------------------------------------------------
# Per-file checks
# ---------------------------------------------------------------------------

def _check_pyproject(schema: str, issuer: str) -> List[str]:
    text = (REPO / "pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m is None:
        return ["pyproject.toml: no `version = \"...\"` line found"]
    got = m.group(1)
    want = _issuer_version(issuer)
    if got != want:
        return [
            f"pyproject.toml: version=\"{got}\" disagrees with "
            f"receipt.py ISSUER version suffix \"{want}\""
        ]
    return []


def _check_init_version(schema: str, issuer: str) -> List[str]:
    text = (REPO / "provenex" / "__init__.py").read_text()
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m is None:
        return ["provenex/__init__.py: no `__version__ = \"...\"` line found"]
    got = m.group(1)
    want = _issuer_version(issuer)
    if got != want:
        return [
            f"provenex/__init__.py: __version__=\"{got}\" disagrees with "
            f"receipt.py ISSUER version suffix \"{want}\""
        ]
    return []


def _check_readme(schema: str, issuer: str) -> List[str]:
    """README.md current-state mentions.

    Validates exactly three places:

        * Headline JSON receipt's ``"schema_version": "..."``
        * Headline JSON receipt's ``"issuer": "..."``
        * Links section's "receipt schema X.Y.Z specification (current)"

    Does NOT validate inline mentions like "v0.8.0 added X" - those are
    stable landing-version markers.
    """
    text = (REPO / "README.md").read_text()
    problems: List[str] = []

    # The headline JSON receipt has exactly one schema_version + issuer
    # pair. Multiple matches would mean someone added another receipt
    # example without updating; treat that as an explicit drift.
    sv_matches = re.findall(r'"schema_version":\s*"([^"]+)"', text)
    if not sv_matches:
        problems.append("README.md: no \"schema_version\": \"...\" found")
    for got in sv_matches:
        if got != schema:
            problems.append(
                f"README.md: receipt example has "
                f"\"schema_version\": \"{got}\" but source of truth is \"{schema}\""
            )

    issuer_matches = re.findall(r'"issuer":\s*"([^"]+)"', text)
    if not issuer_matches:
        problems.append("README.md: no \"issuer\": \"...\" found")
    for got in issuer_matches:
        if got != issuer:
            problems.append(
                f"README.md: receipt example has "
                f"\"issuer\": \"{got}\" but source of truth is \"{issuer}\""
            )

    # The Links section's "(current)" anchor.
    m = re.search(r'receipt schema (\d+\.\d+\.\d+) specification \(current\)', text)
    if m is None:
        problems.append(
            "README.md: missing 'receipt schema X.Y.Z specification (current)' "
            "in the Links section"
        )
    elif m.group(1) != schema:
        problems.append(
            f"README.md Links section: 'receipt schema {m.group(1)} "
            f"specification (current)' but source of truth is \"{schema}\""
        )

    return problems


def _check_receipt_format(schema: str, issuer: str) -> List[str]:
    """receipt_format.md current-state mentions.

    Validates:

        * Header's "current schema version is **`X.Y.Z`**"
        * The example JSON's ``"schema_version": "..."``
        * The example JSON's ``"issuer": "..."``
        * Field table's "Always `X.Y.Z` for receipts produced by this SDK"
        * Schema-history table has a row for the current SCHEMA_VERSION
    """
    text = (REPO / "docs" / "receipt_format.md").read_text()
    problems: List[str] = []

    # Header
    m = re.search(r'current schema version is \*\*`([^`]+)`\*\*', text)
    if m is None:
        problems.append(
            "docs/receipt_format.md: missing 'current schema version is `X.Y.Z`' header"
        )
    elif m.group(1) != schema:
        problems.append(
            f"docs/receipt_format.md header: current schema is \"{m.group(1)}\" "
            f"but source of truth is \"{schema}\""
        )

    # Example schema_version
    for got in re.findall(r'"schema_version":\s*"([^"]+)"', text):
        if got != schema:
            problems.append(
                f"docs/receipt_format.md example: \"schema_version\": \"{got}\" "
                f"!= source of truth \"{schema}\""
            )

    # Example issuer - tolerates the example using a slightly older
    # issuer version IF the schema doesn't change. The point of the
    # example is to show schema shape, not advertise the latest binary.
    # But for current-state hygiene we still want it aligned.
    for got in re.findall(r'"issuer":\s*"([^"]+)"', text):
        if got != issuer:
            problems.append(
                f"docs/receipt_format.md example: \"issuer\": \"{got}\" "
                f"!= source of truth \"{issuer}\""
            )

    # Field table
    m = re.search(
        r'Always `(\d+\.\d+\.\d+)` for receipts produced by this SDK', text
    )
    if m is None:
        problems.append(
            "docs/receipt_format.md: field table missing 'Always `X.Y.Z` "
            "for receipts produced by this SDK' line"
        )
    elif m.group(1) != schema:
        problems.append(
            f"docs/receipt_format.md field table: 'Always `{m.group(1)}`' "
            f"!= source of truth \"{schema}\""
        )

    # Schema-history table row for the current SCHEMA_VERSION.
    if not re.search(
        r'^\|\s*`' + re.escape(schema) + r'`\s*\|',
        text, re.MULTILINE,
    ):
        problems.append(
            f"docs/receipt_format.md: schema-history table has no row for "
            f"the current SCHEMA_VERSION \"{schema}\""
        )

    return problems


def _check_ocsf_mapping(schema: str, issuer: str) -> List[str]:
    """ocsf_mapping.md has an embedded example with product.version and
    feature.version that map to the current binary + schema."""
    text = (REPO / "docs" / "ocsf_mapping.md").read_text()
    problems: List[str] = []
    want_bin = _issuer_version(issuer)

    # The example JSON inside ocsf_mapping.md uses these patterns:
    #     "version": "0.8.2",                                  (product)
    #     "feature": { "name": "provenex-receipt", "version": "2.4.0" }
    for got in re.findall(
        r'"feature":\s*\{\s*"name":\s*"provenex-receipt",\s*'
        r'"version":\s*"([^"]+)"\s*\}',
        text,
    ):
        if got != schema:
            problems.append(
                f"docs/ocsf_mapping.md: feature provenex-receipt version "
                f"=\"{got}\" but source of truth schema is \"{schema}\""
            )

    # The product.version is harder to anchor unambiguously; check via
    # the "name": "provenex-core" sibling key context.
    for m in re.finditer(
        r'"name":\s*"provenex-core",\s*\n?\s*"version":\s*"([^"]+)"',
        text,
    ):
        got = m.group(1)
        if got != want_bin:
            problems.append(
                f"docs/ocsf_mapping.md: provenex-core product version "
                f"=\"{got}\" but source of truth issuer suffix is \"{want_bin}\""
            )
    # Some examples place version on the line above name; handle that
    # ordering too.
    for m in re.finditer(
        r'"version":\s*"([^"]+)",\s*\n\s*"vendor_name":\s*"Provenex"',
        text,
    ):
        got = m.group(1)
        if got != want_bin:
            problems.append(
                f"docs/ocsf_mapping.md: Provenex vendor block product "
                f"version=\"{got}\" but source of truth issuer suffix "
                f"is \"{want_bin}\""
            )

    return problems


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

CHECKS = [
    ("pyproject.toml", _check_pyproject),
    ("provenex/__init__.py", _check_init_version),
    ("README.md", _check_readme),
    ("docs/receipt_format.md", _check_receipt_format),
    ("docs/ocsf_mapping.md", _check_ocsf_mapping),
]


def run() -> List[str]:
    """Run every check. Returns a flat list of drift messages."""
    schema, issuer = _read_source_of_truth()
    all_problems: List[str] = []
    for _, fn in CHECKS:
        all_problems.extend(fn(schema, issuer))
    return all_problems


def main(argv: List[str] = None) -> int:
    schema, issuer = _read_source_of_truth()
    print(
        f"source of truth: provenex/core/receipt.py\n"
        f"  SCHEMA_VERSION = {schema}\n"
        f"  ISSUER         = {issuer}",
        file=sys.stderr,
    )
    problems = run()
    if problems:
        print("", file=sys.stderr)
        print(
            f"FAIL: {len(problems)} drift(s) detected. The current-state "
            f"mentions below do NOT match the source of truth above. Either "
            f"update receipt.py and bump deliberately, or update the doc to "
            f"match.",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("", file=sys.stderr)
        return 1
    print("", file=sys.stderr)
    print(
        f"OK: {len(CHECKS)} file(s) checked; every current-state mention "
        f"agrees with the source of truth.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
