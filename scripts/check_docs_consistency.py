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

import os
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


def _check_helm_chart(schema: str, issuer: str) -> List[str]:
    """Helm chart appVersion + container image tag must match ISSUER suffix."""
    want = _issuer_version(issuer)
    problems: List[str] = []

    chart_path = REPO / "deploy" / "helm" / "provenex-server" / "Chart.yaml"
    if chart_path.exists():
        text = chart_path.read_text()
        m = re.search(r'^appVersion:\s*"([^"]+)"', text, re.MULTILINE)
        if m is None:
            problems.append(
                "deploy/helm/provenex-server/Chart.yaml: no `appVersion: \"...\"` line"
            )
        elif m.group(1) != want:
            problems.append(
                f"deploy/helm/provenex-server/Chart.yaml: appVersion=\"{m.group(1)}\" "
                f"disagrees with receipt.py ISSUER version suffix \"{want}\""
            )

    values_path = REPO / "deploy" / "helm" / "provenex-server" / "values.yaml"
    if values_path.exists():
        text = values_path.read_text()
        # image.tag is nested under image:; match a 'tag: "X.Y.Z"' line that
        # follows an 'image:' block within 5 lines.
        m = re.search(
            r'image:\s*\n(?:\s+(?:#.*|\w+:.*)\n){0,20}\s+tag:\s*"([^"]+)"',
            text,
        )
        if m is None:
            problems.append(
                "deploy/helm/provenex-server/values.yaml: no `image:` block "
                "with a tag: \"X.Y.Z\" line found"
            )
        elif m.group(1) != want:
            problems.append(
                f"deploy/helm/provenex-server/values.yaml: image.tag="
                f"\"{m.group(1)}\" disagrees with receipt.py ISSUER "
                f"version suffix \"{want}\""
            )

    return problems


def _check_deploy_manifests(schema: str, issuer: str) -> List[str]:
    """Container image tags in deploy/manifests + deploy/operator must match."""
    want = _issuer_version(issuer)
    problems: List[str] = []

    manifests = [
        REPO / "deploy" / "manifests" / "provenex-server.yaml",
        REPO / "deploy" / "operator" / "operator.yaml",
    ]
    for path in manifests:
        if not path.exists():
            continue
        text = path.read_text()
        # image: [<registry>/]provenex/provenex-XXX:Y.Y.Y -- accepts a
        # leading registry prefix (e.g., ghcr.io/) so the GHCR-published
        # server image and the still-private operator image both lint.
        matches = re.findall(
            r'image:\s*(?:[\w.-]+/)?provenex/provenex-[\w-]+:(\S+)', text
        )
        if not matches:
            # Manifest exists but has no provenex/provenex-* image. Not a
            # drift, just a manifest we do not lint. Skip.
            continue
        rel = path.relative_to(REPO)
        for got in matches:
            if got != want:
                problems.append(
                    f"{rel}: image tag \"{got}\" disagrees with "
                    f"receipt.py ISSUER version suffix \"{want}\""
                )
    return problems


def _check_security_md(schema: str, issuer: str) -> List[str]:
    """SECURITY.md supported-versions table must mark X.Y.x as current."""
    want = _issuer_version(issuer)
    parts = want.split(".")
    if len(parts) < 2:
        return []  # malformed version; not our problem here
    minor = f"{parts[0]}.{parts[1]}.x"

    path = REPO / "SECURITY.md"
    if not path.exists():
        return []
    text = path.read_text()

    # Look for the '(current minor) | Yes' row in the supported-versions
    # table. Captures the version cell before the '(current minor)' tag.
    m = re.search(
        r'\|\s*([\d.x]+)\s*\(current minor\)\s*\|\s*Yes\s*\|',
        text,
    )
    if m is None:
        return [
            "SECURITY.md: supported-versions table missing the "
            "'(current minor) | Yes' row"
        ]
    if m.group(1) != minor:
        return [
            f"SECURITY.md: supported-versions table marks \"{m.group(1)}\" "
            f"as the current minor, but receipt.py ISSUER suggests "
            f"\"{minor}\""
        ]
    return []


def _check_openapi(schema: str, issuer: str) -> List[str]:
    """docs/openapi/openapi.json info.version must match ISSUER suffix."""
    want = _issuer_version(issuer)
    path = REPO / "docs" / "openapi" / "openapi.json"
    if not path.exists():
        return []
    text = path.read_text()
    # Find the info block's version. info.version appears within
    # "info": { ... "version": "X.Y.Z" ... }.
    m = re.search(
        r'"info":\s*\{[^}]*"version":\s*"([^"]+)"',
        text,
    )
    if m is None:
        return [
            "docs/openapi/openapi.json: no `info.version` field found"
        ]
    if m.group(1) != want:
        return [
            f"docs/openapi/openapi.json: info.version=\"{m.group(1)}\" "
            f"disagrees with receipt.py ISSUER version suffix \"{want}\". "
            f"Regenerate via the create_app().openapi() call in "
            f"provenex/server/app.py."
        ]
    return []


# ---------------------------------------------------------------------------
# Local-link check
# ---------------------------------------------------------------------------

# Markdown link extractor. Matches both `[text](path)` and `![alt](path)`.
# Captures the link target up to the first whitespace or closing paren.
# Reference-style links (`[text][ref]`) are intentionally not matched;
# they resolve to a separate `[ref]: url` definition that the regex
# would otherwise misread as a link target.
_MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)\)")

# Dirs we never walk when collecting markdown files. `bench/wiki_cache`
# is a corpus of plain-text Wikipedia articles used by the bench
# harness; it has no documentation. The rest are build / VCS / IDE
# scratch space.
_LINK_CHECK_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "wiki_cache",
    "provenex_core.egg-info",
}

# Link targets that should be ignored. External URLs, mail/tel/ftp,
# and empty anchors are not file-existence checks.
_LINK_SKIP_PREFIXES = (
    "http://",
    "https://",
    "mailto:",
    "tel:",
    "ftp://",
    "#",
)


def _check_markdown_links(schema: str, issuer: str) -> List[str]:
    """Every relative link in every committed Markdown file must point
    to a path that exists.

    External URLs, mail/tel/ftp, and pure anchors are skipped. Anchor
    and query-string suffixes on a path are stripped before resolution.
    Links that resolve outside the repo (FS escapes) are skipped.

    The purpose of this check is to catch the failure mode where a
    document references a sibling doc, runbook, or example by relative
    path, but the target was renamed, moved, or never shipped. The
    docs-consistency lint already enforces schema and version anchors;
    this check enforces that everything we point readers at actually
    exists.
    """
    problems: List[str] = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        # Prune in-place so os.walk does not descend into skipped trees.
        dirnames[:] = [d for d in dirnames if d not in _LINK_CHECK_SKIP_DIRS]
        for fn in filenames:
            if not fn.endswith(".md"):
                continue
            path = Path(dirpath) / fn
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for m in _MD_LINK_RE.finditer(text):
                target = m.group(1).strip()
                if not target or target.startswith(_LINK_SKIP_PREFIXES):
                    continue
                # Strip #anchor and ?query before existence-checking.
                bare = target.split("#", 1)[0].split("?", 1)[0]
                if not bare:
                    continue
                try:
                    resolved = (path.parent / bare).resolve()
                except (OSError, RuntimeError):
                    continue
                # Defensive: ignore paths that escape the repo.
                try:
                    resolved.relative_to(REPO)
                except ValueError:
                    continue
                if not resolved.exists():
                    rel_doc = path.relative_to(REPO)
                    problems.append(
                        f"{rel_doc}: broken local link to {target!r}"
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
    ("deploy/helm/provenex-server/", _check_helm_chart),
    ("deploy/manifests/ + deploy/operator/", _check_deploy_manifests),
    ("SECURITY.md", _check_security_md),
    ("docs/openapi/openapi.json", _check_openapi),
    ("markdown local links (every .md file)", _check_markdown_links),
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
