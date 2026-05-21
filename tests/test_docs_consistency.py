"""Pytest wrapper around scripts/check_docs_consistency.py.

Runs the same logic the standalone lint runs, but inside the test
suite so CI catches schema-version / issuer drift the moment it lands.
Standalone usage (``python scripts/check_docs_consistency.py``) remains
the operator-facing entry point; this is the structural guard for
contributors.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_docs_consistency.py"


@pytest.fixture(scope="module")
def lint_module():
    """Import the script as a module so we can call its functions
    directly without spawning a subprocess."""
    spec = importlib.util.spec_from_file_location(
        "check_docs_consistency", SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_source_of_truth_present(lint_module):
    """The lint must be able to parse SCHEMA_VERSION + ISSUER from
    provenex/core/receipt.py. If this fails the whole lint is broken."""
    schema, issuer = lint_module._read_source_of_truth()
    assert schema, "SCHEMA_VERSION must be a non-empty string"
    assert issuer.startswith("provenex-core/"), (
        f"ISSUER must start with 'provenex-core/'; got {issuer!r}"
    )


def test_no_drift_across_docs(lint_module):
    """The structural guard.

    Every current-state mention of the schema version / issuer in
    user-facing docs MUST match the source of truth in
    provenex/core/receipt.py. If this test fails, the failure message
    names the file, the value found, and the value expected - paste
    it into a fix PR.

    Landing-version markers like "(schema 2.0.0+)" next to a feature
    description are stable history and are NOT checked here; only
    'current schema is X', 'always X for receipts produced by this
    SDK', and similar present-tense statements are checked.
    """
    problems = lint_module.run()
    if problems:
        msg = (
            "Schema-version / issuer drift detected across user-facing docs. "
            "The source of truth is provenex/core/receipt.py's "
            "SCHEMA_VERSION and ISSUER constants. Fix each line below to "
            "match the source of truth, OR bump the source of truth and "
            "every doc together:\n\n"
            + "\n".join(f"  - {p}" for p in problems)
        )
        pytest.fail(msg)


def test_lint_catches_simulated_drift(lint_module, monkeypatch):
    """If the source of truth bumps without docs following, the lint
    must surface drift. Each check function must return at least one
    problem when the simulated source of truth disagrees with the
    on-disk values.

    Guards against the failure mode where a check function is added
    but its regex never matches anything on disk; the function would
    return [] both before and after a real bump, defeating the
    structural guarantee. This test runs every check against a
    drifted source-of-truth and asserts each one fires.
    """
    real_schema, real_issuer = lint_module._read_source_of_truth()
    # Force the lint to think the source of truth is far ahead of
    # what's on disk. Schema bump: 2.4.0 -> 9.9.9. Issuer bump:
    # 0.9.0 -> 99.99.99.
    drifted_schema = "9.9.9"
    drifted_issuer = "provenex-core/99.99.99"

    # Run every check individually with the drifted source of truth
    # and confirm each returns at least one problem.
    for name, fn in lint_module.CHECKS:
        problems = fn(drifted_schema, drifted_issuer)
        # Some checks (deploy_manifests, openapi, security_md) skip when
        # their target file is missing; we tolerate empty results in that
        # case but flag if the targets exist and the check ignored them.
        if not problems and not _check_targets_missing(lint_module, name):
            pytest.fail(
                f"check for {name!r} returned no problems against a "
                f"drifted source of truth (schema={drifted_schema}, "
                f"issuer={drifted_issuer}); its regex likely does not "
                f"match the on-disk content. Either fix the regex or "
                f"remove the check."
            )


def _check_targets_missing(lint_module, check_name: str) -> bool:
    """True if a check's target files do not exist (clean skip is allowed)."""
    repo = lint_module.REPO
    target_map = {
        "deploy/helm/provenex-server/": [
            "deploy/helm/provenex-server/Chart.yaml",
            "deploy/helm/provenex-server/values.yaml",
        ],
        "deploy/manifests/ + deploy/operator/": [
            "deploy/manifests/provenex-server.yaml",
            "deploy/operator/operator.yaml",
        ],
        "SECURITY.md": ["SECURITY.md"],
        "docs/openapi/openapi.json": ["docs/openapi/openapi.json"],
    }
    targets = target_map.get(check_name)
    if targets is None:
        return False
    return not any((repo / t).exists() for t in targets)
