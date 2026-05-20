"""Tests for the policy simulator.

Acceptance criterion (Phase 4.1): given a directory of 100 receipts
and a policy where one rule is tightened, the simulator reports
exactly the set of decisions whose verdict flips.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("yaml")


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


_POLICY_OLD = """
version: 1
policy_id: hr-corpus-v1
access_control:
  rules:
    - name: eu-only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.pii_clean: true
      on_violation: deny
"""


_POLICY_TIGHTENED = """
version: 1
policy_id: hr-corpus-v2
access_control:
  rules:
    - name: eu-only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.pii_clean: true
      on_violation: deny
    - name: us-pii-gate          # New rule: tightens US too.
      when:
        request.jurisdiction: US
      require:
        chunk.metadata.pii_clean: true
      on_violation: deny
"""


def _write_yaml(tmp_path: Path, body: str, name: str) -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


def _make_receipt(
    receipt_id: str,
    jurisdiction: str,
    pii_clean: bool,
    decision: str,
) -> dict:
    """Build a minimal receipt with one access_control decision.

    The simulator only consults policy.access_control.decisions[i].inputs;
    everything else is unused.
    """
    return {
        "receipt_id": receipt_id,
        "policy": {
            "access_control": {
                "decisions": [
                    {
                        "chunk_fingerprint": "sha256:" + receipt_id.encode().hex().ljust(64, "0")[:64],
                        "decision": decision,
                        "rules_fired": [] if decision == "allow" else ["eu-only"],
                        "inputs_hash": "x",
                        "inputs": {
                            "chunk_metadata": {"pii_clean": pii_clean},
                            "request_context": {
                                "caller": {"id": "u1"},
                                "jurisdiction": jurisdiction,
                                "purpose": "research",
                                "timestamp": "2026-05-20T10:00:00Z",
                            },
                        },
                    }
                ]
            }
        },
    }


# --------------------------------------------------------------------------- #
# Tests                                                                       #
# --------------------------------------------------------------------------- #


def test_simulator_reports_exactly_the_flipped_decisions(tmp_path: Path):
    """100 receipts, one rule tightened, simulator finds exactly the US flips."""
    from provenex.policy.simulator import simulate
    from provenex.policy.unified import Policy

    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir()

    # 50 EU receipts (decisions already reflect the eu-only rule).
    # Mix of pii_clean true/false to exercise both branches.
    for i in range(50):
        pii = i % 2 == 0
        decision = "allow" if pii else "deny"
        receipt = _make_receipt(f"eu-{i:03d}", "EU", pii, decision)
        (rec_dir / f"eu-{i:03d}.json").write_text(json.dumps(receipt))

    # 50 US receipts. Old policy had no US rule, so all 50 are allow.
    # 30 of them are pii_clean=False — those should flip to deny.
    for i in range(50):
        pii = i % 5 == 0  # 10/50 are pii_clean
        receipt = _make_receipt(f"us-{i:03d}", "US", pii, "allow")
        (rec_dir / f"us-{i:03d}.json").write_text(json.dumps(receipt))

    new_policy = Policy.from_yaml(str(_write_yaml(tmp_path, _POLICY_TIGHTENED, "new.yaml")))
    report = simulate(new_policy, rec_dir)

    assert report.receipts_examined == 100
    assert report.decisions_examined == 100
    assert report.decisions_skipped_redacted == 0
    # The 40 US receipts with pii_clean=False flip allow -> deny.
    assert len(report.allow_to_deny) == 40
    assert len(report.deny_to_allow) == 0
    # All flips are US.
    flip_ids = {f.receipt_id for f in report.allow_to_deny}
    assert flip_ids == {f"us-{i:03d}" for i in range(50) if i % 5 != 0}


def test_simulator_skips_redacted_decisions(tmp_path: Path):
    """If a receipt redacts inputs, the simulator records it and moves on."""
    from provenex.policy.simulator import simulate
    from provenex.policy.unified import Policy

    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir()
    receipt = _make_receipt("r1", "EU", True, "allow")
    receipt["policy"]["access_control"]["decisions"][0]["inputs"] = None
    (rec_dir / "r1.json").write_text(json.dumps(receipt))

    new_policy = Policy.from_yaml(
        str(_write_yaml(tmp_path, _POLICY_TIGHTENED, "new.yaml"))
    )
    report = simulate(new_policy, rec_dir)
    assert report.receipts_examined == 1
    assert report.decisions_skipped_redacted == 1
    assert report.flips == []


def test_simulator_refuses_policy_without_access_control(tmp_path: Path):
    """If the proposed policy has no access_control, nothing to simulate."""
    from provenex.policy.simulator import simulate
    from provenex.policy.unified import Policy

    empty_policy_path = _write_yaml(
        tmp_path,
        "version: 1\npolicy_id: bare\n",
        "empty.yaml",
    )
    new_policy = Policy.from_yaml(str(empty_policy_path))
    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir()
    with pytest.raises(ValueError, match="access_control"):
        simulate(new_policy, rec_dir)


def test_simulator_emits_json_and_human(tmp_path: Path):
    """Cover the dict + markdown serializers."""
    from provenex.policy.simulator import simulate
    from provenex.policy.unified import Policy

    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir()
    rec = _make_receipt("us-1", "US", False, "allow")
    (rec_dir / "us-1.json").write_text(json.dumps(rec))

    new_policy = Policy.from_yaml(
        str(_write_yaml(tmp_path, _POLICY_TIGHTENED, "new.yaml"))
    )
    report = simulate(new_policy, rec_dir)

    body = report.to_dict()
    assert body["flips_total"] == 1
    assert body["flips_allow_to_deny"] == 1
    assert body["flips"][0]["chunk_fingerprint"].startswith("sha256:")

    human = report.to_human_diff()
    assert "Policy simulation diff" in human
    assert "allow -> deny" in human


def test_cli_subcommand_runs(tmp_path: Path):
    """Smoke test: `provenex policy simulate` returns 0 and emits JSON."""
    import io
    from contextlib import redirect_stdout

    from provenex.cli.main import main

    rec_dir = tmp_path / "receipts"
    rec_dir.mkdir()
    (rec_dir / "us-1.json").write_text(
        json.dumps(_make_receipt("us-1", "US", False, "allow"))
    )
    policy_path = _write_yaml(tmp_path, _POLICY_TIGHTENED, "new.yaml")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main([
            "policy", "simulate",
            "--policy", str(policy_path),
            "--receipts", str(rec_dir),
        ])
    assert rc == 0
    out = buf.getvalue()
    payload = json.loads(out)
    assert payload["flips_total"] == 1
    assert payload["flips"][0]["kind"] == "allow_to_deny"
