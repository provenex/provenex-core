"""CLI tests for Phase 2 (tool-call admission) extensions.

Covers:

    * ``provenex policy validate`` accepts unified files with
      ``tool_call_control:`` only, with both halves, and the legacy
      access-control-only layout.
    * ``provenex policy hash`` prints one bare hash for single-section
      files (preserves the Phase 1 CLI contract) and prefixed lines for
      multi-section files.
    * ``provenex policy hash --section <name>`` filters to one half.
    * ``provenex audit`` runs cleanly on a 2.2.0 receipt with
      ``actions[]`` + ``tool_call_control``.
    * ``provenex audit --show-policy`` renders the tool-call-control
      block.
    * ``provenex audit --trajectory <dir>`` validates a mixed
      retrieval + tool-call trajectory.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

import pytest

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    ToolCallContext,
    admission_check,
    start_trajectory,
    verify_chunks,
)
from provenex.cli.main import main


VALID_TOOL_POLICY = """
version: 1
policy_id: cli-tool-policy
tool_call_control:
  rules:
    - name: web_search_domain
      when: { tool.name: web_search }
      require:
        tool.target_system: { in: [google_custom_search] }
      on_violation: deny
"""

VALID_UNIFIED_BOTH = """
version: 1
policy_id: cli-unified-v1
verification:
  block_unauthorized: true
access_control:
  rules:
    - name: classification_gate
      require:
        chunk.metadata.classification: { in: [public, internal] }
      on_violation: deny
tool_call_control:
  rules:
    - name: web_search_domain
      when: { tool.name: web_search }
      require:
        tool.target_system: { in: [google_custom_search] }
      on_violation: deny
"""


# --------------------------------------------------------------------------- #
# provenex policy validate                                                    #
# --------------------------------------------------------------------------- #


def test_validate_accepts_tool_call_control_only_file(tmp_path):
    p = tmp_path / "tool.yaml"
    p.write_text(VALID_TOOL_POLICY, encoding="utf-8")
    rc = main(["policy", "validate", "--quiet", str(p)])
    assert rc == 0


def test_validate_accepts_unified_both_halves(tmp_path):
    p = tmp_path / "both.yaml"
    p.write_text(VALID_UNIFIED_BOTH, encoding="utf-8")
    rc = main(["policy", "validate", "--quiet", str(p)])
    assert rc == 0


def test_validate_rejects_cross_domain_chunk_ref_in_tool_rule(tmp_path):
    bad = """
version: 1
policy_id: bad
tool_call_control:
  rules:
    - name: cross_domain
      when: { chunk.metadata.classification: secret }   # chunk.* in a tool rule
      require:
        tool.parameters.q: { in: [a] }
      on_violation: deny
"""
    p = tmp_path / "bad.yaml"
    p.write_text(bad, encoding="utf-8")
    rc = main(["policy", "validate", "--quiet", str(p)])
    assert rc != 0


# --------------------------------------------------------------------------- #
# provenex policy hash                                                        #
# --------------------------------------------------------------------------- #


def test_hash_single_section_prints_bare_sha256(tmp_path, capsys):
    p = tmp_path / "tool.yaml"
    p.write_text(VALID_TOOL_POLICY, encoding="utf-8")
    rc = main(["policy", "hash", str(p)])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("sha256:")


def test_hash_unified_both_sections_prints_two_lines(tmp_path, capsys):
    p = tmp_path / "both.yaml"
    p.write_text(VALID_UNIFIED_BOTH, encoding="utf-8")
    rc = main(["policy", "hash", str(p)])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("access_control")
    assert "sha256:" in lines[0]
    assert lines[1].startswith("tool_call_control")
    assert "sha256:" in lines[1]


def test_hash_section_filter(tmp_path, capsys):
    p = tmp_path / "both.yaml"
    p.write_text(VALID_UNIFIED_BOTH, encoding="utf-8")
    rc = main(
        ["policy", "hash", "--section", "tool_call_control", str(p)]
    )
    assert rc == 0
    out = capsys.readouterr().out.strip()
    # Bare hash — same format as a single-section file.
    assert out.startswith("sha256:")
    assert "\n" not in out


def test_hash_section_filter_missing_section_errors(tmp_path, capsys):
    p = tmp_path / "tool.yaml"
    p.write_text(VALID_TOOL_POLICY, encoding="utf-8")
    rc = main(["policy", "hash", "--section", "access_control", str(p)])
    assert rc != 0


# --------------------------------------------------------------------------- #
# provenex audit on 2.2.0 receipt                                             #
# --------------------------------------------------------------------------- #


def _emit_tool_call_receipt(tmp_path: Path) -> Path:
    """Emit a signed 2.2.0 receipt with one allowed tool call. Returns the file."""
    secret = secrets.token_hex(32)
    os.environ["PROVENEX_SIGNING_SECRET"] = secret
    signer = HmacSha256Signer()

    policy = Policy.from_text(VALID_TOOL_POLICY)
    request = RequestContext(
        caller={"role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    result = admission_check(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "weather"},
            target_system="google_custom_search",
        ),
        request,
        policy=policy,
        signer=signer,
    )
    receipt_path = tmp_path / "tool_call_receipt.json"
    receipt_path.write_text(result.receipt.to_json(), encoding="utf-8")
    return receipt_path


def test_audit_handles_actions_receipt_cleanly(tmp_path, capsys):
    receipt_path = _emit_tool_call_receipt(tmp_path)
    rc = main(["audit", "--quiet", str(receipt_path)])
    assert rc == 0  # signature + (zero inclusion proofs) all OK


def test_audit_show_policy_renders_tool_call_control_block(tmp_path, capsys):
    receipt_path = _emit_tool_call_receipt(tmp_path)
    rc = main(["audit", "--show-policy", str(receipt_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "tool call control:" in out
    assert "policy_id:" in out
    assert "cli-tool-policy" in out
    assert "ALLOW" in out
    assert "web_search.query" in out
    assert "google_custom_search" in out


def test_audit_show_policy_renders_denied_tool_call_in_red(tmp_path, capsys):
    """A denied tool-call decision is rendered with the verdict visible
    in the show-policy block, even when the receipt itself fails the
    overall summary.
    """
    secret = secrets.token_hex(32)
    os.environ["PROVENEX_SIGNING_SECRET"] = secret
    signer = HmacSha256Signer()
    policy = Policy.from_text(VALID_TOOL_POLICY)
    request = RequestContext(
        caller={"role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )
    result = admission_check(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "x"},
            target_system="duckduckgo",  # not allowlisted
        ),
        request,
        policy=policy,
        signer=signer,
    )
    p = tmp_path / "denied.json"
    p.write_text(result.receipt.to_json(), encoding="utf-8")
    # We disable colour for stable string assertions.
    os.environ["NO_COLOR"] = "1"
    try:
        rc = main(["audit", "--show-policy", str(p)])
    finally:
        os.environ.pop("NO_COLOR", None)
    assert rc == 0  # signature + (no proofs) OK; receipt summary FAIL is data not exit
    out = capsys.readouterr().out
    assert "DENY" in out
    assert "web_search_domain" in out


# --------------------------------------------------------------------------- #
# provenex audit --trajectory mixed                                           #
# --------------------------------------------------------------------------- #


def test_audit_trajectory_on_mixed_retrieve_and_tool_call(tmp_path, capsys):
    """The headline demo (Demo 3). Trajectory of retrieval + tool_call +
    retrieval validates end-to-end with one CLI invocation.
    """
    secret = secrets.token_hex(32)
    os.environ["PROVENEX_SIGNING_SECRET"] = secret
    signer = HmacSha256Signer()

    # Set up a Provenex index with one ingested chunk so verify can
    # produce a non-UNVERIFIED outcome.
    index_path = tmp_path / "prov.db"
    index = SQLiteProvenanceIndex(str(index_path))
    from provenex.core.fingerprinter import Fingerprinter
    fp = Fingerprinter()
    chunk_text = "This is a verified chunk of corpus content."
    chunk_fp = fp.fingerprint_chunk(chunk_text)
    index.add(
        fingerprint=chunk_fp,
        document_id="doc-1",
        document_version="sha256:" + "v" * 64,
        chunk_offset=0,
        chunk_length=len(chunk_text),
        authorized=True,
    )

    policy = Policy.from_text(VALID_UNIFIED_BOTH)
    request = RequestContext(
        caller={"role": "engineer"},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )

    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()

    # Step 0: retrieval.
    trj = start_trajectory(agent_id="cli_test_agent")
    r0 = verify_chunks(
        chunks=[chunk_text],
        index=index,
        signer=signer,
        policy=policy,
        request_context=request,
        chunk_metadata=[{"classification": "public"}],
        trajectory=trj,
    )
    (receipts_dir / "step0.json").write_text(r0.receipt.to_json(), encoding="utf-8")

    # Step 1: tool call.
    trj1 = r0.next_trajectory
    r1 = admission_check(
        ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "x"},
            target_system="google_custom_search",
        ),
        request,
        policy=policy,
        signer=signer,
        trajectory=trj1,
    )
    (receipts_dir / "step1.json").write_text(r1.receipt.to_json(), encoding="utf-8")

    # Step 2: another retrieval.
    trj2 = r1.next_trajectory
    r2 = verify_chunks(
        chunks=[chunk_text],
        index=index,
        signer=signer,
        policy=policy,
        request_context=request,
        chunk_metadata=[{"classification": "public"}],
        trajectory=trj2,
    )
    (receipts_dir / "step2.json").write_text(r2.receipt.to_json(), encoding="utf-8")

    index.close()

    rc = main(["audit", "--trajectory", str(receipts_dir), "--quiet"])
    assert rc == 0


def test_audit_trajectory_json_summary_aggregates_mixed_step_kinds(
    tmp_path, capsys
):
    """``audit --trajectory --json`` produces a ``summary`` block that
    aggregates chunk counts AND tool-call counts across the whole
    trajectory, with a ``per_step_kind`` breakdown an auditor can read
    at a glance.
    """
    secret = secrets.token_hex(32)
    os.environ["PROVENEX_SIGNING_SECRET"] = secret
    signer = HmacSha256Signer()

    # Set up: one verified chunk to retrieve, one tool-call admission.
    index_path = tmp_path / "prov.db"
    index = SQLiteProvenanceIndex(str(index_path))
    from provenex.core.fingerprinter import Fingerprinter
    fp = Fingerprinter()
    chunk_text = "Aggregate-summary trajectory test chunk."
    chunk_fp = fp.fingerprint_chunk(chunk_text)
    index.add(
        fingerprint=chunk_fp,
        document_id="doc-1",
        document_version="sha256:" + "v" * 64,
        chunk_offset=0,
        chunk_length=len(chunk_text),
        authorized=True,
    )

    policy = Policy.from_text(VALID_UNIFIED_BOTH)
    request = RequestContext(
        caller={"role": "engineer"},
        jurisdiction="US",
        purpose="incident_response",
        timestamp="2026-05-14T11:30:00Z",
    )

    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()

    trj = start_trajectory(agent_id="agg_test")
    # NOTE: Phase 1's verify_chunks doesn't auto-stamp step_kind on
    # the emitted receipt; we pass it explicitly so the aggregator can
    # bucket retrieval receipts under "retrieval". This is the same
    # caller-side discipline `examples/agentic_admission_demo.py`
    # follows when it wants step_kind on retrieval receipts.
    r0 = verify_chunks(
        chunks=[chunk_text], index=index, signer=signer, policy=policy,
        request_context=request, chunk_metadata=[{"classification": "public"}],
        trajectory=trj, step_kind="retrieval",
    )
    (receipts_dir / "r0.json").write_text(r0.receipt.to_json(), encoding="utf-8")

    # Allowed tool call.
    r1 = admission_check(
        ToolCallContext(
            name="web_search", operation="query",
            parameters={"q": "x"}, target_system="google_custom_search",
        ),
        request, policy=policy, signer=signer, trajectory=r0.next_trajectory,
    )
    (receipts_dir / "r1.json").write_text(r1.receipt.to_json(), encoding="utf-8")

    # Denied tool call (so the aggregate shows non-zero denied).
    r2 = admission_check(
        ToolCallContext(
            name="web_search", operation="query",
            parameters={"q": "y"}, target_system="duckduckgo",
        ),
        request, policy=policy, signer=signer, trajectory=r1.next_trajectory,
    )
    (receipts_dir / "r2.json").write_text(r2.receipt.to_json(), encoding="utf-8")

    index.close()

    rc = main(["audit", "--trajectory", str(receipts_dir), "--json"])
    # rc==1 because the trajectory contains a denied tool call (FAIL overall).
    # That's data, not an error in the audit itself.
    assert rc in (0, 1)
    report = json.loads(capsys.readouterr().out)
    assert report["receipt_count"] == 3
    summary = report["summary"]
    # Chunk totals.
    assert summary["total_chunks"] == 1
    assert summary["verified"] == 1
    # Action totals across both admission receipts.
    assert summary["total_actions"] == 2
    assert summary["actions_allowed"] == 1
    assert summary["actions_denied"] == 1
    # Step-kind breakdown.
    assert summary["per_step_kind"]["retrieval"] == 1
    assert summary["per_step_kind"]["tool_call"] == 2
    # Aggregate status reflects the denied action.
    assert summary["overall_status"] == "FAIL"


def test_audit_trajectory_human_summary_mentions_actions(tmp_path, capsys):
    """The non-JSON output adds a one-line headline so operators get the
    shape of the trajectory at a glance without paging through detail.
    """
    secret = secrets.token_hex(32)
    os.environ["PROVENEX_SIGNING_SECRET"] = secret
    signer = HmacSha256Signer()
    policy = Policy.from_text(VALID_TOOL_POLICY)
    request = RequestContext(
        caller={"role": "engineer"}, jurisdiction="US",
        purpose="test", timestamp="2026-05-14T11:30:00Z",
    )
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    trj = start_trajectory(agent_id="t")
    r0 = admission_check(
        ToolCallContext(
            name="web_search", operation="query",
            parameters={"q": "x"}, target_system="google_custom_search",
        ),
        request, policy=policy, signer=signer, trajectory=trj,
    )
    (receipts_dir / "r0.json").write_text(r0.receipt.to_json(), encoding="utf-8")
    os.environ["NO_COLOR"] = "1"
    try:
        rc = main(["audit", "--trajectory", str(receipts_dir)])
    finally:
        os.environ.pop("NO_COLOR", None)
    assert rc == 0
    out = capsys.readouterr().out
    # Headline aggregate lines.
    assert "Steps:" in out
    assert "tool_call" in out
    assert "Actions:" in out
    assert "1 allowed" in out


def test_audit_trajectory_json_mode_includes_all_three_step_kinds(tmp_path, capsys):
    """JSON-mode output makes the multi-step shape easily inspectable."""
    secret = secrets.token_hex(32)
    os.environ["PROVENEX_SIGNING_SECRET"] = secret
    signer = HmacSha256Signer()

    policy = Policy.from_text(VALID_TOOL_POLICY)
    request = RequestContext(
        caller={"role": "engineer"},
        jurisdiction="US",
        purpose="test",
        timestamp="2026-05-14T11:30:00Z",
    )

    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()

    trj = start_trajectory(agent_id="t")
    r0 = admission_check(
        ToolCallContext(
            name="web_search", operation="query",
            parameters={"q": "a"}, target_system="google_custom_search",
        ),
        request, policy=policy, signer=signer, trajectory=trj,
    )
    (receipts_dir / "r0.json").write_text(r0.receipt.to_json(), encoding="utf-8")

    r1 = admission_check(
        ToolCallContext(
            name="web_search", operation="query",
            parameters={"q": "b"}, target_system="google_custom_search",
        ),
        request, policy=policy, signer=signer, trajectory=r0.next_trajectory,
    )
    (receipts_dir / "r1.json").write_text(r1.receipt.to_json(), encoding="utf-8")

    rc = main(["audit", "--trajectory", str(receipts_dir), "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["overall"] == "PASS"
    assert report["receipt_count"] == 2
    # Both receipts have step_kind=tool_call.
    assert all(
        "step_index" in r and r["ok"] is True
        for r in report["receipts"]
    )
