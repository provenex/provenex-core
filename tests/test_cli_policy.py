"""CLI tests for `provenex policy validate`, `provenex policy hash`, and
`provenex audit --show-policy`.
"""

from __future__ import annotations

import json
import os

from provenex.cli.main import main


VALID_POLICY = """
version: 1
policy_id: cli-test-v1

access_control:
  rules:
    - name: r
      require:
        chunk.metadata.x: y
      on_violation: deny
"""

INVALID_POLICY = """
version: 1
policy_id: cli-test-v1

access_control:
  rules:
    - name: r
      require:
        chunk.metadata.x:
          contains: y     # unsupported operator
      on_violation: deny
"""


# --------------------------------------------------------------------------- #
# policy validate                                                              #
# --------------------------------------------------------------------------- #


def test_policy_validate_on_valid_file_exits_zero(tmp_path, capsys):
    p = tmp_path / "ok.yaml"
    p.write_text(VALID_POLICY, encoding="utf-8")
    rc = main(["policy", "validate", str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "valid" in out


def test_policy_validate_on_invalid_file_exits_nonzero(tmp_path, capsys):
    p = tmp_path / "bad.yaml"
    p.write_text(INVALID_POLICY, encoding="utf-8")
    rc = main(["policy", "validate", str(p)])
    assert rc != 0
    err = capsys.readouterr().err
    assert "unknown operator" in err


def test_policy_validate_quiet_prints_nothing_on_success(tmp_path, capsys):
    p = tmp_path / "ok.yaml"
    p.write_text(VALID_POLICY, encoding="utf-8")
    rc = main(["policy", "validate", "--quiet", str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert out == ""


# --------------------------------------------------------------------------- #
# policy hash                                                                  #
# --------------------------------------------------------------------------- #


def test_policy_hash_prints_sha256_prefix(tmp_path, capsys):
    p = tmp_path / "ok.yaml"
    p.write_text(VALID_POLICY, encoding="utf-8")
    rc = main(["policy", "hash", str(p)])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("sha256:")
    assert len(out) == len("sha256:") + 64


def test_policy_hash_on_invalid_file_exits_nonzero(tmp_path, capsys):
    p = tmp_path / "bad.yaml"
    p.write_text(INVALID_POLICY, encoding="utf-8")
    rc = main(["policy", "hash", str(p)])
    assert rc != 0


def test_policy_hash_is_invariant_to_whitespace(tmp_path, capsys):
    p1 = tmp_path / "a.yaml"
    p2 = tmp_path / "b.yaml"
    p1.write_text(VALID_POLICY, encoding="utf-8")
    p2.write_text("\n\n" + VALID_POLICY + "\n\n", encoding="utf-8")

    rc1 = main(["policy", "hash", str(p1)])
    h1 = capsys.readouterr().out.strip()
    rc2 = main(["policy", "hash", str(p2)])
    h2 = capsys.readouterr().out.strip()
    assert rc1 == 0 == rc2
    assert h1 == h2


# --------------------------------------------------------------------------- #
# audit --show-policy                                                          #
# --------------------------------------------------------------------------- #


def _write_receipt(tmp_path, *, with_block: bool):
    """Build a receipt via verify_chunks and write it to a file, returning the path."""
    from provenex import Policy, verify_chunks
    from provenex.core.receipt import HmacSha256Signer
    from provenex.index.sqlite_index import SQLiteProvenanceIndex
    from provenex.policy.evaluator import RequestContext

    os.environ.setdefault("PROVENEX_SIGNING_SECRET", "test-secret")
    index = SQLiteProvenanceIndex(str(tmp_path / "idx.db"))
    text = "hello world"
    from provenex.core.fingerprinter import Fingerprinter

    fp = Fingerprinter()
    cfp = fp.fingerprint_chunk(text)
    result = fp.fingerprint(text)
    index.add(
        fingerprint=cfp,
        document_id="d",
        document_version=result.document_version,
        chunk_offset=0,
        chunk_length=len(text),
        authorized=True,
    )

    kwargs = dict(
        chunks=[text],
        index=index,
        signer=HmacSha256Signer(),
    )
    if with_block:
        kwargs["policy"] = Policy.from_text(VALID_POLICY)
        kwargs["request_context"] = RequestContext(
            caller={"role": "u"},
            jurisdiction="EU",
            purpose="t",
            timestamp="2026-05-13T00:00:00Z",
        )
        kwargs["chunk_metadata"] = [{"x": "y"}]

    res = verify_chunks(**kwargs)
    receipt_path = tmp_path / "r.json"
    receipt_path.write_text(res.receipt.to_json(), encoding="utf-8")
    index.close()
    return receipt_path


def test_audit_show_policy_prints_block_when_present(tmp_path, capsys):
    path = _write_receipt(tmp_path, with_block=True)
    rc = main(["audit", str(path), "--show-policy"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Policy:" in out
    assert "cli-test-v1" in out
    assert "ALLOW" in out


def test_audit_show_policy_explains_absence_when_no_evaluator(tmp_path, capsys):
    path = _write_receipt(tmp_path, with_block=False)
    rc = main(["audit", str(path), "--show-policy"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "access control:" in out
    assert "no evaluator configured" in out


def test_audit_json_does_not_print_policy_block_to_stdout(tmp_path, capsys):
    """The --json output and --show-policy are independent; --show-policy
    is a human-readable rendering only. The JSON output already carries
    the access_policy field if present, via the receipt's own dict.
    """
    path = _write_receipt(tmp_path, with_block=True)
    rc = main(["audit", str(path), "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    # The audit JSON does not echo the receipt verbatim; it summarizes.
    assert payload["overall"] == "PASS"
