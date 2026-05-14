"""Provenex command-line interface.

Subcommands:

    provenex ingest --index <db> --doc-id <id> <file>...
        Fingerprint one or more files and write them to a SQLite provenance
        index. Each file becomes a separate document if --doc-id is omitted,
        or all files are treated as parts of one document if --doc-id is
        provided.

    provenex verify --index <db> <file>
        Read text from a file (or stdin with ``-``), fingerprint it, and
        report the verification outcome.

    provenex receipt --index <db> --output <text> <chunk_file>...
        Generate a provenance receipt for a set of chunk files plus an LLM
        output, signed with PROVENEX_SIGNING_SECRET, and write JSON to stdout.

    provenex audit <receipt.json> [--show-policy]
        Independently verify a receipt. Checks the signature (if the signing
        secret is in the environment) and verifies each inclusion proof
        against the transparency-log tree root carried on the receipt. With
        ``--show-policy``, also prints the per-chunk data-access policy
        decisions from the receipt's ``access_policy`` block (schema 1.5.0+).
        Needs no database access. This is the auditor's tool.

    provenex policy validate <policy.yaml>
        Parse and validate a native YAML policy file. Exit 0 if valid,
        non-zero with a clear message if not. Use in CI to catch typos
        before a broken policy is deployed.

    provenex policy hash <policy.yaml>
        Print the canonical ``policy_version_hash`` for a policy file.
        Useful for confirming what hash will appear in receipts and (in
        Phase 2) what gets published to the transparency log.

The CLI is intentionally minimal. For production use, embed the Python SDK
directly.
"""

from __future__ import annotations

import argparse
import glob as _glob
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..core.fingerprinter import Fingerprinter
from ..core.merkle import verify_inclusion_proof
from ..core.receipt import HmacSha256Signer, ReceiptBuilder, verify_receipt_signature
from ..core.trajectory import audit_trajectory_dag
from ..index.base import VerificationOutcome
from ..index.sqlite_index import SQLiteProvenanceIndex
from ..policy.policy import VerificationPolicy
from ..policy.yaml_evaluator import NativeYamlEvaluator, validate_policy_file


def _read_text(path: str) -> str:
    """Read a file's text, or stdin if path is ``-``."""
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _cmd_ingest(args: argparse.Namespace) -> int:
    index = SQLiteProvenanceIndex(args.index)
    fp = Fingerprinter()
    files: List[str] = args.files
    if not files:
        print("error: at least one file is required", file=sys.stderr)
        return 2

    if args.doc_id:
        # All files = one logical document.
        joined = "\n".join(_read_text(p) for p in files)
        result = fp.fingerprint(joined)
        # Whole-document fingerprint, so `provenex verify <same-file>` works.
        whole_fp = fp.fingerprint_chunk(joined)
        index.add(
            fingerprint=whole_fp,
            document_id=args.doc_id,
            document_version=result.document_version,
            chunk_offset=0,
            chunk_length=len(joined),
            authorized=not args.unauthorized,
        )
        for f in result.fingerprints:
            if f.fingerprint == whole_fp:
                continue
            index.add(
                fingerprint=f.fingerprint,
                document_id=args.doc_id,
                document_version=result.document_version,
                chunk_offset=f.offset,
                chunk_length=f.length,
                authorized=not args.unauthorized,
            )
        print(
            f"ingested {len(result.fingerprints) + 1} fingerprints under "
            f"document_id={args.doc_id} version={result.document_version}"
        )
    else:
        # Each file = its own document, doc_id derived from filename.
        for path in files:
            text = _read_text(path)
            doc_id = os.path.basename(path)
            result = fp.fingerprint(text)
            whole_fp = fp.fingerprint_chunk(text)
            index.add(
                fingerprint=whole_fp,
                document_id=doc_id,
                document_version=result.document_version,
                chunk_offset=0,
                chunk_length=len(text),
                authorized=not args.unauthorized,
            )
            for f in result.fingerprints:
                if f.fingerprint == whole_fp:
                    continue
                index.add(
                    fingerprint=f.fingerprint,
                    document_id=doc_id,
                    document_version=result.document_version,
                    chunk_offset=f.offset,
                    chunk_length=f.length,
                    authorized=not args.unauthorized,
                )
            print(
                f"ingested {len(result.fingerprints) + 1} fingerprints under "
                f"document_id={doc_id}"
            )
    index.close()
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    index = SQLiteProvenanceIndex(args.index)
    fp = Fingerprinter()
    text = _read_text(args.file)
    chunk_fp = fp.fingerprint_chunk(text)
    outcome = index.verify(chunk_fp)
    entry = index.lookup(chunk_fp)
    print(f"fingerprint: {chunk_fp}")
    print(f"outcome:     {outcome.value}")
    if entry is not None:
        print(f"document:    {entry.document_id} ({entry.document_version})")
        print(f"ingested:    {entry.ingested_at}")
        print(f"authorized:  {entry.authorized}")
        print(f"superseded:  {entry.superseded}")
    index.close()
    # Non-zero exit if not verified, so this works in shell pipelines.
    return 0 if outcome == VerificationOutcome.VERIFIED else 1


def _cmd_receipt(args: argparse.Namespace) -> int:
    index = SQLiteProvenanceIndex(args.index)
    fp = Fingerprinter()
    builder = ReceiptBuilder(policy=VerificationPolicy())
    for path in args.chunk_files:
        text = _read_text(path)
        chunk_fp = fp.fingerprint_chunk(text)
        outcome = index.verify(chunk_fp)
        entry = index.lookup(chunk_fp)
        builder.add_source(
            fingerprint=chunk_fp,
            outcome=outcome,
            entry=entry,
            normalization_applied=fp.fingerprint(text).normalization_applied,
        )
    output_text = _read_text(args.output) if args.output else ""
    signer = HmacSha256Signer() if os.environ.get("PROVENEX_SIGNING_SECRET") else None
    receipt = builder.finalize(output_text=output_text, signer=signer)
    print(receipt.to_json())
    index.close()
    return 0


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #


# Colour codes are only emitted when stdout is a terminal. Set NO_COLOR=1
# in the environment to disable unconditionally.
def _supports_color() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m" if _supports_color() else s


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m" if _supports_color() else s


def _dim(s: str) -> str:
    return f"\033[2m{s}\033[0m" if _supports_color() else s


def _canonical_leaf(source: Dict[str, Any]) -> bytes:
    """Reconstruct the canonical bytes the Merkle tree hashed for a source.

    This must match ``provenex.index.sqlite_index._canonical_payload`` exactly:
    six fields, newline-joined, UTF-8 encoded. Documented in
    ``docs/how_it_works.md``. If the format ever changes, both this function
    and the producer side must change together (and the receipt schema_version
    must bump).
    """
    return "\n".join(
        [
            str(source["fingerprint"]),
            str(source["document_id"]),
            str(source["document_version"]),
            str(source["ingested_at"]),
            str(source["chunk_offset"]),
            str(source["chunk_length"]),
        ]
    ).encode("utf-8")


def _hex_of(prefixed: str) -> bytes:
    """Strip the ``sha256:`` prefix off a hash string and return the raw bytes."""
    if ":" in prefixed:
        return bytes.fromhex(prefixed.split(":", 1)[1])
    return bytes.fromhex(prefixed)


def _audit_signature(
    receipt: Dict[str, Any], public_key_path: Optional[str]
) -> Tuple[bool, str]:
    """Check the receipt signature with whichever key material is available.

    Routing:
        * ``--public-key <pem>`` provided → use Ed25519 with that public key.
        * Else if PROVENEX_SIGNING_SECRET env var is set → use HMAC-SHA256.
        * Else → skip signature check (still returns True so overall result
          depends on inclusion proofs alone).

    The receipt's own ``signature.algorithm`` field must match whichever
    signer we end up using; if it doesn't, we report it as a failure rather
    than silently skipping.
    """
    sig = receipt.get("signature")
    if not sig:
        return True, "no signature on receipt (unsigned)"
    alg = sig.get("algorithm")

    if public_key_path:
        try:
            from ..core.ed25519 import Ed25519Signer
        except ImportError:
            return False, (
                "--public-key requires the [ed25519] extra: "
                "pip install provenex-core[ed25519]"
            )
        if alg != "ed25519":
            return False, (
                f"receipt was signed with {alg!r}, not ed25519; pass the "
                f"matching key material for that algorithm instead"
            )
        try:
            pem = Path(public_key_path).read_bytes()
            verifier = Ed25519Signer.from_public_key_pem(pem)
        except Exception as exc:
            return False, f"could not load public key from {public_key_path}: {exc}"
        ok = verify_receipt_signature(receipt, verifier)
        return ok, f"ed25519: {'valid' if ok else 'INVALID'}"

    secret = os.environ.get("PROVENEX_SIGNING_SECRET")
    if not secret:
        return True, "skipped (PROVENEX_SIGNING_SECRET not set, no --public-key)"
    if alg != "hmac-sha256":
        return False, (
            f"receipt was signed with {alg!r}; pass --public-key for "
            f"asymmetric algorithms"
        )
    ok = verify_receipt_signature(receipt, HmacSha256Signer())
    return ok, f"hmac-sha256: {'valid' if ok else 'INVALID'}"


def _audit_inclusion_proofs(
    receipt: Dict[str, Any],
) -> List[Tuple[int, bool, str]]:
    """Verify every source's inclusion proof against the receipt's tree root.

    Returns a list of (source_index, ok, message) tuples. Sources without an
    inclusion_proof are skipped silently — that just means the receipt was
    produced by the HMAC-only ``SQLiteProvenanceIndex`` and there's no log
    to verify against.
    """
    log = receipt.get("transparency_log") or {}
    tree_size = log.get("tree_size")
    tree_root_hex = log.get("tree_root")
    sources = receipt.get("sources") or []
    out: List[Tuple[int, bool, str]] = []

    for i, source in enumerate(sources):
        proof = source.get("inclusion_proof")
        leaf_index = source.get("leaf_index")
        if proof is None or leaf_index is None:
            continue
        if not tree_root_hex or tree_size is None:
            out.append(
                (i, False, "source has inclusion_proof but no transparency_log on receipt")
            )
            continue
        try:
            leaf = _canonical_leaf(source)
            proof_bytes = [_hex_of(p) for p in proof]
            root_bytes = _hex_of(tree_root_hex)
            ok = verify_inclusion_proof(
                leaf=leaf,
                leaf_index=int(leaf_index),
                tree_size=int(tree_size),
                proof=proof_bytes,
                root=root_bytes,
            )
            msg = (
                f"{len(proof)} hashes against tree_size={tree_size}: "
                f"{'valid' if ok else 'INVALID'}"
            )
        except Exception as exc:  # malformed receipt fields
            ok = False
            msg = f"could not verify: {exc!r}"
        out.append((i, ok, msg))
    return out


def _aggregate_trajectory_summary(
    receipts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Sum per-receipt summary blocks across a trajectory.

    The output mirrors the per-receipt ``summary`` shape:

        * Verification-outcome counts (``verified`` / ``stale`` /
          ``unauthorized`` / ``unverified`` / ``tampered``) plus
          ``total_chunks`` — always present.
        * Tool-call counts (``actions_allowed`` / ``actions_denied``)
          plus ``total_actions`` — emitted only when at least one
          receipt in the trajectory carries actions.
        * ``per_step_kind`` — receipt count per ``trajectory.step_kind``
          (e.g. ``{"retrieval": 2, "tool_call": 1}``). Lets an auditor
          see at a glance what shape of trajectory this was.
        * ``overall_status`` — ``FAIL`` if any per-receipt summary is
          FAIL; else ``PARTIAL`` if any is PARTIAL; else ``PASS``.

    This is purely a summing aggregator over fields the issuing SDK
    already wrote. We do not recompute outcomes; if the receipt's own
    summary was wrong, the trajectory aggregate inherits that wrongness
    — that's a per-receipt audit failure, not a summary issue.
    """
    chunk_keys = ("verified", "stale", "unauthorized", "unverified", "tampered")
    aggregate: Dict[str, Any] = {
        "total_chunks": 0,
        "verified": 0,
        "stale": 0,
        "unauthorized": 0,
        "unverified": 0,
        "tampered": 0,
    }
    actions_total = 0
    actions_allowed = 0
    actions_denied = 0
    any_actions = False
    per_step_kind: Dict[str, int] = {}
    statuses: List[str] = []

    for r in receipts:
        summary = r.get("summary") or {}
        aggregate["total_chunks"] += summary.get("total_chunks", 0) or 0
        for k in chunk_keys:
            aggregate[k] += summary.get(k, 0) or 0
        if "total_actions" in summary:
            any_actions = True
            actions_total += summary.get("total_actions", 0) or 0
            actions_allowed += summary.get("actions_allowed", 0) or 0
            actions_denied += summary.get("actions_denied", 0) or 0
        status = summary.get("overall_status")
        if isinstance(status, str):
            statuses.append(status)
        trajectory = r.get("trajectory") or {}
        kind = trajectory.get("step_kind")
        if isinstance(kind, str):
            per_step_kind[kind] = per_step_kind.get(kind, 0) + 1

    if any_actions:
        aggregate["total_actions"] = actions_total
        aggregate["actions_allowed"] = actions_allowed
        aggregate["actions_denied"] = actions_denied

    if per_step_kind:
        aggregate["per_step_kind"] = per_step_kind

    # Aggregate status: FAIL beats PARTIAL beats PASS.
    if "FAIL" in statuses:
        aggregate["overall_status"] = "FAIL"
    elif "PARTIAL" in statuses:
        aggregate["overall_status"] = "PARTIAL"
    elif statuses:
        aggregate["overall_status"] = "PASS"
    else:
        aggregate["overall_status"] = "PASS"

    return aggregate


def _collect_trajectory_receipts(path_or_glob: str) -> List[Path]:
    """Resolve --trajectory's argument to a list of receipt file paths.

    Acceptable inputs:
        * A directory: every ``*.json`` file in it (non-recursive).
        * A glob pattern (anything containing ``*``, ``?``, or ``[``):
          expanded via ``glob.glob``.
        * A single file: returned as a one-element list (useful for testing).

    The list is sorted for deterministic audit output across platforms.
    """
    p = Path(path_or_glob)
    if p.is_dir():
        return sorted(p.glob("*.json"))
    if any(ch in path_or_glob for ch in "*?["):
        return sorted(Path(m) for m in _glob.glob(path_or_glob))
    if p.is_file():
        return [p]
    return []


def _cmd_audit_trajectory(args: argparse.Namespace) -> int:
    """Audit a set of receipts as a trajectory DAG.

    Performs per-receipt audits (signature + inclusion proofs) on each
    receipt in the set, then validates the trajectory-level DAG invariants
    via ``audit_trajectory_dag``. Overall PASS requires every per-receipt
    audit and every DAG check to pass.
    """
    paths = _collect_trajectory_receipts(args.trajectory)
    if not paths:
        print(
            f"error: no receipt files found at {args.trajectory!r}",
            file=sys.stderr,
        )
        return 2

    parsed: List[Tuple[Path, Dict[str, Any]]] = []
    for p in paths:
        try:
            parsed.append((p, json.loads(p.read_text(encoding="utf-8"))))
        except json.JSONDecodeError as exc:
            print(
                f"error: {p} is not valid JSON: {exc}",
                file=sys.stderr,
            )
            return 2

    # Per-receipt audits.
    per_receipt_results: List[Dict[str, Any]] = []
    all_per_receipt_ok = True
    for path, receipt in parsed:
        sig_ok, sig_msg = _audit_signature(receipt, public_key_path=args.public_key)
        proof_results = _audit_inclusion_proofs(receipt)
        proofs_ok = all(ok for _, ok, _ in proof_results)
        receipt_ok = sig_ok and proofs_ok
        all_per_receipt_ok = all_per_receipt_ok and receipt_ok
        per_receipt_results.append(
            {
                "path": str(path),
                "receipt_id": receipt.get("receipt_id"),
                "step_index": (receipt.get("trajectory") or {}).get("step_index"),
                "signature": {"ok": sig_ok, "message": sig_msg},
                "inclusion_proofs": [
                    {"source_index": i, "ok": ok, "message": msg}
                    for i, ok, msg in proof_results
                ],
                "ok": receipt_ok,
            }
        )

    # Trajectory-level DAG checks.
    dag_result = audit_trajectory_dag(r for _, r in parsed)
    all_ok = all_per_receipt_ok and dag_result.ok

    # Aggregate summary across the whole trajectory. The auditor cares
    # about the totals (how many chunks, how many tool calls, how many
    # of each verdict) — those are tedious to derive by hand from N
    # receipt files. Sum the per-receipt summary blocks so the answer
    # is one line in the JSON output. Pure retrieval receipts have no
    # action keys; pure tool-call receipts have no verification counts;
    # mixed receipts have both. The aggregator handles all three.
    aggregate = _aggregate_trajectory_summary([r for _, r in parsed])

    if args.json:
        report = {
            "trajectory_id": dag_result.trajectory_id,
            "receipt_count": dag_result.receipt_count,
            "summary": aggregate,
            "receipts": per_receipt_results,
            "trajectory_checks": [c.to_dict() for c in dag_result.checks],
            "overall": "PASS" if all_ok else "FAIL",
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if all_ok else 1

    if args.quiet:
        print("PASS" if all_ok else "FAIL")
        return 0 if all_ok else 1

    # Human-readable.
    print(f"{_dim('Trajectory:')} {dag_result.trajectory_id or '(none)'}")
    print(f"{_dim('Receipts:  ')} {dag_result.receipt_count}")
    # One-line summary surface so an operator gets the headline without
    # paging through per-receipt detail. Mirrors what --json carries
    # under "summary".
    by_kind = aggregate.get("per_step_kind") or {}
    if by_kind:
        kinds_str = ", ".join(f"{n} {k}" for k, n in sorted(by_kind.items()))
        print(f"{_dim('Steps:     ')} {kinds_str}")
    chunk_total = aggregate.get("total_chunks", 0)
    if chunk_total:
        print(
            f"{_dim('Chunks:    ')} {chunk_total} "
            f"({aggregate.get('verified', 0)} verified)"
        )
    if "total_actions" in aggregate:
        print(
            f"{_dim('Actions:   ')} {aggregate['total_actions']} "
            f"({aggregate.get('actions_allowed', 0)} allowed, "
            f"{aggregate.get('actions_denied', 0)} denied)"
        )
    print()
    for r in per_receipt_results:
        mark = _green("OK") if r["ok"] else _red("FAIL")
        step = r["step_index"]
        step_str = f"step #{step}" if step is not None else "(no step)"
        print(f"  [{mark}] {step_str:<10} {r['receipt_id']}")
        if not r["signature"]["ok"]:
            print(f"        {_red('signature:')} {r['signature']['message']}")
        for ip in r["inclusion_proofs"]:
            if not ip["ok"]:
                print(
                    f"        {_red('proof #' + str(ip['source_index']) + ':')} "
                    f"{ip['message']}"
                )
    print()
    print(f"  {_dim('Trajectory DAG checks:')}")
    for c in dag_result.checks:
        mark = _green("OK") if c.ok else _red("FAIL")
        print(f"    [{mark}] {c.name}: {c.message}")
    print()
    print(f"  Overall: {_green('PASS') if all_ok else _red('FAIL')}")
    return 0 if all_ok else 1


def _cmd_audit(args: argparse.Namespace) -> int:
    # Dispatch to trajectory mode when --trajectory is provided.
    if getattr(args, "trajectory", None):
        if args.receipt_file:
            print(
                "error: --trajectory and a positional receipt file are mutually "
                "exclusive",
                file=sys.stderr,
            )
            return 2
        return _cmd_audit_trajectory(args)

    if not args.receipt_file:
        print(
            "error: provide a receipt file or use --trajectory <dir_or_glob>",
            file=sys.stderr,
        )
        return 2

    raw = _read_text(args.receipt_file)
    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: receipt is not valid JSON: {exc}", file=sys.stderr)
        return 2

    sig_ok, sig_msg = _audit_signature(receipt, public_key_path=args.public_key)
    proof_results = _audit_inclusion_proofs(receipt)
    all_ok = sig_ok and all(ok for _, ok, _ in proof_results)

    if args.json:
        report = {
            "receipt_id": receipt.get("receipt_id"),
            "schema_version": receipt.get("schema_version"),
            "signature": {"ok": sig_ok, "message": sig_msg},
            "inclusion_proofs": [
                {"source_index": i, "ok": ok, "message": msg}
                for i, ok, msg in proof_results
            ],
            "overall": "PASS" if all_ok else "FAIL",
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if all_ok else 1

    if not args.quiet:
        print(f"{_dim('Receipt:')} {receipt.get('receipt_id', '(no id)')}")
        print(f"{_dim('Schema: ')} {receipt.get('schema_version', '?')}")
        print(f"{_dim('Issued: ')} {receipt.get('issued_at', '?')}")
        print()

        mark = _green("OK") if sig_ok else _red("FAIL")
        print(f"  Signature ........... [{mark}] {sig_msg}")

        log = receipt.get("transparency_log") or {}
        if log:
            print(
                f"  Transparency log .... tree_size={log.get('tree_size')} "
                f"tree_root={log.get('tree_root', '?')[:32]}..."
            )

        if proof_results:
            print()
            for i, ok, msg in proof_results:
                mark = _green("OK") if ok else _red("FAIL")
                src = (receipt.get("sources") or [{}])[i]
                print(f"  Source #{i}  [{mark}]  {msg}")
                print(
                    f"    {_dim('fingerprint:')} {src.get('fingerprint', '?')[:40]}..."
                )
                print(
                    f"    {_dim('document:   ')} {src.get('document_id', '?')} "
                    f"({src.get('verification_outcome', '?')})"
                )
        else:
            print()
            print(
                f"  {_dim('No inclusion proofs on this receipt.')} "
                f"{_dim('(HMAC-only index, no transparency log.)')}"
            )

        if getattr(args, "show_policy", False):
            _print_policy_block(receipt)

        print()
        if all_ok:
            print(f"  Overall: {_green('PASS')}")
        else:
            print(f"  Overall: {_red('FAIL')}")
    else:
        # --quiet: a single line
        print("PASS" if all_ok else "FAIL")

    return 0 if all_ok else 1


# --------------------------------------------------------------------------- #
# policy                                                                       #
# --------------------------------------------------------------------------- #


def _cmd_policy_validate(args: argparse.Namespace) -> int:
    """Parse and validate a native YAML policy file.

    Exit code is 0 on a valid file and non-zero (with a message on stderr)
    on any parse or unsupported-feature error. Designed for use in CI:
    a typo or a reserved-but-unimplemented feature should fail the build,
    not silently allow.
    """
    ok, err = validate_policy_file(args.file)
    if not ok:
        print(f"error: {err}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"{args.file}: valid")
    return 0


def _cmd_policy_hash(args: argparse.Namespace) -> int:
    """Print the canonical ``policy_version_hash`` for a policy file.

    This is what would appear on every receipt produced under this policy
    and (with the commercial transparency-log integration) what gets
    entered into the transparency log.

    Unified files in schema 2.2.0 may carry two independently-versioned
    halves: ``access_control`` (chunk policy) and ``tool_call_control``
    (tool-call policy). Each has its own hash. By default we print
    every hash present in the file, one per line, prefixed with the
    section name; pass ``--section access_control`` or ``--section
    tool_call_control`` to filter.
    """
    from ..policy.unified import Policy

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
        try:
            policy = Policy.from_text(text, source=args.file)
            ac_hash = (
                policy.access_control.policy_version_hash
                if policy.access_control is not None
                else None
            )
            tcc_hash = (
                policy.tool_call_control.policy_version_hash
                if policy.tool_call_control is not None
                else None
            )
        except Exception:
            # Legacy access-control-only file with rules at top level.
            ev = NativeYamlEvaluator.from_path(args.file)
            ac_hash = ev.policy_version_hash
            tcc_hash = None
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    section = getattr(args, "section", None)
    if section == "access_control":
        if ac_hash is None:
            print(
                f"error: {args.file} has no access_control section",
                file=sys.stderr,
            )
            return 1
        print(ac_hash)
        return 0
    if section == "tool_call_control":
        if tcc_hash is None:
            print(
                f"error: {args.file} has no tool_call_control section",
                file=sys.stderr,
            )
            return 1
        print(tcc_hash)
        return 0

    # No filter:
    # - Single-section file: print the hash bare (preserves the
    #   Phase 1 CLI contract — pipeline scripts that grep
    #   ``sha256:...`` from this output continue working).
    # - Multi-section file: prefix each line with the section name so
    #   the auditor can distinguish them.
    present = [(s, h) for s, h in (
        ("access_control", ac_hash),
        ("tool_call_control", tcc_hash),
    ) if h is not None]
    if not present:
        print(
            f"error: {args.file} has no rule sections to hash",
            file=sys.stderr,
        )
        return 1
    if len(present) == 1:
        print(present[0][1])
    else:
        # Pad section names to the longest so the columns line up.
        width = max(len(s) for s, _ in present)
        for section_name, h in present:
            print(f"{section_name:<{width}}  {h}")
    return 0


def _print_policy_block(receipt: Dict[str, Any]) -> None:
    """Render the unified ``policy`` block for ``provenex audit --show-policy``.

    Schema 2.0.0: ``policy.verification`` is always present; the optional
    ``policy.access_control`` carries chunk-decision records. Schema
    2.2.0 (Phase 2): adds an optional ``policy.tool_call_control``
    carrying tool-call admission records. We render every half present
    so an auditor sees all gates at a glance.
    """
    policy_block = receipt.get("policy") or {}
    print()
    print(f"  {_dim('Policy:')}")

    # Verification half — always there.
    verification = policy_block.get("verification") or {}
    blocking = [k.replace("block_", "") for k, v in verification.items() if k.startswith("block_") and v]
    if blocking:
        print(f"    {_dim('verification (blocks):')} {', '.join(blocking)}")
    else:
        print(f"    {_dim('verification (blocks):')} {_dim('(none)')}")

    # Access-control half — optional.
    ac = policy_block.get("access_control")
    if ac:
        print(f"    {_dim('access control:')}")
        print(f"      {_dim('evaluator:           ')} {ac.get('evaluator', '?')}")
        print(f"      {_dim('policy_id:           ')} {ac.get('policy_id', '?')}")
        print(f"      {_dim('policy_version_hash: ')} {ac.get('policy_version_hash', '?')}")
        in_log = ac.get("policy_in_transparency_log")
        print(f"      {_dim('in transparency log: ')} {in_log!s}")
        decisions = ac.get("decisions") or []
        print(f"      {_dim('decisions:           ')} {len(decisions)}")
        for i, d in enumerate(decisions):
            verdict = d.get("decision", "?")
            mark = _green("ALLOW") if verdict == "allow" else _red(verdict.upper())
            rules = d.get("rules_fired") or []
            rules_str = ", ".join(rules) if rules else _dim("(no rules fired)")
            fp = (d.get("chunk_fingerprint") or "?")[:40]
            print(f"      [{mark}] chunk #{i}  {_dim(fp + '...')}  rules: {rules_str}")
    else:
        print(f"    {_dim('access control:        none (no evaluator configured)')}")

    # Tool-call control half — optional (schema 2.2.0+).
    tcc = policy_block.get("tool_call_control")
    actions = receipt.get("actions") or []
    if tcc:
        print(f"    {_dim('tool call control:')}")
        print(f"      {_dim('evaluator:           ')} {tcc.get('evaluator', '?')}")
        print(f"      {_dim('policy_id:           ')} {tcc.get('policy_id', '?')}")
        print(f"      {_dim('policy_version_hash: ')} {tcc.get('policy_version_hash', '?')}")
        in_log = tcc.get("policy_in_transparency_log")
        print(f"      {_dim('in transparency log: ')} {in_log!s}")
        decisions = tcc.get("decisions") or []
        print(f"      {_dim('decisions:           ')} {len(decisions)}")
        # Render each decision next to its action record for the auditor.
        by_action_idx = {a.get("action_index"): a for a in actions}
        for d in decisions:
            verdict = d.get("decision", "?")
            mark = _green("ALLOW") if verdict == "allow" else _red(verdict.upper())
            rules = d.get("rules_fired") or []
            rules_str = ", ".join(rules) if rules else _dim("(no rules fired)")
            aidx = d.get("action_index")
            action = by_action_idx.get(aidx) or {}
            tool_label = (
                f"{action.get('name', '?')}.{action.get('operation', '?')}"
            )
            target = action.get("target_system")
            target_str = f" → {target}" if target else ""
            print(
                f"      [{mark}] action #{aidx}  {_dim(tool_label + target_str)}"
                f"  rules: {rules_str}"
            )
    elif actions:
        print(
            f"    {_dim('tool call control:     none (admission allowed by default — actions present but no policy configured)')}"
        )


# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser."""
    parser = argparse.ArgumentParser(
        prog="provenex",
        description=(
            "Policy enforcement for AI data access, with cryptographic proof."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="Fingerprint files into the index")
    p_ingest.add_argument("--index", required=True, help="Path to SQLite index file")
    p_ingest.add_argument(
        "--doc-id",
        default=None,
        help="Treat all files as one document with this ID (default: per-file)",
    )
    p_ingest.add_argument(
        "--unauthorized",
        action="store_true",
        help="Mark the ingested document(s) as not authorized",
    )
    p_ingest.add_argument("files", nargs="+", help="Files to ingest (or - for stdin)")
    p_ingest.set_defaults(func=_cmd_ingest)

    p_verify = sub.add_parser("verify", help="Verify a chunk against the index")
    p_verify.add_argument("--index", required=True, help="Path to SQLite index file")
    p_verify.add_argument("file", help="File to verify (or - for stdin)")
    p_verify.set_defaults(func=_cmd_verify)

    p_receipt = sub.add_parser("receipt", help="Generate a signed provenance receipt")
    p_receipt.add_argument("--index", required=True, help="Path to SQLite index file")
    p_receipt.add_argument(
        "--output",
        default=None,
        help="Path to LLM output text (will be hashed; not stored)",
    )
    p_receipt.add_argument("chunk_files", nargs="+", help="Files representing retrieved chunks")
    p_receipt.set_defaults(func=_cmd_receipt)

    p_audit = sub.add_parser(
        "audit",
        help="Verify a receipt independently (signature + inclusion proofs)",
        description=(
            "Validate a Provenex receipt. Checks the receipt signature (if "
            "PROVENEX_SIGNING_SECRET is set in the environment) and verifies "
            "each source's inclusion proof against the transparency-log tree "
            "root carried on the receipt. Needs no database access."
        ),
    )
    p_audit.add_argument(
        "receipt_file",
        nargs="?",
        default=None,
        help="Receipt JSON file to audit (or - for stdin). Omit when --trajectory is used.",
    )
    p_audit.add_argument(
        "--trajectory",
        default=None,
        metavar="DIR_OR_GLOB",
        help=(
            "Trajectory audit mode: validate that a set of receipts (directory "
            "or glob pattern) form a consistent trajectory DAG. Mutually "
            "exclusive with the positional receipt file."
        ),
    )
    p_audit.add_argument(
        "--public-key",
        default=None,
        help=(
            "Path to a PEM-encoded Ed25519 public key. Required when the "
            "receipt was signed with Ed25519. Without this flag, HMAC-SHA256 "
            "is assumed and PROVENEX_SIGNING_SECRET is read from the env."
        ),
    )
    p_audit.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of human-readable output",
    )
    p_audit.add_argument(
        "--quiet",
        action="store_true",
        help="Print only PASS/FAIL (overrides default human-readable output)",
    )
    p_audit.add_argument(
        "--show-policy",
        action="store_true",
        help=(
            "Also print the receipt's access_policy block (schema 1.5.0+): "
            "evaluator, policy_id, policy_version_hash, and per-chunk decisions "
            "with rules_fired."
        ),
    )
    p_audit.set_defaults(func=_cmd_audit)

    # policy subcommands (schema 1.5.0+).
    p_policy = sub.add_parser(
        "policy",
        help="Data-access policy operations (validate, hash)",
        description=(
            "Operations on native YAML data-access policy files (schema "
            "1.5.0+). Use 'policy validate' in CI to catch typos before a "
            "broken policy is deployed; use 'policy hash' to confirm the "
            "canonical version hash that will appear on receipts."
        ),
    )
    p_policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)

    p_policy_validate = p_policy_sub.add_parser(
        "validate",
        help="Parse and validate a native YAML policy file",
    )
    p_policy_validate.add_argument("file", help="Path to a policy YAML file")
    p_policy_validate.add_argument(
        "--quiet",
        action="store_true",
        help="Exit 0/1 without printing on success",
    )
    p_policy_validate.set_defaults(func=_cmd_policy_validate)

    p_policy_hash = p_policy_sub.add_parser(
        "hash",
        help="Print the canonical policy_version_hash for a policy file",
    )
    p_policy_hash.add_argument("file", help="Path to a policy YAML file")
    p_policy_hash.add_argument(
        "--section",
        choices=("access_control", "tool_call_control"),
        default=None,
        help=(
            "Print the hash of only one section. Without this flag, every "
            "hashable section in the file is printed, one per line, "
            "prefixed with the section name."
        ),
    )
    p_policy_hash.set_defaults(func=_cmd_policy_hash)

    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
