"""Provenex command-line interface.

Four subcommands:

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

    provenex audit <receipt.json>
        Independently verify a receipt. Checks the signature (if the signing
        secret is in the environment) and verifies each inclusion proof
        against the transparency-log tree root carried on the receipt.
        Needs no database access. This is the auditor's tool.

The CLI is intentionally minimal. For production use, embed the Python SDK
directly.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Tuple

from ..core.fingerprinter import Fingerprinter
from ..core.merkle import verify_inclusion_proof
from ..core.receipt import HmacSha256Signer, ReceiptBuilder, verify_receipt_signature
from ..index.base import VerificationOutcome
from ..index.sqlite_index import SQLiteProvenanceIndex
from ..policy.policy import VerificationPolicy


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
    receipt: Dict[str, Any], quiet: bool
) -> Tuple[bool, str]:
    """Check the receipt signature if a signing secret is available."""
    sig = receipt.get("signature")
    if not sig:
        return True, "no signature on receipt (unsigned)"
    secret = os.environ.get("PROVENEX_SIGNING_SECRET")
    if not secret:
        return True, "skipped (PROVENEX_SIGNING_SECRET not set)"
    alg = sig.get("algorithm")
    if alg != "hmac-sha256":
        return False, f"unknown signature algorithm: {alg}"
    ok = verify_receipt_signature(receipt, HmacSha256Signer())
    return ok, f"{alg}: {'valid' if ok else 'INVALID'}"


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


def _cmd_audit(args: argparse.Namespace) -> int:
    raw = _read_text(args.receipt_file)
    try:
        receipt = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: receipt is not valid JSON: {exc}", file=sys.stderr)
        return 2

    sig_ok, sig_msg = _audit_signature(receipt, quiet=args.quiet)
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


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser."""
    parser = argparse.ArgumentParser(
        prog="provenex",
        description="Cryptographic provenance verification for RAG pipelines.",
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
        help="Receipt JSON file to audit (or - for stdin)",
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
    p_audit.set_defaults(func=_cmd_audit)

    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
