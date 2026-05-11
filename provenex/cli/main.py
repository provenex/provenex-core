"""Provenex command-line interface.

Three subcommands:

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

The CLI is intentionally minimal — for production use, embed the Python SDK
directly.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from ..core.fingerprinter import Fingerprinter
from ..core.receipt import HmacSha256Signer, ReceiptBuilder
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

    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
