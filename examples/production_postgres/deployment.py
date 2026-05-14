"""Production deployment: Postgres provenance index, multi-pod shape.

Run with::

    docker compose -f examples/production_postgres/docker-compose.yml up -d
    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \\
        python examples/production_postgres/deployment.py

This is the production analog of ``examples/standalone_demo.py``. The
algorithm and the receipt format are identical to the SQLite path; what
changes is the deployment shape:

    - One shared Postgres instance is the source of truth.
    - One ingester pod writes fingerprints alongside the vector-store
      ingest (in this script: a single :class:`PostgresProvenanceIndex`
      instance representing the ingester).
    - Many verify pods read from the same Postgres (in this script: a
      second :class:`PostgresProvenanceIndex` instance with its own
      connection pool, representing one verify pod).

The two "pods" share no in-process state. The only thing they share is
the Postgres index — and the canonical HMAC payload, which is identical
to the SQLite backend's. A receipt produced here verifies bit-identically
against a SQLite-backed index using the same signing secret.

Acts:

    1. Ingester pod ingests a small document.
    2. Verify pod reads the same index from a SEPARATE connection pool,
       verifies a chunk → VERIFIED, and emits a signed receipt.
    3. Direct DB tamper (bypassing the SDK). Verify pod re-verifies →
       TAMPERED. The HMAC over the row catches it; the signing key was
       never compromised, only the bytes in the DB.
    4. Receipt portability check: the canonical payload Postgres signed
       is identical to what SQLite would have signed for the same row.

Total runtime ~6 s with default pacing. Pass ``--fast`` to skip the sleeps.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from provenex.core.fingerprinter import Fingerprinter
from provenex.core.receipt import HmacSha256Signer, ReceiptBuilder
from provenex.index.postgres_index import PostgresProvenanceIndex
from provenex.index.sqlite_index import _canonical_payload, _sign
from provenex.policy.policy import VerificationPolicy

_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


DEFAULT_DSN = "postgresql://provenex:provenex_dev_only@localhost:5433/provenex"


def banner(title: str) -> None:
    print()
    print(f"{BOLD}{CYAN}━━━ {title} {'━' * max(0, 60 - len(title))}{RESET}")


def kv(label: str, value: str, color: str = "") -> None:
    print(f"  {DIM}{label:>14}:{RESET} {color}{value}{RESET}")


def pause(seconds: float, *, skip: bool) -> None:
    if not skip:
        time.sleep(seconds)


def _preflight(dsn: str) -> None:
    """Fail fast with a clear message if Postgres isn't reachable."""
    try:
        import psycopg

        with psycopg.connect(dsn, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
    except ImportError:
        print(
            f"{RED}error:{RESET} the 'postgres' extra is not installed.\n"
            f'  pip install -e ".[postgres]"',
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    except Exception as exc:
        print(
            f"{RED}error:{RESET} could not connect to Postgres at {dsn}\n"
            f"  reason: {exc}\n\n"
            f"  Did you bring up the docker-compose stack?\n"
            f"    docker compose -f examples/production_postgres/docker-compose.yml up -d\n\n"
            f"  Or point at your own Postgres:\n"
            f"    export PROVENEX_POSTGRES_DSN=postgresql://user:pw@host:5432/db",
            file=sys.stderr,
        )
        raise SystemExit(2) from None


def _reset_schema(dsn: str) -> None:
    """Drop and recreate the example tables for a clean run.

    Keeps the example idempotent: re-running it doesn't accumulate state
    from prior runs.
    """
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS provenex_fingerprints CASCADE")
            cur.execute("DROP TABLE IF EXISTS provenex_documents CASCADE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fast", action="store_true", help="Skip pacing sleeps (CI mode)."
    )
    args = parser.parse_args()

    if not os.environ.get("PROVENEX_SIGNING_SECRET"):
        print(
            f"{RED}error:{RESET} set PROVENEX_SIGNING_SECRET first, e.g.:\n"
            f"  export PROVENEX_SIGNING_SECRET="
            f'"$(python3 -c \'import secrets; print(secrets.token_hex(32))\')"',
            file=sys.stderr,
        )
        return 2

    dsn = os.environ.get("PROVENEX_POSTGRES_DSN", DEFAULT_DSN)
    _preflight(dsn)
    _reset_schema(dsn)

    banner("Setup")
    kv("dsn", dsn)
    kv("shape", "one ingester pod + one verify pod (separate pools)")
    pause(0.8, skip=args.fast)

    # ----------------------------------------------------------------- act 1
    banner("1. Ingester pod writes fingerprints to Postgres")

    document_text = (
        "Encryption policy. All data at rest must be encrypted using AES-256-GCM "
        "with keys generated by the enterprise KMS. Key-encryption keys must be "
        "rotated quarterly; data-encryption keys are rotated on access. "
        "Network traffic between services must use TLS 1.3 with forward secrecy. "
        "Self-signed certificates are not permitted in production. Certificate "
        "pinning is required for all third-party integrations. "
        "Backups are encrypted with a separate key hierarchy and stored in a "
        "geographically distinct region. Restore procedures must be drilled "
        "quarterly with verification."
    )

    ingester = PostgresProvenanceIndex(dsn=dsn)
    fp = Fingerprinter()
    ingest_result = fp.fingerprint(document_text)
    for f in ingest_result.fingerprints:
        ingester.add(
            fingerprint=f.fingerprint,
            document_id="policy_v4",
            document_version=ingest_result.document_version,
            chunk_offset=f.offset,
            chunk_length=f.length,
            authorized=True,
        )
    ingester.close()  # ingester pod disconnects after the batch

    print(f"  {GREEN}✓ ingested{RESET} {len(ingest_result.fingerprints)} chunks")
    kv("document_id", "policy_v4")
    kv("connection pool", "ingester (closed)")
    print(
        f"  {DIM}↑ ingester pod is done. State now lives in Postgres only.{RESET}"
    )
    pause(1.2, skip=args.fast)

    # ----------------------------------------------------------------- act 2
    banner("2. Verify pod connects to the SAME Postgres, separate pool")

    # A different process in production. Here, a fresh
    # PostgresProvenanceIndex with its own pool against the same DB. No
    # state shared in memory; the index is the source of truth.
    verifier = PostgresProvenanceIndex(dsn=dsn)
    kv("connection pool", "verifier (new)")

    retrieved_chunk = document_text[: ingest_result.fingerprints[0].length]
    chunk_fp = fp.fingerprint_chunk(retrieved_chunk)
    outcome = verifier.verify(chunk_fp)
    entry = verifier.lookup(chunk_fp)

    kv("chunk fp", chunk_fp[:32] + "...")
    kv(
        "outcome",
        outcome.value,
        color=GREEN if outcome.value == "VERIFIED" else RED,
    )
    print(
        f"  {DIM}↑ the verify pod re-fingerprinted the chunk and matched it "
        f"against the index the ingester pod wrote.{RESET}"
    )
    pause(1.0, skip=args.fast)

    # Bundle into a signed receipt. The application keeps this.
    builder = ReceiptBuilder(policy=VerificationPolicy())
    builder.add_source(fingerprint=chunk_fp, outcome=outcome, entry=entry)
    receipt = builder.finalize(
        output_text="model answer: AES-256, rotated quarterly.",
        signer=HmacSha256Signer(),
    )
    receipt_path = Path.cwd() / "provenex_production_receipt.json"
    receipt_path.write_text(receipt.to_json())
    kv("receipt id", receipt.receipt_id, color=CYAN)
    kv("saved to", str(receipt_path))
    print(f"  {GREEN}✓ signed receipt issued{RESET}")
    pause(1.0, skip=args.fast)

    # ----------------------------------------------------------------- act 3
    banner("3. Tamper with the Postgres index: HMAC catches it")

    import psycopg

    # An attacker with DB access (but no signing key) rewrites a row.
    # The HMAC over the canonical payload should refuse to verify.
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE provenex_fingerprints SET chunk_offset = 999 "
                "WHERE fingerprint = %s",
                (chunk_fp,),
            )
    print(f"  {YELLOW}✎ rewrote chunk_offset 0 → 999 directly in Postgres{RESET}")
    pause(0.8, skip=args.fast)

    tampered_outcome = verifier.verify(chunk_fp)
    kv(
        "outcome",
        tampered_outcome.value,
        color=RED if tampered_outcome.value == "TAMPERED" else YELLOW,
    )
    print(
        f"  {DIM}↑ row signature failed validation. The DB was compromised; "
        f"the signing key was not.{RESET}"
    )
    pause(1.2, skip=args.fast)

    # ----------------------------------------------------------------- act 4
    banner("4. Receipt portability: same canonical payload as SQLite")

    # Re-derive the canonical payload from a non-tampered row Postgres
    # stored. This is the bytes the HMAC was over. The same function imports
    # cleanly from provenex.index.sqlite_index — the two backends share
    # exactly one signing-payload definition. A receipt produced here
    # verifies against the SQLite backend (and vice versa) using the same
    # secret.
    verifier.close()
    second_chunk_fp = ingest_result.fingerprints[1].fingerprint
    verifier2 = PostgresProvenanceIndex(dsn=dsn)
    clean_entry = verifier2.lookup(second_chunk_fp)
    payload = _canonical_payload(
        fingerprint=clean_entry.fingerprint,
        document_id=clean_entry.document_id,
        document_version=clean_entry.document_version,
        ingested_at=clean_entry.ingested_at,
        chunk_offset=clean_entry.chunk_offset,
        chunk_length=clean_entry.chunk_length,
    )
    secret = os.environ["PROVENEX_SIGNING_SECRET"].encode("utf-8")
    derived_signature = _sign(payload, secret)
    ok = derived_signature == clean_entry.signature
    kv("payload bytes", str(len(payload)) + " B")
    kv(
        "re-derived sig",
        "MATCHES stored signature" if ok else "MISMATCH (bug)",
        color=GREEN if ok else RED,
    )
    print(
        f"  {DIM}↑ same canonical payload function as the SQLite backend. "
        f"Receipts are portable across backends.{RESET}"
    )
    verifier2.close()
    pause(1.0, skip=args.fast)

    # ----------------------------------------------------------------- coda
    banner("Deployment notes")
    print(f"  {DIM}topology:{RESET}  many verify pods + one ingester pod, "
          f"shared Postgres")
    print(f"  {DIM}reads:{RESET}     scale via Postgres read replicas")
    print(f"  {DIM}writes:{RESET}    row-locked supersession; multi-writer safe")
    print(f"  {DIM}merkle:{RESET}    use MerklePostgresProvenanceIndex for the "
          f"transparency log; single ingester pod recommended in OSS")
    print()
    print(f"  {BOLD}Receipt saved at:{RESET} {receipt_path}")
    print(f"  {BOLD}Re-verify offline:{RESET} provenex audit {receipt_path.name}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
