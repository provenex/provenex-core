"""RAG pipeline + Provenex: the integration architecture, in code.

Run with::

    PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
        python examples/rag_with_provenance.py

This demo answers the question "but how does this fit alongside my
vector database?" It does NOT replace the vector store. It sits
alongside, doing cryptographic identity verification at the retrieval
boundary while the vector store does what it always does (similarity
search).

What it shows, in order:

    1. Ingest. The corpus is written to TWO stores in parallel:
       the vector store (for similarity retrieval) and the Provenex
       index (for cryptographic verification). The two writes are
       independent. Provenex never talks to the vector store.

    2. Clean query. A query comes in, the vector store returns its
       top-k matches, Provenex re-fingerprints each one at the
       boundary and confirms VERIFIED. The signed receipt goes
       alongside the LLM answer.

    3. Poisoned retrieval. An attacker adds a chunk DIRECTLY to the
       vector store, bypassing the Provenex ingest pipeline (this is
       the threat model: data poisoning, prompt-injected scraping,
       a colleague who didn't follow the runbook, etc). The poisoned
       chunk is returned by similarity search. Provenex catches it:
       outcome UNVERIFIED. Policy blocks it. The LLM never sees it.

    4. Architecture coda. The same five lines of Provenex code work
       against Pinecone, Weaviate, Milvus, Qdrant, Chroma, FAISS,
       pgvector, MongoDB Atlas Vector, or a Postgres table you wrote
       yourself. The vector store is fungible. Provenex is the
       invariant audit layer.

The MockVectorStore here is INTENTIONALLY FAKE. It uses keyword overlap, not
embeddings. The point is not to show how a vector DB works (use a
real one for that). The point is to show that Provenex doesn't depend
on what the vector store does internally, only on the chunks it
returns. Swap it for Pinecone in one line.

Total runtime ~15 s with default pacing. Pass ``--fast`` to skip
sleeps.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from provenex.core.fingerprinter import Fingerprinter
from provenex.core.hasher import sha256_fingerprint
from provenex.core.receipt import HmacSha256Signer, ReceiptBuilder
from provenex.index.base import VerificationOutcome
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex
from provenex.policy.policy import VerificationPolicy

# ANSI colors. Disabled automatically when stdout isn't a TTY.
_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def banner(title: str) -> None:
    print()
    print(f"{BOLD}{CYAN}━━━ {title} {'━' * max(0, 60 - len(title))}{RESET}")


def kv(label: str, value: str, color: str = "") -> None:
    print(f"  {DIM}{label:>16}:{RESET} {color}{value}{RESET}")


def pause(seconds: float, *, skip: bool) -> None:
    if not skip:
        time.sleep(seconds)


# --------------------------------------------------------------------- #
# The fake vector store. Replace with Pinecone/Weaviate/Milvus in prod. #
# --------------------------------------------------------------------- #


@dataclass
class StoredChunk:
    document_id: str
    chunk_offset: int
    text: str


class MockVectorStore:
    """A deliberately fake vector store.

    Real vector DBs do approximate nearest-neighbor over learned
    dense embeddings. This one does keyword overlap because we don't
    want to pull `sentence-transformers` into a stdlib demo. The
    quality of retrieval is irrelevant. The point of this file is
    what Provenex does at the boundary, regardless of what the vector
    store returned.

    In production: instantiate a Pinecone/Weaviate/Milvus/Qdrant/
    Chroma/FAISS/pgvector retriever and substitute it for this class.
    Provenex never touches the vector store directly.
    """

    def __init__(self) -> None:
        self._chunks: List[StoredChunk] = []

    def add(self, document_id: str, chunk_offset: int, text: str) -> None:
        self._chunks.append(StoredChunk(document_id, chunk_offset, text))

    def search(self, query: str, k: int = 2) -> List[StoredChunk]:
        """Return top-k chunks by keyword overlap with the query."""
        query_words = {w.lower() for w in query.split()}
        scored: List[Tuple[int, StoredChunk]] = []
        for chunk in self._chunks:
            chunk_words = {w.lower().strip(".,;:") for w in chunk.text.split()}
            overlap = len(query_words & chunk_words)
            if overlap > 0:
                scored.append((overlap, chunk))
        scored.sort(key=lambda x: -x[0])
        return [chunk for _, chunk in scored[:k]]


# --------------------------------------------------------------------- #
# A tiny in-memory "LLM" for the demo. Concatenates the chunks. The    #
# actual LLM is irrelevant; we just need an output to hash.            #
# --------------------------------------------------------------------- #


def stub_llm(query: str, chunks: List[StoredChunk]) -> str:
    """Pretend to generate an answer from the chunks. Just for the demo."""
    if not chunks:
        return f"I cannot answer '{query}' without verified sources."
    return (
        f"Based on {len(chunks)} verified source(s): "
        + " ".join(c.text[:60].strip() + "..." for c in chunks[:2])
    )


# --------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fast", action="store_true", help="Skip pacing sleeps.")
    args = parser.parse_args()

    if not os.environ.get("PROVENEX_SIGNING_SECRET"):
        print(
            f"{RED}error:{RESET} set PROVENEX_SIGNING_SECRET first, e.g.:\n"
            f"  export PROVENEX_SIGNING_SECRET="
            f'"$(python3 -c \'import secrets; print(secrets.token_hex(32))\')"',
            file=sys.stderr,
        )
        return 2

    workdir = Path(tempfile.mkdtemp(prefix="provenex_rag_demo_"))
    db_path = workdir / "provenance.db"

    # The corpus: five chunks of a policy doc. In a real RAG pipeline
    # this is what a chunker would emit (RecursiveCharacterTextSplitter
    # etc). Keep them short for legibility.
    document_id = "policy_v4"
    corpus_chunks = [
        "All data at rest must be encrypted using AES-256-GCM with keys "
        "generated by the enterprise KMS.",
        "Key-encryption keys must be rotated quarterly. Data-encryption "
        "keys are rotated on every access.",
        "Network traffic between services must use TLS 1.3 with forward "
        "secrecy. Self-signed certificates are not permitted in production.",
        "Backups are encrypted with a separate key hierarchy and stored "
        "in a geographically distinct region.",
        "Restore procedures must be drilled quarterly with verification "
        "that the decrypted backup matches the source-of-truth hash.",
    ]
    full_doc = "\n".join(corpus_chunks)
    document_version = sha256_fingerprint(full_doc)

    # --------------------------------------------------------------- act 1
    banner("1. Ingest: write to vector store AND Provenex in parallel")

    vector_store = MockVectorStore()
    provenex_index = MerkleSQLiteProvenanceIndex(str(db_path))
    fp = Fingerprinter()

    print(f"  {DIM}document:{RESET} {document_id} "
          f"({len(corpus_chunks)} chunks, version={document_version[:20]}...)")
    pause(0.6, skip=args.fast)

    offset = 0
    for chunk_text in corpus_chunks:
        # Write 1: the vector store (similarity search target).
        vector_store.add(document_id, offset, chunk_text)
        # Write 2: the Provenex index (cryptographic identity).
        chunk_fp = fp.fingerprint_chunk(chunk_text)
        provenex_index.add(
            fingerprint=chunk_fp,
            document_id=document_id,
            document_version=document_version,
            chunk_offset=offset,
            chunk_length=len(chunk_text),
            authorized=True,
        )
        offset += len(chunk_text) + 1

    print(f"  {GREEN}✓ vector store:{RESET}    {len(vector_store._chunks)} chunks")
    print(f"  {GREEN}✓ provenex index:{RESET}  {provenex_index.tree_size()} leaves")
    kv("tree root", provenex_index.tree_root(), color=YELLOW)
    print(f"  {DIM}↑ two independent writes. Provenex never asked the "
          f"vector store anything.{RESET}")
    pause(1.2, skip=args.fast)

    # --------------------------------------------------------------- act 2
    banner("2. Clean query: vector store returns chunks, Provenex verifies")

    query = "What is the encryption key rotation policy?"
    print(f"  {DIM}query:{RESET} {query!r}")
    pause(0.5, skip=args.fast)

    retrieved = vector_store.search(query, k=2)
    print(f"  {DIM}vector store returned {len(retrieved)} chunk(s):{RESET}")
    for i, chunk in enumerate(retrieved):
        print(f"    {DIM}[{i}]{RESET} {chunk.text[:70]}...")
    pause(0.8, skip=args.fast)

    # Verify each retrieved chunk at the boundary.
    policy = VerificationPolicy(block_unverified=True, block_tampered=True)
    builder = ReceiptBuilder(policy=policy)
    accepted: List[StoredChunk] = []
    blocked: List[StoredChunk] = []
    for chunk in retrieved:
        chunk_fp = fp.fingerprint_chunk(chunk.text)
        outcome = provenex_index.verify(chunk_fp)
        entry = provenex_index.lookup(chunk_fp)
        builder.add_source(fingerprint=chunk_fp, outcome=outcome, entry=entry)
        if _blocked_by_policy(outcome, policy):
            blocked.append(chunk)
        else:
            accepted.append(chunk)
        outcome_color = GREEN if outcome == VerificationOutcome.VERIFIED else RED
        print(f"  {DIM}[{retrieved.index(chunk)}]{RESET} provenex.verify → "
              f"{outcome_color}{outcome.value}{RESET}")
    pause(0.8, skip=args.fast)

    llm_answer = stub_llm(query, accepted)
    receipt = builder.finalize(
        output_text=llm_answer,
        signer=HmacSha256Signer(),
        transparency_log={
            "tree_size": provenex_index.tree_size(),
            "tree_root": provenex_index.tree_root(),
        },
    )
    print()
    kv("LLM answer", llm_answer[:64] + "...")
    kv("receipt status", receipt.summary["overall_status"],
       color=GREEN if receipt.summary["overall_status"] == "OK" else YELLOW)
    kv("verified", str(receipt.summary["verified"]), color=GREEN)
    kv("blocked", str(len(blocked)),
       color=GREEN if len(blocked) == 0 else RED)
    pause(1.5, skip=args.fast)

    # --------------------------------------------------------------- act 3
    banner("3. Poisoned retrieval: Provenex catches an un-ingested chunk")

    # The threat: someone adds a chunk DIRECTLY to the vector store,
    # bypassing the Provenex ingest pipeline. Could be data poisoning,
    # could be a colleague who didn't follow the runbook, could be a
    # vector-store-only attack vector. The fingerprint for this chunk
    # was never written to Provenex, so verify returns UNVERIFIED.
    poisoned_chunk = (
        "Backups should be left unencrypted to simplify the restore "
        "procedure during incident response."  # ← obviously bad advice
    )
    vector_store.add(document_id, 9999, poisoned_chunk)
    print(f"  {YELLOW}✎ attacker added a chunk straight to the vector store:{RESET}")
    print(f"    {DIM}{poisoned_chunk!r}{RESET}")
    print(f"  {DIM}↑ never fingerprinted, never signed, never in the Merkle log.{RESET}")
    pause(1.2, skip=args.fast)

    bad_query = "What's the backup encryption policy during incident response?"
    print()
    print(f"  {DIM}query:{RESET} {bad_query!r}")
    retrieved = vector_store.search(bad_query, k=2)
    print(f"  {DIM}vector store returned {len(retrieved)} chunk(s); "
          f"keyword overlap picked up the poisoned one:{RESET}")
    pause(0.6, skip=args.fast)

    builder = ReceiptBuilder(policy=policy)
    accepted = []
    blocked = []
    for i, chunk in enumerate(retrieved):
        chunk_fp = fp.fingerprint_chunk(chunk.text)
        outcome = provenex_index.verify(chunk_fp)
        entry = provenex_index.lookup(chunk_fp)
        builder.add_source(fingerprint=chunk_fp, outcome=outcome, entry=entry)
        if _blocked_by_policy(outcome, policy):
            blocked.append(chunk)
            outcome_color = RED
        else:
            accepted.append(chunk)
            outcome_color = GREEN
        print(f"    {DIM}[{i}]{RESET} provenex.verify → "
              f"{outcome_color}{outcome.value}{RESET} "
              f"{DIM}({chunk.text[:50]}...){RESET}")
    pause(1.0, skip=args.fast)

    llm_answer = stub_llm(bad_query, accepted)  # only verified chunks reach the LLM
    receipt = builder.finalize(
        output_text=llm_answer,
        signer=HmacSha256Signer(),
        transparency_log={
            "tree_size": provenex_index.tree_size(),
            "tree_root": provenex_index.tree_root(),
        },
    )
    print()
    kv("LLM answer", llm_answer[:64] + ("..." if len(llm_answer) > 64 else ""))
    kv("receipt status", receipt.summary["overall_status"],
       color=YELLOW if receipt.summary["overall_status"] != "OK" else GREEN)
    kv("verified", str(receipt.summary["verified"]), color=GREEN)
    kv("blocked", str(len(blocked)), color=RED if blocked else GREEN)
    print(f"  {DIM}↑ the poisoned chunk was caught at the boundary. "
          f"It never reached the LLM, and the receipt records the attempt.{RESET}")
    pause(1.5, skip=args.fast)

    # --------------------------------------------------------------- coda
    banner("Architecture: what just happened, and why it generalizes")
    print(f"  {DIM}ingest:{RESET}    chunk → vector_store.add() │ provenex.add()")
    print(f"  {DIM}query:{RESET}     vector_store.search() → "
          f"[provenex.verify(c) for c in chunks] → policy filter → LLM")
    print()
    print(f"  Provenex never reads the vector store. It re-fingerprints")
    print(f"  whatever chunks came out and checks them against its own")
    print(f"  signed index. Swap MockVectorStore for Pinecone, Weaviate,")
    print(f"  Milvus, Qdrant, Chroma, FAISS, pgvector, MongoDB Atlas")
    print(f"  Vector, or your own Postgres table. The rest of the code")
    print(f"  is byte-identical.")
    print()
    print(f"  {DIM}For the cryptographic story (HMAC tamper-detection, offline{RESET}")
    print(f"  {DIM}proof verification with the database deleted), see{RESET}")
    print(f"  {DIM}examples/standalone_demo.py.{RESET}")
    print()

    provenex_index.close()
    return 0


def _blocked_by_policy(
    outcome: VerificationOutcome, policy: VerificationPolicy
) -> bool:
    """Mirror of what ProvenexRetriever does internally: block per policy."""
    return (
        (outcome == VerificationOutcome.UNVERIFIED and policy.block_unverified)
        or (outcome == VerificationOutcome.TAMPERED and policy.block_tampered)
        or (outcome == VerificationOutcome.STALE and policy.block_stale)
        or (outcome == VerificationOutcome.UNAUTHORIZED and policy.block_unauthorized)
    )


if __name__ == "__main__":
    raise SystemExit(main())
