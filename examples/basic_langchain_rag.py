"""End-to-end example: ingest, retrieve, verify, generate signed receipt.

This example uses minimal duck-typed stubs in place of LangChain's Document
and BaseRetriever so it runs without LangChain installed. The integration
points are identical for real LangChain — the wrapper only requires
``page_content`` on documents and ``invoke``/``get_relevant_documents`` on
retrievers.

To run with real LangChain (FAISS, Chroma, etc.), replace ``StubDoc`` with
``langchain_core.documents.Document`` and ``StubRetriever`` with your existing
retriever. Everything else stays the same.

Run:
    PROVENEX_SIGNING_SECRET=demo-secret python examples/basic_langchain_rag.py
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from provenex.core.receipt import HmacSha256Signer
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor, ProvenexRetriever
from provenex.policy.policy import VerificationPolicy


# --- Duck-typed LangChain stand-ins (replace with real LangChain in production) ---


@dataclass
class StubDoc:
    page_content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class StubRetriever:
    """In a real pipeline, this is your existing Chroma/FAISS/Pinecone retriever."""

    def __init__(self, docs: List[StubDoc]) -> None:
        self._docs = docs

    def get_relevant_documents(self, query: str) -> List[StubDoc]:
        # In reality this would do semantic similarity search. For the demo
        # we return everything; Provenex would verify each result.
        return list(self._docs)


# --- Demo --------------------------------------------------------------------


def main() -> None:
    if "PROVENEX_SIGNING_SECRET" not in os.environ:
        os.environ["PROVENEX_SIGNING_SECRET"] = "demo-secret-only-for-example"

    sample_dir = Path(__file__).parent / "sample_docs"
    policy_text = (sample_dir / "sample_policy.txt").read_text()
    guideline_text = (sample_dir / "sample_guideline.txt").read_text()

    # --- ONE-TIME SETUP ---
    index = SQLiteProvenanceIndex("provenance_demo.db")
    ingestor = ProvenexIngestor(index=index)

    # --- INGESTION (do this whenever documents are added or updated) ---
    policy_chunks = [StubDoc(page_content=policy_text)]
    guideline_chunks = [StubDoc(page_content=guideline_text)]
    ingestor.ingest(policy_chunks, doc_id="policy_v4", authorized=True)
    ingestor.ingest(guideline_chunks, doc_id="guideline_v2", authorized=True)
    print("ingested 2 documents into provenance index")

    # --- INFERENCE TIME ---
    # Replace StubRetriever with your existing LangChain retriever:
    base_retriever = StubRetriever(policy_chunks + guideline_chunks)

    # Add an extra chunk that was NEVER ingested through Provenex — to show
    # the UNVERIFIED outcome on the receipt.
    base_retriever._docs.append(  # type: ignore[attr-defined]
        StubDoc(page_content="This chunk was injected from outside Provenex.")
    )

    retriever = ProvenexRetriever(
        base_retriever=base_retriever,
        index=index,
        policy=VerificationPolicy(
            block_unauthorized=True,
            block_unverified=False,  # flag but don't block, for demo visibility
        ),
        signer=HmacSha256Signer(),
    )

    # The single new call replaces your existing retriever invocation.
    result = retriever.get_relevant_documents_with_receipt(
        query="What is the encryption policy?",
        output_text="All PII must be encrypted at rest using AES-256.",
    )

    print(f"\nretrieved {len(result.documents)} chunks (kept), "
          f"{len(result.blocked)} blocked by policy")
    print("\n--- PROVENANCE RECEIPT ---")
    print(result.receipt.to_json())
    print("--- END RECEIPT ---")

    index.close()


if __name__ == "__main__":
    main()
