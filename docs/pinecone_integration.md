# Pinecone + Provenex

A walkthrough of dropping Provenex into a Pinecone-backed RAG pipeline. The code on this page is intentionally close to what a real production pipeline looks like, but it is **not part of the test suite** because Pinecone requires a paid account (or free-tier serverless) to run. Treat it as a recipe to adapt, not as runnable example code.

> The same pattern works against Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector, MongoDB Atlas Vector, Elasticsearch with vectors, Vespa, or any retriever you wrote yourself. Provenex doesn't talk to the vector DB. It re-fingerprints whatever chunks come out. See [`how_it_works.md`](how_it_works.md) for why this works.

## What you'll have at the end

- Documents ingested into Pinecone for similarity search **and** into Provenex for cryptographic verification, in parallel writes
- A retriever that asks Pinecone for top-k chunks, re-fingerprints each one at the boundary, evaluates them against a unified policy (verification gate + access-control gate), and emits a signed receipt
- Any chunk that wasn't ingested through Provenex (a poisoned document, an out-of-band write to Pinecone, a colleague who skipped the runbook) is caught at the retrieval boundary, returns `UNVERIFIED`, and is blocked from reaching the LLM by policy
- Any chunk that passed verification but fails the access-control rules (wrong jurisdiction, missing role, stale) is recorded as `policy_decision: deny` on the receipt with the rule that fired

## Prerequisites

```bash
pip install provenex-core
pip install pinecone-client>=4.0
pip install sentence-transformers          # or any embedder you like
```

Set up environment:

```bash
export PINECONE_API_KEY="pcsk_..."
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

The signing secret goes in your secrets manager in production. The Pinecone API key is from the Pinecone console.

## Wiring

```python
import os

from pinecone import Pinecone, ServerlessSpec
from sentence_transformers import SentenceTransformer

from provenex import (
    Policy, RequestContext, HmacSha256Signer, verify_chunks,
)
from provenex.core.fingerprinter import Fingerprinter
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex


# ---- shared infra: vector store + embedder + provenance index ----------------

pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])

INDEX_NAME = "policy-docs"
DIM = 384  # all-MiniLM-L6-v2 produces 384-d vectors

if INDEX_NAME not in [i["name"] for i in pc.list_indexes()]:
    pc.create_index(
        name=INDEX_NAME,
        dimension=DIM,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1"),
    )
pinecone_index = pc.Index(INDEX_NAME)

embedder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

# A Merkle-backed Provenex index produces receipts with inclusion proofs
# that an auditor can verify offline. Use SQLiteProvenanceIndex instead
# if you only want HMAC-signed rows and don't need offline proof verification.
provenance_index = MerkleSQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()


# ---- ingest ------------------------------------------------------------------

def ingest_document(text: str, doc_id: str, authorized: bool = True) -> None:
    """Chunk a document, embed, upsert to Pinecone, AND add to Provenex.

    The two writes (vector_db.upsert and provenex.add) are independent.
    Provenex doesn't talk to Pinecone; it just keeps its own signed
    fingerprint index of the same chunks.
    """
    # Bring your own chunker. In production this is usually a LangChain
    # RecursiveCharacterTextSplitter, a LlamaIndex SentenceSplitter, or a
    # similar fixed-window splitter. For brevity here, naive paragraph split.
    chunks = [c.strip() for c in text.split("\n\n") if c.strip()]

    # Compute the per-doc version hash up front so both stores reference it.
    fp_result = fp.fingerprint(text)
    document_version = fp_result.document_version

    # Embed all chunks in one batch.
    embeddings = embedder.encode(chunks, convert_to_numpy=True).tolist()

    # Write 1: Pinecone (semantic similarity).
    pinecone_index.upsert(
        vectors=[
            {
                "id": f"{doc_id}::{i}",
                "values": emb,
                "metadata": {
                    "doc_id": doc_id,
                    "doc_version": document_version,
                    "chunk_index": i,
                    # Pinecone needs the chunk text in metadata because the
                    # retriever returns vector IDs + metadata, not the
                    # original text. Provenex re-fingerprints THIS text.
                    "text": chunk,
                },
            }
            for i, (chunk, emb) in enumerate(zip(chunks, embeddings))
        ]
    )

    # Write 2: Provenex (cryptographic identity).
    for chunk in chunks:
        chunk_fp = fp.fingerprint_chunk(chunk)
        provenance_index.add(
            fingerprint=chunk_fp,
            document_id=doc_id,
            document_version=document_version,
            chunk_offset=0,
            chunk_length=len(chunk),
            authorized=authorized,
        )


# ---- retrieve + verify -------------------------------------------------------

policy = Policy.from_yaml("provenex_policy.yaml")  # unified verification + access_control


def answer_with_provenance(
    query: str,
    request: RequestContext,
    top_k: int = 5,
    output_text: str = "",
) -> tuple[list[str], dict]:
    """Retrieve from Pinecone, run the unified policy, return (kept chunks, receipt).

    The kept chunks are what you'd pass to the LLM. The receipt is what
    you'd persist for compliance.
    """
    query_emb = embedder.encode(query, convert_to_numpy=True).tolist()

    # Vector DB does its job: similarity search.
    results = pinecone_index.query(
        vector=query_emb, top_k=top_k, include_metadata=True
    )

    chunks = [m.metadata["text"] for m in results.matches]
    # Surface whatever tags Pinecone metadata carries that your policy
    # rules want to read (residency, classification, PII flag, ...).
    chunk_metadata = [
        {
            "residency": m.metadata.get("residency"),
            "classification": m.metadata.get("classification"),
            "contains_pii": m.metadata.get("contains_pii", False),
            "corpus": m.metadata.get("corpus"),
        }
        for m in results.matches
    ]

    result = verify_chunks(
        chunks=chunks,
        index=provenance_index,
        signer=HmacSha256Signer(),
        policy=policy,
        request_context=request,
        chunk_metadata=chunk_metadata,
        # Declare that these tags came from the signed index row, not from
        # an external lookup. Recorded on the receipt as a trust signal.
        chunk_metadata_binding="at_ingest",
        output_text=output_text,
    )
    return result.kept, result.receipt.to_dict()
```

The merkle-log inclusion proofs are attached automatically when the index is a `MerkleSQLiteProvenanceIndex` — no extra plumbing needed on the caller side.

## What this gets you

After ingesting and querying, you have:

- A Pinecone index doing the actual similarity search, untouched by Provenex
- A separate `provenance.db` containing only fingerprints + metadata. No PII, no chunk text, no embeddings. The kind of thing your security team is comfortable letting backup to a public bucket.
- A signed receipt JSON for every query, with one inclusion proof per verified chunk and the tree root anyone needs to re-verify them later
- Five seconds of work for an auditor: pipe the receipt through `provenex audit receipt.json` and read PASS or FAIL

## The boundary

The integration point is the **text in `match.metadata["text"]`**, not the vector DB itself. If you change vector DBs tomorrow (Pinecone → Weaviate, Pinecone → pgvector), the only thing that changes is the retrieval code. The Provenex side does not move. Your historical receipts remain verifiable.

If your retriever doesn't ship text in metadata (some setups store text in a separate document store keyed by ID), keep the text-lookup step in your code path before calling `fp.fingerprint_chunk`. The contract Provenex needs is `chunk_text -> outcome`; whatever you do to get that text is your retrieval architecture's business.

## What we DON'T do

We don't replace Pinecone's data plane. We don't intercept Pinecone API calls. We don't install a plugin into your Pinecone account. The two databases are written to in parallel from your application code, and read from in parallel at retrieval time. If Pinecone is unreachable, your query fails the same way it would without Provenex; if Provenex is unreachable, your query fails at the verification step before the LLM sees anything.

This is the design. The audit trail is invariant to your retrieval choices, and the retrieval performance is invariant to the audit trail.

## See also

- [`langchain_integration.md`](langchain_integration.md): same pattern via the `ProvenexRetriever` drop-in wrapper
- [`../examples/rag_with_provenance.py`](../examples/rag_with_provenance.py): runnable version using a fake vector store, so you can see the flow end-to-end without any account
- [`how_it_works.md`](how_it_works.md): the algorithm and threat model
