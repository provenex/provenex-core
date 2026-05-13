# provenex-core

[![test](https://github.com/provenex/provenex-core/actions/workflows/test.yml/badge.svg)](https://github.com/provenex/provenex-core/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/provenex-core.svg?cacheSeconds=300)](https://pypi.org/project/provenex-core/)
[![Python](https://img.shields.io/pypi/pyversions/provenex-core.svg?cacheSeconds=300)](https://pypi.org/project/provenex-core/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/provenex/provenex-core/blob/main/LICENSE)

Cryptographic provenance verification for RAG pipelines. When an enterprise AI system answers a question, this is what proves which documents the answer came from, whether they were current and authorized, and that they weren't tampered with along the way.

This repository contains the open source core: fingerprinting, local SQLite index, receipt generation, LangChain integration. The algorithm is open so it can be audited. Hosted infrastructure, Bloom-filter acceleration, compliance-grade exports, and cross-enterprise provenance graphs are available separately at [provenex.ai](https://provenex.ai).

> **Note on terminology.** "Provenance" means several different things in the AI stack right now: training-data lineage, vector DB governance (Pinecone Nexus, Weaviate), retrieval verification, output faithfulness, generated-media credentials (C2PA). Provenex is the **retrieval verification** layer. It produces cryptographic proof of which chunks reached the LLM, verifiable offline by anyone with the signing key, across any retriever. We've written up the full map in [Five Things People Mean by "AI Provenance"](https://provenex.ai/blog/five-things-ai-provenance).

## Where Provenex fits in your stack

If you haven't been steeped in RAG vocabulary, here's the picture in plain English before we get to code.

### The pieces of a typical RAG pipeline

| Piece | What it does | Common examples |
| --- | --- | --- |
| **Chunker** | Splits long documents into small passages an embedder can encode | LangChain `RecursiveCharacterTextSplitter`, LlamaIndex `SentenceSplitter` |
| **Embedder** | Turns each chunk (and each user query) into a numeric vector capturing meaning | OpenAI `text-embedding-3`, Cohere Embed, `sentence-transformers` |
| **Vector database** | Stores those vectors. At query time, returns chunks whose vectors are *similar* to the query's vector | Pinecone, Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector |
| **Retriever** | The piece of glue code that takes a user query, asks the vector DB for similar chunks, and hands them to the LLM | LangChain `Retriever`, LlamaIndex `Retriever`, or hand-rolled Python |
| **LLM** | Generates an answer conditioned on the retrieved chunks | GPT-4, Claude, Gemini, Llama-3, etc. |

What's missing from that list: anything that says "these chunks are bit-exact identical to documents we authorized, and we can prove it to an auditor five years from now." That's what Provenex adds.

### Where Provenex slots in

Provenex introduces two pieces of its own:

| Piece | What it does |
| --- | --- |
| **Provenex index** | A separate database (SQLite locally, hosted in production) that stores **cryptographic fingerprints** of every chunk you ingested, plus metadata: document ID, document version, ingestion timestamp, authorization state. Not the embeddings. Not the chunk text. SHA-256 hashes and metadata only. |
| **Ingester** | At document-write time, alongside the code that writes embeddings to your vector DB, this code writes fingerprints to the Provenex index. Two writes, both committed before "ingest" is done. |
| **Retrieval-time verifier** | At query time, after your retriever pulls chunks from the vector DB, the verifier re-fingerprints each chunk and checks the Provenex index. Each chunk gets one of five outcomes (`VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`). A configurable policy decides which outcomes are allowed to reach the LLM. |
| **Receipt** | The signed JSON record of the whole transaction. Records the chunks, their outcomes, the policy, a hash of the LLM output, and a signature over the whole thing. The artifact your compliance team keeps. |

### Standard RAG vs RAG with Provenex

```
Standard RAG:

  documents ─▶ chunker ─▶ embedder ─▶ vector DB ────────┐
                                                         │
  user query ─▶ embedder ─▶ vector DB.search() ───▶ retriever ─▶ LLM ─▶ answer
                                                         │
                                                  (top-k chunks)


Same pipeline with Provenex:

  documents ─┬─▶ chunker ─▶ embedder ─▶ vector DB ──────┐
             │                                           │
             └─▶ provenex.add()  (parallel write,        │
                                  signed fingerprints)   │
                                                         │
  user query ─▶ embedder ─▶ vector DB.search() ─▶ retriever ─┐
                                                              │
                                                              ▼
                                              ┌─────────────────────┐
                                              │ provenex.verify(chunk)│
                                              │   per retrieved chunk│
                                              └──────────┬───────────┘
                                                         │
                                          policy filter applied
                                                         │
                                                         ▼
                                                 verified chunks ─▶ LLM ─▶ answer
                                                         │
                                                         ▼
                                                 signed receipt ─▶ audit / compliance
```

### Where does your code change?

**Not in your vector DB.** Provenex doesn't talk to Pinecone, Weaviate, Milvus, or any vector store directly. There's no plugin to install, no schema migration, no managed-vendor permission to wire up. Your vector DB stays exactly as it is.

The integration lives in your **application code**, the same RAG glue layer that already calls your vector DB. Two spots:

1. **In your ingest pipeline.** Wherever your code currently writes chunks into the vector DB (`pinecone_index.upsert(chunks)`, `weaviate.batch.add(...)`, `chroma_collection.add(...)`, etc.), add a parallel call to `provenex.add(...)` for each chunk. Both writes happen at the same place, in the same code path.
2. **In your retrieval path.** Wherever you get chunks back from the vector DB and hand them to the LLM, run them through `provenex.verify(chunk)` first. Either inline in your own code, or via the drop-in `ProvenexRetriever` wrapper if you're on LangChain.

Conceptually it's a few lines in two files. You keep your vector DB. You keep your embedder. You keep your LLM. You're adding a parallel signed index that gives every retrieval an auditable, offline-verifiable receipt.

## Five-line integration

```python
from provenex.integrations.langchain import ProvenexIngestor, ProvenexRetriever
from provenex.index.sqlite_index import SQLiteProvenanceIndex

index = SQLiteProvenanceIndex("provenance.db")
ingestor = ProvenexIngestor(index=index)

ingestor.ingest(documents, doc_id="policy_v4", authorized=True)

retriever = ProvenexRetriever(base_retriever=your_existing_retriever, index=index)
result = retriever.get_relevant_documents_with_receipt(query)
print(result.receipt.to_json())
```

Your existing vector store is untouched. Provenex runs alongside as a parallel signed index. Whether you use **Pinecone, Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector, MongoDB Atlas Vector Search, Elasticsearch with vectors, Vespa, or a Postgres table you wrote yourself**, Provenex doesn't know and doesn't care. The integration surface is the retriever (drop-in wrappers ship for both LangChain and LlamaIndex), not the database. `your_existing_retriever` keeps doing semantic similarity; Provenex adds cryptographic identity.

## What a provenance receipt looks like

Every retrieval produces a JSON receipt that records exactly what went into the answer. Compliance teams hold onto it. Auditors verify it independently.

```json
{
  "receipt_id": "prx_f2de431dc125ccfc6b57e6ca327fa504",
  "schema_version": "1.1.0",
  "issued_at": "2026-05-08T14:32:07.441Z",
  "issuer": "provenex-core/0.2.0",
  "output": {
    "hash": "sha256:6e9052525c80e43fb3612dce5edd025d350c8f0a1318097988ab4b0750c2f388",
    "hash_algorithm": "sha256"
  },
  "sources": [
    {
      "chunk_index": 0,
      "fingerprint": "sha256:1ebcde39...",
      "document_id": "policy_v4",
      "document_version": "sha256:1ebcde39...",
      "ingested_at": "2026-04-01T09:00:00Z",
      "chunk_offset": 0,
      "chunk_length": 936,
      "authorized": true,
      "verification_outcome": "VERIFIED",
      "normalization_applied": ["unicode_nfc", "strip_zero_width", "whitespace_collapse"]
    }
  ],
  "policy": { "block_unauthorized": true, "block_tampered": true, "...": "..." },
  "summary": { "total_chunks": 3, "verified": 2, "unverified": 1, "overall_status": "PARTIAL" },
  "signature": { "algorithm": "hmac-sha256", "value": "fc5d40895ca2..." }
}
```

Every retrieved chunk gets one of five verification outcomes:

| Outcome | Meaning |
| --- | --- |
| `VERIFIED` | Chunk in index, document current, authorized. |
| `STALE` | Chunk in index, but the document has been superseded by a newer version. |
| `UNAUTHORIZED` | Chunk in index, but the document is not authorized for this context. |
| `UNVERIFIED` | Chunk fingerprint not in index. It was never ingested through Provenex. |
| `TAMPERED` | Chunk in index but the stored signature failed verification. Alarm condition. |

The receipt is signed (HMAC-SHA256 by default; pluggable). Anyone with the receipt and the key can verify it didn't change since it was issued.

## How it works

Three components:

**1. Ingestion.** Documents are normalized (Unicode NFC, whitespace collapse, optional case folding, zero-width stripping) and run through a sliding window. Each window gets a Rabin-Karp rolling hash (base `1_000_003`, modulo Mersenne prime `2^61 - 1`) for cheap O(1) updates, strengthened with SHA-256 for collision-resistant identity. The fingerprints (not the document content) are written to the provenance index along with `document_id`, `document_version`, timestamp, and authorization state. The index never stores document text.

**2. Retrieval verification.** When your retriever returns chunks, Provenex re-fingerprints each one using the same normalization and hash pipeline, checks the fingerprint against the index, and assigns one of the five outcomes above. Configurable policy decides which outcomes block the chunk before it reaches the LLM.

**3. Receipt.** After verification, a JSON receipt is issued that records the chunks, their outcomes, the policy in effect, a SHA-256 of the LLM output, and a signature over the whole thing. The receipt is the artifact you keep.

See [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md) for the full algorithm, including the architectural distinction between fingerprint-based identity and embedding-based similarity. See [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md) for the schema spec.

## How this fits alongside Pinecone Nexus, Weaviate, and other vector DBs

Vector databases store **semantic similarity**: dense embeddings that let you find content similar to a query. Provenex stores **cryptographic identity**: SHA-256 fingerprints that prove bit-exact match against a signed reference. These solve different problems and compose cleanly.

| | Vector DBs (Pinecone Nexus, Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector, ...) | Provenex |
| --- | --- | --- |
| Primary storage | Dense embeddings (semantic similarity) | SHA-256 fingerprints (cryptographic identity) |
| Retrieval | Approximate nearest neighbor over vectors | Bit-exact match against signed index |
| Tampering | Not detectable. Embeddings are lossy by design | Detectable. Any modification produces a different SHA-256 |
| Audit artifact | Vendor dashboard, internal logs | Signed JSON receipt, verifiable offline |
| Trust root | Vendor's SOC 2 attestation | HMAC signature, verifiable by anyone with the key |
| Vendor lock-in | Yes (per database) | None. Works alongside any retriever |

The expected enterprise deployment is **both**: vector DB for retrieval performance and vendor governance, Provenex for cryptographic audit trails compliance teams can hand to a regulator. See [the blog post](https://provenex.ai/blog/five-things-ai-provenance) for the longer argument.

### Why vendor-agnostic matters

Pinecone Nexus is governance inside Pinecone. Weaviate has its own governance stack. Milvus, Qdrant, Chroma, and the rest each have their own, or none. If you run Pinecone for one workload and Weaviate for another, you have two separate audit stories with two separate vendor trust roots, and no way to produce a single cryptographic record that says "this chunk, wherever it came from, is bit-exact identical to the one we authorized."

Provenex works the same way against all of them, because it never talks to the vector DB. It re-fingerprints the chunks the retriever returns, regardless of where they were stored. One signed index, one receipt schema, one verifiable artifact across every retrieval path in the enterprise.

This also means **migration risk between vector DBs goes to zero.** If you decide to move from Pinecone to Weaviate, or from a managed service to something self-hosted, your provenance audit trail doesn't change. You re-ingest into the new vector DB; the Provenex index stays the same. Vector DB swaps are decoupled from compliance infrastructure.

The technical reason this works: Provenex's integration surface is the retriever (LangChain, LlamaIndex, custom Python), not the vector DB itself. As long as the retriever returns the chunk text the vector DB stored, Provenex can fingerprint it. We've smoke-tested against Chroma and FAISS in the examples. Pinecone, Weaviate, Milvus, Qdrant, and the rest are integration-trivial: a few lines of adapter code if you're not on a framework that already wraps them.

## Install

```bash
pip install provenex-core                  # core only (pure stdlib)
pip install "provenex-core[langchain]"     # + LangChain integration
pip install "provenex-core[llamaindex]"    # + LlamaIndex integration
pip install "provenex-core[ed25519]"       # + Ed25519 asymmetric signing
```

`pip install provenex` is also live as a convenience alias that pulls in `provenex-core`. Python 3.10+. The core has zero third-party dependencies; it's pure stdlib. LangChain, LlamaIndex, and the Ed25519 signer are optional extras.

### Try it in 30 seconds

```bash
pip install provenex-core
git clone https://github.com/provenex/provenex-core.git   # for the demo script
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python provenex-core/examples/standalone_demo.py
```

`examples/standalone_demo.py` runs the full story end-to-end. It ingests a document, issues a signed receipt with a cryptographic inclusion proof, watches the HMAC catch a tampered row, then re-verifies the proof **with the database deleted** using only the receipt fields and the published tree root. It's the demo we'd show a skeptical compliance team.

For the integration-pattern story (how Provenex sits alongside any vector database without replacing it), run [`examples/rag_with_provenance.py`](https://github.com/provenex/provenex-core/blob/main/examples/rag_with_provenance.py). Watch a poisoned chunk that was added directly to the vector store, bypassing Provenex ingest, get caught at the retrieval boundary and blocked from reaching the LLM.

## CLI

```bash
provenex ingest  --index prov.db --doc-id policy_v4 policy.txt
provenex verify  --index prov.db retrieved_chunk.txt
provenex receipt --index prov.db --output llm_output.txt chunk1.txt chunk2.txt
provenex audit   receipt.json
```

Set `PROVENEX_SIGNING_SECRET` in your environment. The `verify` command exits non-zero when the outcome is not `VERIFIED`, so it composes in shell pipelines.

`provenex audit` is the auditor's tool. Given a receipt JSON, it verifies the signature and every inclusion proof against the transparency-log tree root carried on the receipt. No database access required. Exit 0 on PASS, 1 on FAIL, 2 on a parse error. Use `--json` for machine-readable output or `--quiet` for a single-line `PASS`/`FAIL`.

For receipts signed with **Ed25519** (asymmetric), pass `--public-key audit.pub` instead of relying on `PROVENEX_SIGNING_SECRET`. An auditor with only the public key can verify but cannot forge: the strongest version of the "verifiable by anyone" guarantee, suitable for handing receipts to external regulators. Requires `pip install "provenex-core[ed25519]"`.

```bash
provenex audit receipt.json --public-key audit.pub
```

## Why open source?

Compliance teams won't trust a black box. If a regulator asks how your provenance system works, "it's proprietary" is not an answer. The whole algorithm needs to be auditable end to end: normalization, rolling hash, sliding window, SHA-256 strengthening, receipt schema, signature payload. So it is. The commercial value is in the hosted infrastructure that runs this algorithm at scale across an enterprise, not in keeping the algorithm secret.

What's in this repo:

- Fingerprinting engine (normalizer + Rabin-Karp + SHA-256)
- Local SQLite provenance index with HMAC-signed rows
- RFC 6962 Merkle transparency log (optional, on top of the SQLite index)
- Receipt generation, HMAC + Ed25519 signing, offline inclusion-proof verification
- LangChain integration (retriever middleware + ingestor)
- LlamaIndex integration (retriever middleware + ingestor)
- CLI: `provenex ingest / verify / receipt / audit`
- Python SDK: `pip install provenex-core`

What's not in this repo (commercial features at provenex.ai):

- Hosted provenance index with distributed signed append-only storage
- Bloom-filter acceleration for high-throughput verification
- Compliance-grade export formats (PDF, JSON-LD for regulators)
- Cross-enterprise provenance graphs
- Inference attribution and temporal decay scoring
- Enterprise SSO / RBAC

The interface (`ProvenanceIndex`) is the same. Moving from open source to commercial is one line of code: the class you instantiate.

## Privacy and data sovereignty

The index stores fingerprints (one-way SHA-256 hashes) and metadata. **No document content, no PII, no chunk text is ever written.** Anyone with the index can verify retrieval, but no one can recover document content from it.

## License

MIT. See [LICENSE](https://github.com/provenex/provenex-core/blob/main/LICENSE).

## Links

**Reading:**

- [Five Things People Mean by "AI Provenance" (And Which One Is For You)](https://provenex.ai/blog/five-things-ai-provenance): the category map, and where Provenex sits
- [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md): full algorithm, threat model, and architectural comparison to embedding-based systems
- [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md): receipt schema specification
- [`docs/quickstart.md`](https://github.com/provenex/provenex-core/blob/main/docs/quickstart.md): 5-minute getting-started
- [`docs/langchain_integration.md`](https://github.com/provenex/provenex-core/blob/main/docs/langchain_integration.md): LangChain-specific patterns
- [`docs/pinecone_integration.md`](https://github.com/provenex/provenex-core/blob/main/docs/pinecone_integration.md): code walkthrough for adding Provenex to a Pinecone-backed RAG pipeline
- [`docs/threat_model.md`](https://github.com/provenex/provenex-core/blob/main/docs/threat_model.md): attacker model, defended/undefended threats, and the security FAQ compliance teams have asked us

**Project:**

- Homepage: [provenex.ai](https://provenex.ai)
- Issues and discussion: GitHub Issues on this repo
- Commercial features: contact via provenex.ai

