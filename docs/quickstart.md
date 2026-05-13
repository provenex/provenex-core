# Quickstart

Get a working provenance receipt in five minutes. Two paths below: one for an existing LangChain RAG pipeline, one for standalone use without LangChain.

## Install

```bash
pip install "provenex-core[langchain]"
```

For the core SDK without LangChain, drop the `[langchain]` extra. Pure stdlib core; LangChain is an optional extra. Python 3.10+.

## Set a signing secret

The provenance index and receipt signer both need an HMAC key. In production this lives in your secrets manager. For local development, export it:

```bash
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

Anything calling Provenex in this shell will pick it up automatically. You can also pass `signing_secret=b"..."` explicitly to `SQLiteProvenanceIndex` and `HmacSha256Signer`.

## Path A — drop into an existing LangChain pipeline

```python
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor, ProvenexRetriever
from provenex.core.receipt import HmacSha256Signer

# One-time setup.
index = SQLiteProvenanceIndex("provenance.db")

# Ingest documents whenever they're added or updated. `documents` can be
# LangChain Documents or any object with a `page_content` attribute.
ingestor = ProvenexIngestor(index=index)
ingestor.ingest(documents, doc_id="policy_v4", authorized=True)

# Wrap your existing retriever. `your_existing_retriever` is the
# Chroma/FAISS/Pinecone/etc. retriever you already use.
retriever = ProvenexRetriever(
    base_retriever=your_existing_retriever,
    index=index,
    signer=HmacSha256Signer(),
)

# At inference time:
result = retriever.get_relevant_documents_with_receipt(
    query="What is the encryption policy?",
    output_text=llm_output,  # pass the LLM's answer so its hash goes on the receipt
)

print(result.receipt.to_json())
for doc in result.documents:       # the chunks that survived policy filtering
    ...
for doc in result.blocked:         # the chunks policy removed
    ...
```

That's it. Your vector store is untouched. The receipt is signed, JSON-serializable, and self-describing.

## Path B — standalone, no LangChain

The core SDK works without any framework integration:

```python
from provenex.core.fingerprinter import Fingerprinter
from provenex.core.receipt import HmacSha256Signer, ReceiptBuilder
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.policy.policy import VerificationPolicy

index = SQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()

# Ingestion.
result = fp.fingerprint(document_text)
for f in result.fingerprints:
    index.add(
        fingerprint=f.fingerprint,
        document_id="policy_v4",
        document_version=result.document_version,
        chunk_offset=f.offset,
        chunk_length=f.length,
        authorized=True,
    )

# Retrieval-time verification.
builder = ReceiptBuilder(policy=VerificationPolicy())
for chunk_text in retrieved_chunks:
    chunk_fp = fp.fingerprint_chunk(chunk_text)
    outcome = index.verify(chunk_fp)
    entry = index.lookup(chunk_fp)
    builder.add_source(fingerprint=chunk_fp, outcome=outcome, entry=entry)

receipt = builder.finalize(output_text=llm_output, signer=HmacSha256Signer())
print(receipt.to_json())
```

## Path C — with transparency log (offline verification)

The `SQLiteProvenanceIndex` above protects each row with an HMAC. For an additional layer — receipts that an auditor can verify with no access to the index, no signing key, and no network — swap in `MerkleSQLiteProvenanceIndex`. Same `ProvenanceIndex` interface, plus a tree root and inclusion proofs.

```python
from provenex.core.fingerprinter import Fingerprinter
from provenex.core.merkle import verify_inclusion_proof
from provenex.core.receipt import HmacSha256Signer, ReceiptBuilder
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex
from provenex.policy.policy import VerificationPolicy

# Producer side — ingest as before, then publish the tree root.
index = MerkleSQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()
result = fp.fingerprint(document_text)
for f in result.fingerprints:
    index.add(
        fingerprint=f.fingerprint,
        document_id="policy_v4",
        document_version=result.document_version,
        chunk_offset=f.offset,
        chunk_length=f.length,
        authorized=True,
    )
published_tree_root = index.tree_root()  # share this; sign it; gossip it

# Per-retrieval — pull the inclusion proof out alongside the verify outcome.
chunk_fp = fp.fingerprint_chunk(retrieved_chunk)
leaf_bytes, leaf_index, proof = index.inclusion_proof(chunk_fp)

builder = ReceiptBuilder(policy=VerificationPolicy())
builder.add_source(
    fingerprint=chunk_fp,
    outcome=index.verify(chunk_fp),
    entry=index.lookup(chunk_fp),
    leaf_index=leaf_index,
    inclusion_proof=proof,
)
receipt = builder.finalize(
    output_text=llm_output,
    signer=HmacSha256Signer(),
    transparency_log={"tree_size": index.tree_size(), "tree_root": index.tree_root()},
)
```

An auditor with the receipt JSON and the previously-published tree root can verify offline, no database needed:

```python
# Auditor side — receipt.sources[i] carries leaf_index + inclusion_proof,
# receipt.transparency_log carries tree_size + tree_root. That's everything.
ok = verify_inclusion_proof(
    leaf=leaf_bytes,                                # canonical row bytes
    leaf_index=leaf_index,
    tree_size=tree_size,
    proof=[bytes.fromhex(p.split(":", 1)[1]) for p in proof],
    root=bytes.fromhex(published_tree_root.split(":", 1)[1]),
)
assert ok
```

See [`../examples/standalone_demo.py`](../examples/standalone_demo.py) for a runnable end-to-end version that also demonstrates the HMAC layer catching a tampered row.

## Verify a receipt independently

Anyone with the receipt JSON and the signing secret can confirm the receipt hasn't been altered:

```python
import json
from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature

receipt = json.loads(receipt_json)
ok = verify_receipt_signature(receipt, HmacSha256Signer(secret=b"..."))
assert ok, "receipt signature invalid — receipt has been tampered with"
```

For asymmetric verification (so an auditor can verify without holding the signing key), implement the `ReceiptSigner` interface with Ed25519 or similar and swap it in. The receipt structure does not change.

## Next steps

- [`how_it_works.md`](how_it_works.md) — the algorithm, end to end
- [`receipt_format.md`](receipt_format.md) — schema reference for the receipt JSON
- [`langchain_integration.md`](langchain_integration.md) — deeper LangChain integration notes
- [`../examples/standalone_demo.py`](../examples/standalone_demo.py) — end-to-end Merkle demo: ingest, verify, tamper-detection, offline proof verification. Pure stdlib, no LangChain.
- [`../examples/rag_with_provenance.py`](../examples/rag_with_provenance.py) — RAG integration pattern: ingest into both vector store and Provenex, verify at retrieval, watch the policy block a chunk that bypassed Provenex ingest.
- [`../examples/basic_langchain_rag.py`](../examples/basic_langchain_rag.py) — full runnable end-to-end demo against a LangChain retriever
- [`../examples/policy_configuration.py`](../examples/policy_configuration.py) — dev / prod / high-assurance policy presets
- [`scaling.md`](scaling.md) — 1M-chunk benchmark numbers (verify p50 371 µs, offline proof verify 47 µs) and honest discussion of how they move on enterprise hardware
