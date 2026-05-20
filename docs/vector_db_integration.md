# Vector DB integration matrix

Provenex does not talk to any vector database directly. The integration lives in your application code in two places: alongside the code that writes embeddings (parallel ingest into the Provenex index) and alongside the code that reads chunks back at retrieval time (re-fingerprint and verify). This doc covers the canonical pattern once, then shows the API-shape differences for the eleven vector databases customers commonly run.

For a deep dive against a specific stack with full runnable code, see [pinecone_integration.md](pinecone_integration.md). Once you have the pattern, transposing to any other vector DB is mechanical.

## The canonical pattern

Two integration points, both in your application code.

### Ingest

Anywhere your code writes a chunk to the vector DB, write the same chunk's fingerprint to Provenex in parallel.

```python
from provenex import Fingerprinter, SQLiteProvenanceIndex
from provenex.index.base import ENTRY_KIND_WHOLE_CHUNK, ENTRY_KIND_WINDOW

index = SQLiteProvenanceIndex("provenance.db")
fp = Fingerprinter()

def ingest_chunks(doc_id: str, chunks: list[str], authorized: bool = True) -> None:
    for chunk in chunks:
        # Write 1: vector DB (your existing code)
        embedding = embedder.encode(chunk)
        vector_db_upsert(doc_id, chunk, embedding)

        # Write 2: Provenex (the new line)
        result = fp.fingerprint(chunk)
        whole_fp = fp.fingerprint_chunk(chunk)
        index.add(
            fingerprint=whole_fp, document_id=doc_id,
            document_version=result.document_version,
            chunk_offset=0, chunk_length=len(chunk),
            authorized=authorized, entry_kind=ENTRY_KIND_WHOLE_CHUNK,
        )
        for f in result.fingerprints:
            if f.fingerprint == whole_fp:
                continue
            index.add(
                fingerprint=f.fingerprint, document_id=doc_id,
                document_version=result.document_version,
                chunk_offset=f.offset, chunk_length=f.length,
                authorized=authorized, entry_kind=ENTRY_KIND_WINDOW,
            )
```

The two writes are independent: Provenex never reads from the vector DB, the vector DB never reads from Provenex. The chunk text is the contract; whatever the vector DB stores as the chunk text is what Provenex re-fingerprints at retrieval. The `entry_kind` split (`ENTRY_KIND_WHOLE_CHUNK` for the whole chunk; `ENTRY_KIND_WINDOW` for the sliding-window locators) is the v0.8.0 window-aligned-splice control; see [threat_model.md § Window-aligned splice control](threat_model.md#window-aligned-splice-substring-promotion-to-verified).

### Retrieval

Anywhere your code receives chunks from the vector DB and forwards them to the LLM, run them through Provenex first.

```python
from provenex import verify_chunks, Policy, RequestContext, HmacSha256Signer

def retrieve_with_provenance(query: str, request: RequestContext) -> tuple[list[str], dict]:
    # Step 1: vector DB query (your existing code)
    matches = vector_db_query(query, top_k=5)
    chunks = [m["text"] for m in matches]
    chunk_metadata = [{"residency": m.get("residency"), "classification": m.get("classification")}
                      for m in matches]

    # Step 2: Provenex verification (the new code)
    result = verify_chunks(
        chunks=chunks, index=index, signer=HmacSha256Signer(),
        policy=Policy.from_yaml("policy.yaml"),
        request_context=request, request_text=query,
        chunk_metadata=chunk_metadata,
    )
    return result.kept, result.receipt.to_dict()  # only verified chunks reach LLM
```

`result.kept` is the chunks that cleared both gates (verification + access-control); `result.blocked` carries the chunks the policy filtered out; `result.receipt` is the signed audit record. The vector DB query path stays exactly as it was; Provenex sits on the boundary between retrieval and the LLM. See [cookbook.md § Verify a chunk with custom metadata](cookbook.md#1-verify-a-chunk-with-custom-metadata) for the per-chunk-metadata structure.

## The per-DB matrix

Same pattern, different APIs. The differences are entirely in the vector DB calls; the Provenex code on the right side of each row is unchanged.

### Pinecone

```python
# Ingest: vector DB call
pinecone_index.upsert(vectors=[{
    "id": f"{doc_id}::{i}", "values": embedding,
    "metadata": {"doc_id": doc_id, "text": chunk, "residency": "EU"},
}])

# Retrieval: vector DB call
results = pinecone_index.query(vector=query_emb, top_k=5, include_metadata=True)
chunks = [m.metadata["text"] for m in results.matches]
```

Full walkthrough: [pinecone_integration.md](pinecone_integration.md).

### Weaviate

```python
# Ingest
collection = client.collections.get("Chunks")
collection.data.insert(properties={"doc_id": doc_id, "text": chunk,
                                   "residency": "EU"}, vector=embedding)

# Retrieval
result = collection.query.near_vector(near_vector=query_emb, limit=5,
                                       return_properties=["doc_id", "text", "residency"])
chunks = [o.properties["text"] for o in result.objects]
```

Weaviate's `properties` map is the equivalent of Pinecone's `metadata`. The `text` field is what Provenex re-fingerprints; the rest is policy-input metadata.

### Milvus

```python
# Ingest
client.insert("chunks", [{"id": f"{doc_id}::{i}", "vector": embedding,
                          "doc_id": doc_id, "text": chunk, "residency": "EU"}])

# Retrieval
results = client.search("chunks", data=[query_emb], limit=5,
                        output_fields=["doc_id", "text", "residency"])
chunks = [r["entity"]["text"] for r in results[0]]
```

Milvus's `output_fields` selects which fields come back; include the chunk text or Provenex has nothing to re-fingerprint.

### Qdrant

```python
# Ingest
client.upsert("chunks", points=[
    PointStruct(id=f"{doc_id}_{i}", vector=embedding,
                payload={"doc_id": doc_id, "text": chunk, "residency": "EU"}),
])

# Retrieval
results = client.search("chunks", query_vector=query_emb, limit=5)
chunks = [r.payload["text"] for r in results]
```

Qdrant's `payload` is the metadata bag; same shape as the others.

### Chroma

```python
# Ingest
collection.add(ids=[f"{doc_id}_{i}"], embeddings=[embedding],
               documents=[chunk], metadatas=[{"doc_id": doc_id, "residency": "EU"}])

# Retrieval
results = collection.query(query_embeddings=[query_emb], n_results=5,
                            include=["documents", "metadatas"])
chunks = results["documents"][0]
metadata = results["metadatas"][0]
```

Chroma keeps the chunk text in the `documents` field (separate from `metadatas`); the rest is the standard pattern.

### FAISS (with an external text store)

FAISS stores vectors only; the chunk text lives in a separate store keyed by the vector ID.

```python
# Ingest
import faiss
index_faiss.add(embedding[None, :])   # FAISS handles the vector
text_store[next_id] = chunk             # your own keyed text store
next_id += 1

# Retrieval
distances, ids = index_faiss.search(query_emb[None, :], k=5)
chunks = [text_store[i] for i in ids[0]]
```

The same separation applies to any "vector index plus separate text store" pattern. Provenex fingerprints the text store's text, not the FAISS index.

### pgvector

```python
# Ingest
cursor.execute(
    "INSERT INTO chunks (doc_id, text, embedding, residency) VALUES (%s, %s, %s, %s)",
    (doc_id, chunk, embedding, "EU"),
)

# Retrieval
cursor.execute(
    "SELECT doc_id, text, residency FROM chunks ORDER BY embedding <=> %s LIMIT 5",
    (query_emb,),
)
rows = cursor.fetchall()
chunks = [r["text"] for r in rows]
```

pgvector lives in the same Postgres database your application probably already uses. The Provenex index can co-exist in the same Postgres cluster (different schema or different database) or live separately; the two are independent.

### MongoDB Atlas Vector Search

```python
# Ingest
collection.insert_one({"doc_id": doc_id, "text": chunk,
                       "embedding": embedding, "residency": "EU"})

# Retrieval
results = collection.aggregate([
    {"$vectorSearch": {"index": "chunks_vector_idx", "path": "embedding",
                       "queryVector": query_emb, "numCandidates": 100, "limit": 5}},
])
chunks = [r["text"] for r in results]
```

MongoDB's vector search returns documents directly; the chunk text is a regular field.

### Elasticsearch with vectors

```python
# Ingest
es.index(index="chunks", body={"doc_id": doc_id, "text": chunk,
                                "embedding": embedding, "residency": "EU"})

# Retrieval
results = es.search(index="chunks", body={
    "knn": {"field": "embedding", "query_vector": query_emb, "k": 5,
            "num_candidates": 100},
})
chunks = [hit["_source"]["text"] for hit in results["hits"]["hits"]]
```

Elasticsearch's KNN search returns the source document; the chunk text is a top-level field.

### Vespa

```python
# Ingest (via the feed API)
client.feed_data_point("chunks", doc_id_and_chunk_idx, {
    "fields": {"doc_id": doc_id, "text": chunk, "embedding": embedding, "residency": "EU"},
})

# Retrieval
result = client.query(yql=f"select * from chunks where ({{targetHits:5}}nearestNeighbor(embedding, qvector))",
                      ranking="default", body={"input.query(qvector)": query_emb})
chunks = [hit["fields"]["text"] for hit in result.hits]
```

Vespa's YQL is more expressive than the other DBs; the integration point is still the chunk text on the return path.

### OpenSearch

OpenSearch's vector search is API-compatible with Elasticsearch's:

```python
# Same as Elasticsearch above; replace es client with the OpenSearch client.
```

OpenSearch and Elasticsearch diverged at version 7; for vector-search-only deployments, the integration code is identical.

## What the matrix is telling you

The Provenex code is unchanged across all eleven backends. The only thing that varies is your vector DB's API for getting the chunk text in and out.

- Provenex does not talk to your vector DB. No plugin, no integration package, no shared schema.
- The chunk text is the contract. Whatever bytes your vector DB ships back at retrieval time, Provenex re-fingerprints. If your retrieval doesn't return the chunk text (some setups store text in a separate document store keyed by ID), look the text up before calling `verify_chunks`.
- Your vector DB is unaffected by adding Provenex. Same performance, same operational characteristics, same backup story. Provenex runs as a parallel signed index plus a policy gate.

If you change vector DBs (Pinecone to Weaviate, Weaviate to pgvector), the only code that moves is in the table above. Historical receipts continue to verify against the existing Provenex index; the audit trail is invariant to the vector store.

## Edge case: a retriever that does not return the chunk text

Some setups (FAISS plus separate text store, vector-only KNN where the text lives in an OLTP database) return chunk IDs at retrieval time. Look up the text in your secondary store before calling `verify_chunks`:

```python
def retrieve(query: str) -> list[str]:
    ids = vector_db_query(query, top_k=5)
    chunks = [text_store.get(chunk_id) for chunk_id in ids]
    # Now hand `chunks` to verify_chunks.
    return chunks
```

The Provenex contract is `chunk_text -> outcome`; whatever you do to get the text is your retrieval architecture's business. The fingerprint is deterministic against the text; the text store and the vector index can be on different days, different machines, different platforms, and the verify step still works because the fingerprint depends on bytes, not on plumbing.

## Read next

- [pinecone_integration.md](pinecone_integration.md): the Pinecone deep dive with a full ingest plus retrieval walkthrough.
- [how_it_works.md § Fingerprinting](how_it_works.md#1-fingerprinting): why the chunk text is the contract.
- [cookbook.md](cookbook.md): twenty short recipes for the common application patterns.
- [examples/rag_with_provenance.py](../examples/rag_with_provenance.py): runnable example against a fake vector store, the same shape as the matrix.
- [examples/basic_langchain_rag.py](../examples/basic_langchain_rag.py): runnable LangChain example against an in-memory vector store.
