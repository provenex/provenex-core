# LangChain integration

Provenex ships a drop-in middleware that wraps any existing LangChain retriever, verifies every retrieved chunk against a provenance index, applies a policy, and emits a signed receipt. Your vector store stays untouched.

## Install

```bash
pip install provenex-core[langchain]
```

The `[langchain]` extra pulls in `langchain-core>=0.1`. The Provenex core itself has zero third-party dependencies; LangChain is opt-in.

## Architecture

```
                            ┌────────────────────────┐
                            │ ProvenanceIndex (SQLite)│
                            └───────────┬────────────┘
                                        │
   ┌─────────────────┐                  │ verify
   │ ProvenexIngestor│──────────────────┼────────────────┐
   └────────┬────────┘                  │                │
            │ fingerprint + write       │                │
            ▼                           │                │
                              ┌─────────▼────────────────▼───────┐
   Your existing pipeline:    │      ProvenexRetriever            │
   ────────────────────       │  (wraps your retriever, returns   │
   Vector store / retriever ─▶│   documents + signed receipt)     │
                              └───────────────────────────────────┘
```

Provenex never touches the vector store. The vector store keeps doing semantic similarity; Provenex adds a parallel signed index for cryptographic identity.

## Ingestion

```python
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.integrations.langchain import ProvenexIngestor

index = SQLiteProvenanceIndex("provenance.db")
ingestor = ProvenexIngestor(index=index)

ingestor.ingest(documents, doc_id="policy_v4", authorized=True)
```

`documents` may be:

- A list of `langchain_core.documents.Document` instances
- A list of any duck-typed object with `page_content` (the rest of `Document`'s interface is not required)
- A list of plain strings

All chunks in one call are treated as a single logical document under `doc_id`. The ingestor:

1. Joins all chunks with newlines and computes the `document_version` hash over the normalized join. This makes the version stable across re-chunking.
2. Fingerprints each chunk individually (one whole-chunk fingerprint per input element).
3. Also fingerprints the sliding windows over each chunk's text. These let verification succeed when the retriever returns text trimmed or further re-chunked downstream, as long as a `window_size`-codepoint window matches.

### Re-ingestion

Re-ingesting under the same `doc_id` with new content automatically marks the older fingerprints as `superseded`. A retrieval that returns one of the old chunks will produce a `STALE` outcome.

```python
ingestor.ingest(updated_documents, doc_id="policy_v4", authorized=True)
# All old fingerprints under "policy_v4" are now superseded.
```

### Revoking authorization

```python
index.set_authorization("policy_v4", False)
```

All fingerprints under that `doc_id` will now return `UNAUTHORIZED` at verification.

## Retrieval

```python
from provenex.integrations.langchain import ProvenexRetriever
from provenex.core.receipt import HmacSha256Signer
from provenex.policy.policy import VerificationPolicy

retriever = ProvenexRetriever(
    base_retriever=your_existing_retriever,
    index=index,
    policy=VerificationPolicy(block_unauthorized=True, block_tampered=True),
    signer=HmacSha256Signer(),
)

result = retriever.get_relevant_documents_with_receipt(
    query="What is the encryption policy?",
    output_text=llm_output,
)
```

`result` is a `RetrievalResult` with three fields:

| Field | Type | Notes |
| --- | --- | --- |
| `documents` | list | Chunks that survived policy filtering. Pass these to the LLM. |
| `blocked` | list | Chunks the policy removed. Surfaced so you can log or display them. |
| `receipt` | `ProvenanceReceipt` | The signed receipt covering ALL chunks (kept and blocked). |

### LangChain retriever versions

The middleware supports both:

- **LangChain 0.1+ runnable interface**: `base_retriever.invoke(query)`.
- **Classic interface**: `base_retriever.get_relevant_documents(query)`.

It tries `invoke` first and falls back to the classic method. If your retriever exposes neither, you'll get a `TypeError` with a clear message.

### Classic-style alias

For maximum drop-in compatibility:

```python
docs = retriever.get_relevant_documents("query")  # returns only kept docs
```

This works as a direct replacement for `your_existing_retriever.get_relevant_documents(query)`, except chunks blocked by policy are removed. The receipt is computed but not returned. For real production use, call `get_relevant_documents_with_receipt` and capture the receipt. That's the whole point.

## Configuration parity

The fingerprinter configuration at ingestion time **must match** the configuration at verification time. If they diverge, fingerprints won't match and every retrieved chunk will appear `UNVERIFIED`.

Provenex defaults both sides to the same `FingerprinterConfig` (window_size=128, stride=64, default normalization), so the common case requires zero configuration. If you customize:

```python
from provenex.core.fingerprinter import Fingerprinter, FingerprinterConfig
from provenex.core.normalizer import NormalizationOptions

config = FingerprinterConfig(
    window_size=64,
    stride=32,
    normalization=NormalizationOptions(case_fold=True),
)
fp = Fingerprinter(config)

ingestor = ProvenexIngestor(index=index, fingerprinter=fp)
retriever = ProvenexRetriever(base_retriever=..., index=index, fingerprinter=fp)
```

Use the same `Fingerprinter` instance on both sides, or two instances configured identically.

## Common gotchas

**Don't re-normalize before passing to Provenex.** The middleware normalizes internally as part of fingerprinting. If you pre-normalize differently from Provenex's pipeline, the fingerprints won't match what was ingested.

**Pass `output_text` to `get_relevant_documents_with_receipt` after the LLM runs.** If you call it before inference, pass `output_text=""`. The receipt will record a hash of the empty string. To get a complete receipt, regenerate after the LLM produces its answer:

```python
result = retriever.get_relevant_documents_with_receipt(query, output_text="")
# ... call LLM with result.documents ...
llm_output = llm.invoke(...)
# Regenerate receipt with the real output hash.
final_result = retriever.get_relevant_documents_with_receipt(query, output_text=llm_output)
```

If your pipeline structure makes this awkward, build the receipt directly with `ReceiptBuilder` and call `finalize` once you have the LLM output.

**SQLite is per-process.** The open source `SQLiteProvenanceIndex` is fine for a single process. For multi-worker deployments, use a single process per database file, or move to the hosted Provenex commercial index. The interface is identical.

**Authorization is per `document_id`, not per fingerprint.** Toggling `set_authorization("policy_v4", False)` affects every chunk of that document. This is intentional. You want one knob per document, not per chunk.

## Full example

See [`examples/basic_langchain_rag.py`](../examples/basic_langchain_rag.py) for a runnable end-to-end demo: two documents ingested, three chunks retrieved (one not ingested through Provenex), policy applied, signed receipt printed.

## LlamaIndex

A LlamaIndex integration is on the roadmap. Its design will mirror this one: a wrapper around the base retriever, identical receipt format, same policy engine. Until then, the standalone path in [`quickstart.md`](quickstart.md#path-b-standalone-no-langchain) works for any framework. Just call the SDK directly.
