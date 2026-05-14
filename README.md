# provenex-core

[![test](https://github.com/provenex/provenex-core/actions/workflows/test.yml/badge.svg)](https://github.com/provenex/provenex-core/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/provenex-core.svg?cacheSeconds=300&v=0.4.0)](https://pypi.org/project/provenex-core/)
[![Python](https://img.shields.io/pypi/pyversions/provenex-core.svg?cacheSeconds=300&v=0.4.0)](https://pypi.org/project/provenex-core/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/provenex/provenex-core/blob/main/LICENSE)

**Policy enforcement for AI data access, with cryptographic proof.**

> **Buyer framing.** Platform engineering champions Provenex (a runtime guardrail they don't have to build). Security signs off (cryptographic enforcement, not promises). Compliance consumes the output (a queryable, exportable, regulator-ready record). Three reinforcing budget lines, faster close than a compliance-only sale.

Provenex is the policy enforcement layer for AI data access. You declare your security policy once — in our native YAML config (or OPA/Rego, commercial) — and Provenex enforces it on every retrieval, then emits a cryptographically signed receipt that proves which chunks were allowed, which were blocked, and under what policy.

> **Scope of this repo.** `provenex-core` is the retrieval primitive — Phase 1 of the broader vision: enforce policy on what an AI system *reads*. Agentic tool-call enforcement (the "can this agent access Jira / Salesforce / this connector" question, anchored on the MCP ecosystem) is Phase 2 and lives in a separate Provenex repository on the same policy-and-proof spine. Provenex is always **decision and proof, not execution** — an admission controller for AI data access, not a proxy that brokers calls or holds tokens.

This repository contains the open source core: fingerprinting, local SQLite index, the native YAML policy DSL, receipt generation, and integrations for LangChain / LangGraph / LlamaIndex / CrewAI. The algorithm is open so it can be audited. Hosted infrastructure, the Rego adapter, the OPA service adapter, Bloom-filter acceleration, compliance-grade exports, and cross-enterprise policy interoperability are available separately at [provenex.ai](https://provenex.ai).

## What you declare. What you get back.

A unified policy file:

```yaml
version: 1
policy_id: hr-corpus-retrieval-v3

# Five-outcome verification gate
verification:
  block_unauthorized: true
  block_tampered: true
  block_stale: false

# Data-access rules
access_control:
  rules:
    - name: jurisdiction_eu_only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency:
          in: [EU, EEA]
      on_violation: deny

    - name: pii_classification_gate
      when:
        chunk.metadata.contains_pii: true
      require:
        request.caller.role:
          in: [hr_admin, payroll]
      on_violation: deny

    - name: freshness_for_policy_corpus
      when:
        chunk.metadata.corpus: policy_documents
      require:
        chunk.ingested_at:
          not_older_than: 90d
      on_violation: deny

  defaults:
    unknown_metadata: deny
```

A signed receipt per retrieval — verifiable offline by anyone with the public key:

```json
{
  "receipt_id": "prx_f2de431dc125ccfc6b57e6ca327fa504",
  "schema_version": "2.1.0",
  "issuer": "provenex-core/0.4.0",
  "output": { "hash": "sha256:...", "hash_algorithm": "sha256" },
  "sources": [
    { "chunk_index": 0, "fingerprint": "sha256:1ebcde39...",
      "verification_outcome": "VERIFIED", "...": "..." }
  ],
  "policy": {
    "verification": { "block_unauthorized": true, "block_tampered": true, "...": "..." },
    "access_control": {
      "evaluator": "native_yaml",
      "policy_id": "hr-corpus-retrieval-v3",
      "policy_version_hash": "sha256:e10b1df5...",
      "policy_in_transparency_log": false,
      "decisions": [
        {
          "chunk_fingerprint": "sha256:1ebcde39...",
          "decision": "allow",
          "rules_fired": ["jurisdiction_eu_only", "freshness_for_policy_corpus"],
          "inputs_hash": "sha256:a3f9c2d1...",
          "inputs": { "chunk_metadata": { "...": "..." }, "request_context": { "...": "..." } }
        }
      ]
    }
  },
  "summary": { "total_chunks": 3, "verified": 2, "unverified": 1, "overall_status": "PARTIAL" },
  "signature": { "algorithm": "hmac-sha256", "value": "fc5d40895ca2..." }
}
```

A chunk reaches the LLM only if it clears **both** gates: the verification policy AND the access-control policy. The receipt records both verdicts per chunk so an auditor can reason about them independently — and the signature covers everything.

## Where Provenex fits in your stack

```
Standard RAG:
  documents ─▶ chunker ─▶ embedder ─▶ vector DB
                                            │
  user query ─▶ embedder ─▶ vector DB.search() ──▶ retriever ─▶ LLM ─▶ answer


Same pipeline with Provenex:
  documents ─┬─▶ chunker ─▶ embedder ─▶ vector DB
             │
             └─▶ provenex.add()   (parallel signed write)

  user query ─▶ embedder ─▶ vector DB.search() ─▶ retriever ─┐
                                                              ▼
                                ┌───────────────────────────────────────┐
                                │  policy.verification (5-outcome gate) │
                                │  policy.access_control (rule engine)  │
                                │      BOTH must allow                  │
                                └────────────┬──────────────────────────┘
                                             ▼
                                    surviving chunks ─▶ LLM ─▶ answer
                                             │
                                             ▼
                              signed policy-decision receipt ─▶ audit / compliance
```

### The pieces

| Piece | What it does |
| --- | --- |
| **Provenex index** | A separate database (SQLite locally, hosted in production) that stores **cryptographic fingerprints** of every chunk you ingested, plus metadata: document ID, version, ingestion timestamp, authorization state, residency / classification / PII tags supplied by upstream tools. Not the embeddings. Not the chunk text. SHA-256 hashes and metadata only. |
| **Ingester** | At document-write time, alongside the code that writes embeddings to your vector DB, this writes fingerprints to the Provenex index. Two writes, both committed before "ingest" is done. |
| **Policy evaluator** | At query time, after your retriever pulls chunks from the vector DB, Provenex re-fingerprints each chunk and runs it through both gates: the verification policy (origin, freshness, tampering) and the access-control policy (jurisdiction, classification, PII tags, freshness windows, caller role). |
| **Receipt** | A signed JSON record of the whole transaction: chunks, verification outcomes, the unified policy, per-chunk decisions, the rules that fired, a hash of the LLM output, and a signature over the whole thing. |

### Where does your code change?

**Not in your vector DB.** Provenex doesn't talk to Pinecone, Weaviate, Milvus, or any vector store directly. There's no plugin to install, no schema migration, no managed-vendor permission to wire up. Your vector DB stays exactly as it is.

The integration lives in your **application code**, the same RAG glue layer that already calls your vector DB. Two spots:

1. **In your ingest pipeline.** Wherever your code currently writes chunks into the vector DB, add a parallel call to `provenex.add(...)` for each chunk.
2. **In your retrieval path.** Wherever you get chunks back from the vector DB and hand them to the LLM, run them through `provenex.verify_chunks(..., policy=Policy.from_yaml("hr_policy.yaml"), request_context=...)` first.

## What policy can express

In scope, in the open-source core:

- **Origin / provenance** — was this chunk ingested through Provenex (`VERIFIED` vs `UNVERIFIED`), is the document version current (`STALE`), is it authorized (`UNAUTHORIZED`), did the stored signature survive (`TAMPERED`).
- **Freshness / recency** — `chunk.ingested_at` against a duration window.
- **Access control** — fields under `request.caller.*` against rule expectations.
- **Jurisdiction / data residency** — `chunk.metadata.residency` against `request.jurisdiction`.
- **Sensitivity / classification** — `chunk.metadata.classification` against caller role or purpose.
- **PII presence and handling** — `chunk.metadata.contains_pii` (or any tag your upstream PII tool sets) against caller role.
- **Authorization scope** — `request.purpose` and arbitrary policy-defined combinations of the above.

Out of scope, deliberately:

- **Content quality assessment.**
- **Factual accuracy or hallucination detection.**
- **Bias detection.**
- **Output safety or content moderation.**
- **Cost-based routing.**
- **Business logic enforcement.**
- **PII detection.** Provenex enforces PII tags set by upstream tools; it does not detect PII itself.
- **Quality evaluation.** Provenex enforces quality decisions made by upstream data governance; it does not evaluate quality itself.

The refusal list is as important as the feature list. A policy enforcement layer that quietly drifts into hallucination detection becomes unpredictable.

## Policy languages: bring your own, or use ours

Provenex is **evaluator-agnostic**. The runtime accepts pluggable evaluator backends:

| Backend | Status | Use when |
| --- | --- | --- |
| **Native YAML DSL** | Open-source core (v0.4) | You aren't already on OPA. Want a small, opinionated DSL that fits in a config file. |
| **Rego adapter** | Commercial | You author authorization policies in Rego elsewhere and want one language across the stack. |
| **OPA service adapter** | Commercial | You run OPA as a service and want Provenex to delegate decisions to it. |

Compared to OPA alone, Provenex adds the **cryptographic enforcement record**, the **integration with retrieval**, and (in a future release) **transparency-log-backed proof** of which policy was in effect when. OPA tells you yes / no. Provenex tells you yes / no plus a signed receipt verifiable offline.

See [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md) for the full DSL reference, supported operators, and worked examples.

## Five-line integration

```python
from provenex import (
    verify_chunks, Policy, RequestContext,
    HmacSha256Signer, SQLiteProvenanceIndex,
)

index = SQLiteProvenanceIndex("provenance.db")
policy = Policy.from_yaml("hr_policy.yaml")
request = RequestContext(
    caller={"role": "hr_admin"}, jurisdiction="EU",
    purpose="customer_support", timestamp="2026-05-13T00:00:00Z",
)
result = verify_chunks(
    chunks=retrieved_chunks, index=index,
    signer=HmacSha256Signer(),
    policy=policy, request_context=request,
    chunk_metadata=[doc.metadata for doc in retrieved_documents],
)
feed_to_llm(result.kept)            # only chunks that cleared BOTH gates
save_receipt(result.receipt)        # signed, verifiable offline
```

Your existing vector store is untouched. Provenex runs alongside as a parallel signed index plus a policy gate. Whether you use **Pinecone, Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector, MongoDB Atlas Vector Search, Elasticsearch with vectors, Vespa, or a Postgres table you wrote yourself**, Provenex doesn't know and doesn't care.

## Agentic and multi-step flows

Modern RAG isn't always one retrieve-then-answer cycle. Agents reason, retrieve, reflect, retrieve again. Multiple agents collaborate. Tools fetch live data. Provenex is built for these flows alongside the simple one-shot case:

| Framework | Integration |
| --- | --- |
| **LangChain** | `ProvenexRetriever` wraps any retriever. Accepts an optional `trajectory=` for multi-step chains. |
| **LangGraph** | `provenex_retrieval_node(...)` factory + state helpers. Drops into any state-graph DAG; the trajectory threads through the shared state. |
| **CrewAI** | `ProvenexCrewSession` owns a per-crew trajectory; `session.wrap_tool(tool)` wraps any retrieval / tool / memory callable. |
| **LlamaIndex** | `ProvenexRetriever` middleware (same pattern as LangChain). |
| **Anything else** | `provenex.verify_chunks(chunks, index=..., policy=..., request_context=..., trajectory=...)` — framework-agnostic one-liner. |

Every retrieval step emits its own signed receipt with a `trajectory` block linking it to its parents in a DAG. After the agent finishes, `provenex audit --trajectory <dir>` validates the entire trajectory end-to-end: signatures, inclusion proofs, no dangling parents, no cycles, shared trajectory id, at least one root step. One audit pass, the whole run.

Receipts also carry two optional per-chunk fields useful in agent flows:

- **`claims[]`** — self-attribution claims from the agent ("I used this chunk", "this supports the answer", "this is relevant"). Cryptographically bound to the receipt so the agent cannot deny what it asserted. Provenex does not verify the claim itself — that is the agent operator's compliance burden, made auditable by the signature.
- **`content_source`** — origin classifier (`indexed_corpus`, `live_tool_output`, `memory_store`, `compiled_artifact`). Lets an auditor reading an `UNVERIFIED` outcome distinguish "this chunk was supposed to be in the index and wasn't" (alarm) from "this came from a live web search" (expected).

See [`docs/quickstart.md`](https://github.com/provenex/provenex-core/blob/main/docs/quickstart.md) for a runnable agentic example.

## How it works

Four components:

**1. Ingestion.** Documents are normalized (Unicode NFC, whitespace collapse, optional case folding, zero-width stripping) and run through a sliding window. Each window gets a Rabin-Karp rolling hash (base `1_000_003`, modulo Mersenne prime `2^61 - 1`) for cheap O(1) updates, strengthened with SHA-256 for collision-resistant identity. The fingerprints (not the document content) are written to the provenance index along with `document_id`, `document_version`, timestamp, authorization state, and customer-supplied tags. The index never stores document text.

**2. Verification.** When your retriever returns chunks, Provenex re-fingerprints each one using the same normalization and hash pipeline, checks the fingerprint against the index, and assigns one of five outcomes (`VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`). A configurable `policy.verification` decides which outcomes are blocked before the next stage.

**3. Policy evaluation.** Each chunk that survived the verification gate goes through the configured policy evaluator (native YAML in the open-source core; Rego and OPA service commercial). The evaluator returns allow or deny plus the names of the rules that fired. The chunk reaches the LLM only if both gates allow it.

**4. Receipt.** After verification and policy evaluation, a JSON receipt is issued that records the chunks, their verification outcomes, the policy that was in effect (both halves), the per-chunk decisions and rules fired, a SHA-256 of the LLM output, and a signature over the whole thing.

For iterative agentic flows, each retrieval step emits its own receipt with a `trajectory` block linking it to its parents — see [Agentic and multi-step flows](#agentic-and-multi-step-flows). The five verification outcomes and the policy framework are unchanged; the trajectory metadata sits alongside them.

See [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md) for the full algorithm, including the architectural distinction between fingerprint-based identity and embedding-based similarity. See [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md) for the schema spec.

## How this fits alongside vector databases (and OPA)

Vector databases store **semantic similarity**: dense embeddings that let you find content similar to a query. Provenex stores **cryptographic identity**: SHA-256 fingerprints that prove bit-exact match against a signed reference, plus a policy evaluation layer over operator-declared rules. These solve different problems and compose cleanly.

| | Vector DBs | Provenex |
| --- | --- | --- |
| Primary storage | Dense embeddings (semantic similarity) | SHA-256 fingerprints (cryptographic identity) + signed metadata |
| Retrieval | Approximate nearest neighbor over vectors | Bit-exact match against signed index |
| Tampering | Not detectable. Embeddings are lossy by design | Detectable. Any modification produces a different SHA-256 |
| Policy enforcement | Tag-based filters at query construction | Evaluator-agnostic rule engine + signed decision record |
| Audit artifact | Vendor dashboard, internal logs | Signed JSON receipt, verifiable offline |
| Trust root | Vendor's SOC 2 attestation | HMAC (or Ed25519) signature, verifiable by anyone with the key |
| Vendor lock-in | Yes (per database) | None. Works alongside any retriever |

The expected enterprise deployment is **both**: vector DB for retrieval performance, Provenex for the policy enforcement record.

### Composing with OPA and existing data governance tools

Provenex sits **above** your existing governance plumbing, not in place of it. PII detection happens in your data pipeline; classification happens in your data catalog; identity is owned by your IdP; authorization rules are authored in OPA / Rego if that's your house language. Provenex consumes the tags and identity those systems produce, applies the policy at retrieval time, and emits the signed record. The Rego adapter (commercial) lets you reuse Rego policies you already have; the OPA service adapter (commercial) lets you delegate decisions to a running OPA instance. The native YAML DSL exists for teams who don't already run OPA — it covers the common retrieval policies without forcing a new platform commitment.

### Why vendor-agnostic matters

If you run more than one vector DB across the enterprise — common for cost or latency reasons — you have separate audit stories with separate vendor trust roots, and no way to produce a single signed record that says "this chunk, wherever it came from, was bit-exact identical to the one we authorized AND passed the policy in effect for this caller."

Provenex works the same way against all of them, because it never talks to the vector DB. It re-fingerprints the chunks the retriever returns, runs the same unified policy across every retrieval path, and emits the same receipt schema. One signed index, one policy engine, one verifiable artifact across every retrieval path in the enterprise. **Migration risk between vector DBs goes to zero.**

## Install

```bash
pip install provenex-core                  # core only (pure stdlib)
pip install "provenex-core[policy]"        # + native YAML policy DSL (PyYAML)
pip install "provenex-core[langchain]"     # + LangChain integration
pip install "provenex-core[langgraph]"     # + LangGraph integration
pip install "provenex-core[llamaindex]"    # + LlamaIndex integration
pip install "provenex-core[crewai]"        # + CrewAI integration
pip install "provenex-core[ed25519]"       # + Ed25519 asymmetric signing
```

Python 3.10+. The core has zero third-party dependencies; it's pure stdlib. Framework integrations, the native YAML DSL, and the Ed25519 signer are optional extras.

### Try it in 30 seconds

```bash
pip install "provenex-core[policy]"
git clone https://github.com/provenex/provenex-core.git
export PROVENEX_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
python provenex-core/examples/standalone_demo.py
```

For the integration-pattern story, run [`examples/rag_with_provenance.py`](https://github.com/provenex/provenex-core/blob/main/examples/rag_with_provenance.py). Watch a poisoned chunk that was added directly to the vector store, bypassing Provenex ingest, get caught at the retrieval boundary and blocked from reaching the LLM.

## CLI

```bash
provenex ingest  --index prov.db --doc-id policy_v4 policy.txt
provenex verify  --index prov.db retrieved_chunk.txt
provenex receipt --index prov.db --output llm_output.txt chunk1.txt chunk2.txt
provenex audit   receipt.json
provenex audit   receipt.json --show-policy          # render the unified policy block
provenex audit   --trajectory ./receipts/            # validate a whole agentic trajectory at once
provenex policy  validate hr_policy.yaml             # parse + validate a policy file
provenex policy  hash     hr_policy.yaml             # print canonical policy_version_hash
```

`provenex policy validate` is the CI-time check for policy files: a typo or a reserved-but-unimplemented feature fails the build instead of silently allowing at runtime. `provenex policy hash` prints the canonical `policy_version_hash` that will appear on every receipt produced under that policy.

For receipts signed with **Ed25519** (asymmetric), pass `--public-key audit.pub` instead of relying on `PROVENEX_SIGNING_SECRET`. An auditor with only the public key can verify but cannot forge: the strongest version of the "verifiable by anyone" guarantee, suitable for handing receipts to external regulators.

## Why open source?

Security teams won't trust a black box. If a regulator asks how your access-policy enforcement system works, "it's proprietary" is not an answer. The whole algorithm needs to be auditable end to end: normalization, rolling hash, sliding window, SHA-256 strengthening, policy evaluator semantics, receipt schema, signature payload. So it is.

### Open source (this repo, MIT)

- Fingerprinting engine (normalizer + Rabin-Karp + SHA-256)
- Local SQLite provenance index with HMAC-signed rows
- RFC 6962 Merkle transparency log (optional, on top of the SQLite index)
- Receipt generation, HMAC + Ed25519 signing, offline inclusion-proof verification
- **Unified policy** (schema 2.1.0): single top-level `policy` block with `verification` and `access_control` halves
- **Native YAML data-access policy DSL**: pluggable `PolicyEvaluator` protocol with the YAML evaluator as the reference backend
- **`metadata_binding`** per decision: each `chunk_metadata` block on the receipt declares whether it was tag-at-ingest (signed by the index row) or tag-at-evaluate (looked up at decision time). Lets an auditor see the trust class of every input at a glance.
- **Bloom-filter interface** (`BloomFilterIndex` ABC + `NoopBloomFilter` + `BloomAcceleratedIndex` wrapper). The interface is OSS so commercial deployments are drop-in; the actual high-throughput Bloom implementation ships commercially.
- Trajectory receipts (schema 1.3.0+): per-step receipts linked into a DAG for agentic / multi-step flows
- Self-attribution claims (schema 1.4.0+): signed but unverified records of what the agent said it used
- Content-source classifier (schema 1.4.0+): distinguish indexed-corpus chunks from live-tool / memory-store chunks
- LangChain / LangGraph / LlamaIndex / CrewAI integrations
- Framework-agnostic `provenex.verify_chunks(...)` for everything else
- CLI: `provenex ingest / verify / receipt / audit / policy`
- Python SDK: `pip install provenex-core`

### Commercial (at provenex.ai)

- **Rego adapter** — load Rego bundles into the same `PolicyEvaluator` protocol; emit the same receipt shape
- **OPA service adapter** — delegate evaluation to a running OPA instance over HTTP
- Hosted provenance index with distributed signed append-only storage
- Transparency-log-backed policy bundle records (so `policy_in_transparency_log: true` lights up)
- **Bloom-filter implementation** for high-throughput verification at 10M+ chunk scale (the OSS ships the interface; commercial ships the working filter)
- Compliance-grade export formats (PDF, CSV, JSON-LD for regulator-side / semantic-web consumers)
- Identity-provider integration (RequestContext auto-populated from Okta / Azure AD)
- Inference attribution and temporal decay scoring
- Enterprise SSO / RBAC, HSM-backed Ed25519, dedicated support, SLA

The interfaces (`ProvenanceIndex`, `PolicyEvaluator`, `BloomFilterIndex`) are the same across open source and commercial. Moving from one to the other is one line of code: the class you instantiate.

## Privacy and data sovereignty

The index stores fingerprints (one-way SHA-256 hashes) and metadata. **No document content, no PII, no chunk text is ever written.** Anyone with the index can verify retrieval, but no one can recover document content from it. The `policy.access_control.decisions[].inputs` field on the receipt records the metadata the evaluator looked at (residency tags, classification, caller role) — operators who want to redact those can set `inputs: null` while keeping the `inputs_hash` for offline verification.

## License

MIT. See [LICENSE](https://github.com/provenex/provenex-core/blob/main/LICENSE).

## Links

**Reading:**

- [Five Things People Mean by "AI Provenance" (And Which One Is For You)](https://provenex.ai/blog/five-things-ai-provenance): the category map, and where Provenex sits
- [`docs/policy.md`](https://github.com/provenex/provenex-core/blob/main/docs/policy.md): unified policy reference (verification + access control), DSL, worked examples, commercial roadmap
- [`docs/how_it_works.md`](https://github.com/provenex/provenex-core/blob/main/docs/how_it_works.md): full algorithm, threat model, and architectural comparison to embedding-based systems
- [`docs/receipt_format.md`](https://github.com/provenex/provenex-core/blob/main/docs/receipt_format.md): receipt schema 2.0.0 specification
- [`docs/quickstart.md`](https://github.com/provenex/provenex-core/blob/main/docs/quickstart.md): 5-minute getting-started, including a policy-driven retrieval path
- [`docs/threat_model.md`](https://github.com/provenex/provenex-core/blob/main/docs/threat_model.md): attacker model, defended/undefended threats, trust model for policy decisions
- [`docs/scaling.md`](https://github.com/provenex/provenex-core/blob/main/docs/scaling.md): 1M-chunk benchmark numbers and policy-evaluation latency profile

**Project:**

- Homepage: [provenex.ai](https://provenex.ai)
- Issues and discussion: GitHub Issues on this repo
- Commercial features: contact via provenex.ai
