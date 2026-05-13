# Show HN draft

A draft of the Show HN / launch post for Provenex 0.1.0. Aimed at a
technical audience that respects honest pushback, dislikes AI hype,
and appreciates a small auditable codebase.

---

## Suggested submission

**Title** (under 80 chars; HN truncates aggressively):

> Show HN: Provenex – cryptographic transparency log for RAG retrieval

**URL**:

> https://github.com/provenex/provenex-core

**Text body** (under ~700 chars on HN's submission form):

> A small library (1,200 LoC, pure stdlib core) that produces signed,
> verifiable provenance receipts for RAG pipelines. Every retrieval
> emits a JSON receipt with SHA-256 fingerprints of every chunk that
> reached the LLM, plus an RFC 6962 Merkle inclusion proof you can
> verify offline against a published tree root.
>
> The cryptographic story is the differentiator from vector-DB
> governance (Pinecone Nexus, Weaviate, etc.). Provenex doesn't replace
> your vector DB; it runs alongside as a parallel signed index.
> Pinecone/Weaviate/Milvus/Qdrant/FAISS/pgvector all work unmodified.
>
> 1M chunks ingested in 12 minutes on a 2018 laptop. Offline proof
> verification: 47 µs (any chunk, any time, no DB). MIT, on PyPI.
> Comments and demolitions welcome.

---

## First comment (sometimes the better place for the substantive intro)

If the URL submission feels light, paste this as the first comment so
the substance shows up immediately:

> Hi HN, builder here. Quick context on what's interesting (and what
> isn't) before the obvious "how is this different from $vendor" wave:
>
> The trick that makes Provenex useful is that it composes RFC 6962
> Certificate-Transparency-style signed logs with per-row HMAC. The
> HMAC catches anyone tampering with rows; the Merkle tree catches a
> key-holder inserting or removing rows after the fact. The two layers
> together let a regulator hold a receipt and a previously-published
> tree root and re-verify the whole story offline, no DB, no network,
> no signing key.
>
> What it ISN'T:
>
> - A vector DB. Provenex never talks to Pinecone/Weaviate/Milvus/etc.
>   It just re-fingerprints the chunks they return.
> - A hallucination detector. We record what the LLM SAW, not what it
>   did with it. Faithfulness is a different layer.
> - Magic AI safety. It's a transparency layer. Same kind of guarantee
>   as a signed audit log: tamper-evident, externally verifiable.
>
> The threat model is in docs/threat_model.md if anyone wants to throw
> rocks at it. The 1M-scale bench numbers are in docs/scaling.md and
> are reproducible (one shell command, single-threaded, no GPU).
>
> Genuinely curious which part of the design feels weakest under hostile
> scrutiny. The hosted commercial version (Bloom-filter acceleration,
> cross-org provenance graphs, HSM-backed asymmetric keys) is what we
> sell; this core is MIT and meant to be auditable.

---

## Notes on timing + venue

- Best HN posting windows for technical content: Tuesday-Thursday,
  8-10am Eastern. Weekend posts get half the engagement.
- `Show HN:` prefix is enforced by mods for "I built this" content.
  Stating it explicitly increases on-topic comments.
- Cross-post to /r/MachineLearning the day AFTER HN. Different audience,
  different vocabulary, but the threat-model + transparency-log angle
  reads well there too.
- Twitter/X: lead with the standalone-demo asciicast (when recorded)
  rather than the text. The "delete the database, re-verify the proof"
  moment is the visual hook.

## Things to be ready for

- "Why not just use a database WAL / SQL audit trigger?" → because the
  receipt is publishable, verifiable by a third party, and survives
  vendor migrations. WAL doesn't leave your DB.
- "How is this different from Pinecone Nexus?" → Nexus is governance
  inside Pinecone. Provenex is vendor-agnostic by construction.
  See the comparison table in the README.
- "Isn't this just HMAC over rows?" → No, the Merkle layer is what
  makes it verifiable WITHOUT the signing key. RFC 6962 is the
  reference implementation pattern.
- "What's the catch?" → Honestly: ingest is single-threaded today
  (1.4k chunks/sec). Parallelism is the next big unlock. We're upfront
  about this in docs/scaling.md.
- "How do I trust the maintainers won't backdoor it?" → It's MIT, the
  code is small (read it), and there's a CI pipeline. Beyond that you
  bring your own audit. The hosted product offers SOC 2 and
  cross-org gossip of tree heads.

## What NOT to do in the launch thread

- Don't argue with people who didn't read the README. Link to the
  specific section and move on.
- Don't promise features that aren't shipped. The phase-2 RAG overhead
  bench is documented as design, not as measurement; leave it that way.
- Don't downplay limitations. "We don't detect hallucinations" is
  honest and disarming. Avoid hedging.
