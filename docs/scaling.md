# Provenex at scale

Measured numbers from a single 1,000,000-chunk run, with an honest
discussion of how each workload should move on server-class hardware.

> **Headline.** One million chunks ingested in **12.2 minutes** on a 6-core
> 2018 mobile laptop. Verification settles at **p50 371 µs / p99 599 µs**.
> Inclusion proofs are **20 hashes** (≈ log₂(1M)), generated in **403 µs**
> at p50 and verified offline against the tree head in **47 µs**.

The bench is single-threaded by design. The numbers below describe what
one Python process can do end-to-end, not the ceiling of the
architecture. See the [scaling discussion](#what-changes-on-enterprise-hardware)
below for what those numbers should look like on production hardware.

---

## What was measured

| Workload | What it exercises |
|---|---|
| **Ingest** | SHA-256 fingerprint → SQLite write → Merkle tree update, sequentially per chunk |
| **Verify** | Single-fingerprint lookup against the index; produces one of the five outcomes (`VERIFIED`, `UNVERIFIED`, `MISMATCHED`, `STALE`, `REVOKED`) |
| **Proof generation** | Pull the inclusion proof (~log₂ N hashes) for a known fingerprint out of the Merkle index |
| **Proof verification (offline)** | Verify the proof against the tree head with no index access (what an external auditor does) |

The same `Fingerprinter` and `MerkleSQLiteProvenanceIndex` an application
would use are exercised directly. No monkey-patching, no private
internals. What the bench measures is what an application will see.

---

## Hardware under test

| Component | Value |
|---|---|
| CPU | Intel Core i7-8750H (Coffee Lake-H, 6c/12t, base 2.2 GHz, turbo 4.1 GHz) |
| Memory | 16 GB DDR4 |
| Storage | Internal NVMe SSD (Apple stock) |
| OS | macOS 12.4 |
| Python | 3.12.10 (Python.org build, dynamic OpenSSL 3.0.16) |

Two things to keep in mind when interpreting these numbers:

1. **No SHA-NI.** Coffee Lake-H does not have Intel's SHA-256 hardware
   acceleration (introduced in Goldmont and Ice Lake). All SHA-256 work
   is software. Server CPUs from ~2019 onward (Ice Lake-SP, Cascade
   Lake, EPYC Rome+, Graviton2+, Apple M1+) all have hardware SHA-256.
2. **Mobile thermal envelope.** Sustained turbo isn't guaranteed. The
   chip's TDP is 45 W and ingest is a 12-minute hot loop. Desktop or
   server parts hold their boost clocks indefinitely.

---

## Headline numbers (1M-chunk synthetic corpus)

### Ingest

| Metric | Value |
|---|---|
| Chunks ingested | 1,000,000 |
| Wall time | 12.2 min |
| Sustained throughput | **1,400 chunks/sec** |
| Final index size | 986.9 MB (**1,035 bytes/chunk**) |
| Fingerprint latency | p50 **70 µs**, p95 132 µs, p99 181 µs |
| Index-add latency | p50 **184 µs**, p95 325 µs, p99 1.06 ms |

The index-add p99 (1 ms) and p999 (40 ms) are SQLite page-flush spikes,
expected on consumer SSDs running WAL with `synchronous=NORMAL`.

### Verify

| Metric | Value |
|---|---|
| Sample size | 10,000 (90% known, 10% synthetic-unknown) |
| Sustained throughput | **3,300 verifications/sec** |
| p50 / p95 / p99 / p999 | **371 µs / 417 µs / 599 µs / 705 µs** |
| Max observed | 1.50 ms |

The 90/10 split exercises both the `VERIFIED` and `UNVERIFIED` outcome
paths.

### Inclusion proof

| Metric | Value |
|---|---|
| Proof size | **20 hashes** (≈ ⌈log₂(1,000,000)⌉ = 20), constant max |
| Proof-generation p50 / p95 / p99 | **403 µs / 424 µs / 444 µs** |
| Offline-verification p50 / p95 / p99 | **47 µs / 48 µs / 51 µs** |
| Sustained throughput | 2,400 proofs/sec generated + verified |

**This is the headline number for the product.** An auditor with
the receipt and the published tree head can re-verify any chunk in
47 microseconds. No index, no database, no network needed. The proof
is 20 hashes (640 bytes) regardless of corpus size up through 1M;
doubling the corpus to 2M adds one hash, four billion chunks would
still fit in 32 hashes.

### Policy evaluation (schema 2.0.0 access-control gate)

| Metric | Value (10k synthetic) |
|---|---|
| Sample size | 1,000 evaluations |
| Sustained throughput | **30k+ evaluations/sec** |
| p50 / p95 / p99 / p999 | **22 µs / 34 µs / 38 µs / 54 µs** |
| Max observed | 64 µs |
| Rules in policy | 3 (jurisdiction, PII gate, freshness) |

The native YAML evaluator runs well under verification latency - the
access-control gate is not the bottleneck. A typical 5-10 chunk
retrieval adds <0.5 ms of policy overhead on top of verification.
The policy is independent of corpus size: latency depends on the
number of rules and the depth of metadata paths, not on the index.

Run the policy bench with: `python -m bench.scale --scale 10k --policy-samples 10000`

---

## Real-data validation (Wikipedia 100K)

The 1M numbers above use a synthetic corpus: random ASCII with a
log-normal chunk-length distribution. A reasonable skeptic asks: do
those numbers hold up on real text? To answer it, we ran the same bench
at 100K against a snapshot of 5,600 Wikipedia articles, chunked at 800
characters the way a real RAG pipeline would (see
`bench/wiki_corpus.py`). Same code path, same configuration, only the
source of the bytes changed.

Run conditions matched: both ran on the same laptop within four
minutes of each other, same warm state, same Python process startup.

| Metric | Synthetic 100K | Wikipedia 100K | Verdict |
|---|---|---|---|
| Ingest wall time | 60 s | 63 s | within noise |
| Ingest throughput | 1.7k chunks/s | 1.6k chunks/s | within noise |
| Index size on disk | 1,035 B/chunk | 1,039 B/chunk | **equivalent** |
| Mean proof size | 16.909 hashes | 16.909 hashes | **identical** (tree shape) |
| Verify p50 | 37.6 µs | 37.7 µs | **identical** |
| Verify p99 | 54 µs | 83 µs | wiki +50% (still well below 100 µs) |
| Proof gen p50 | 30.6 µs | 32.0 µs | within noise |
| Proof verify (offline) p50 | 26.9 µs | 27.6 µs | within noise |
| Fingerprint p50 | 67 µs | 93 µs | **wiki +39%** (see below) |

**The metrics that matter (verify, proof generation, offline proof
verification, index footprint) are statistically indistinguishable on
real vs synthetic data.** The system doesn't care what the text says;
it cares about chunk count and chunk length, and those are matched.

The one meaningful divergence is **fingerprinting**: Wikipedia chunks
are ~40% slower per chunk. The cause is the chunk-length distribution,
not the content. Real Wikipedia text chunks land tightly around the
target 800-char window (the chunker takes what the article gives it,
in fixed-ish windows), while the synthetic corpus draws chunk lengths
from a log-normal distribution with σ=0.4. So the synthetic mean
chunk is shorter, which means fewer sliding-window SHA-256 calls per
chunk. This is a chunk-shape effect; it isn't "Wikipedia is harder."
Any real RAG pipeline using a standard fixed-window splitter
(`RecursiveCharacterTextSplitter`, `TokenTextSplitter`) will see the
Wikipedia number, not the synthetic one. Both are still on the same
side of the order-of-magnitude line for ingest throughput.

**Implication for the 1M synthetic numbers.** Treat verify, proof gen,
proof verify, and the index footprint at 1M as transferring directly to
real RAG workloads. Treat the ingest-throughput number (1.4k/s) as a
slight overestimate on real text. Expect closer to 1.3k/s on real
chunks of the same target size, dominated by the same Python-overhead
bottleneck. None of this changes the headline claim.

---

## Interpreting the numbers

### Per-workload bottleneck

| Workload | Primary bottleneck | Secondary |
|---|---|---|
| Fingerprint | Python interpreter overhead (~50-60 µs) | SHA-256 compute (~5 µs software) |
| Index add | SQLite write + Merkle tree update | Page cache pressure as DB grows |
| Verify | SQLite point lookup | Five-outcome state machine (negligible) |
| Proof gen | SQLite reads of Merkle internal nodes | Hash assembly |
| Proof verify (offline) | SHA-256 of 20 internal nodes | Pure CPU; no IO |

The per-chunk fingerprint at 70 µs is dominated by Python overhead, not
the cryptographic work itself. An 800-char chunk needs roughly 12
sliding-window hashes; each `hashlib.sha256()` call costs a few
microseconds in interpreter dispatch alone. SHA-NI would shave the
SHA-256 portion but leave the dispatch cost. **The realistic
single-thread fingerprint ceiling on faster hardware is ~30-40 µs**, not
the 5× speedup the hash itself would imply.

### Index footprint

At ~1 KB per chunk we're carrying the original metadata row (document
id, version, offset, length, outcome state), an index entry on the
fingerprint, **and** the Merkle tree internal nodes. The tree alone
adds ~32 bytes per leaf in internal-node storage (2N nodes for N leaves,
half the size of leaves on average). A bare key-value store without the
Merkle layer would be ~600 bytes/chunk; the **~400 byte premium pays
for tamper-evidence**.

### What the proof story buys you

The 20-hash proof + 47-µs offline verify is what differentiates this
from a vector-DB-plus-audit-log approach. A customer can:

1. Get a receipt back from their retrieval API.
2. Cache the published tree head out-of-band (signed, immutable).
3. Re-verify the receipt years later, from a different machine, with
   no access to the original index, in under a millisecond.

Nothing else in the RAG provenance space gives you that. Vector DBs
give you "we found this at retrieval time"; transparency-log-style
proofs give you "and here's why you can prove it five years from now."

---

## What changes on enterprise hardware

No single multiplier applies across deployments; benchmarks should be
run on the target hardware. The discussion below names the factors
that move performance and gives a **range**.

### CPU axis

| Improvement source | Helps which workload | Expected magnitude |
|---|---|---|
| **Hardware SHA-256 (SHA-NI / ARMv8 crypto)** | Offline proof verify; minor on fingerprint | 2-3× on pure-SHA paths (offline verify); ~10-20% on fingerprint (mostly Python overhead) |
| **Higher sustained clock** (4.5-5.0 GHz vs 2.2 GHz base) | All Python-bound paths | 1.5-2× on fingerprint, verify, proof gen |
| **Larger L3 + better mem bandwidth** | Verify and proof gen as index grows | Modest, single-digit % |
| **Single-thread perf (IPC)** | All Python paths | ~10-30% generation-over-generation |

A reasonable bound on a current-gen server CPU (Sapphire Rapids,
Genoa, Graviton4, M3 Max) running the **same single-threaded code**:
fingerprint ~30-45 µs, verify ~150-250 µs, proof gen ~150-250 µs,
offline verify ~15-25 µs. Sustained ingest throughput **on a single
process** likely lands in the **3,000-5,000 chunks/sec** range.

### IO axis

| Improvement source | Helps which workload | Expected magnitude |
|---|---|---|
| **Enterprise NVMe with battery-backed write cache** | Index add (SQLite WAL flushes) | 2-5× on the p999 tail of index_add |
| **More RAM (so the index page-caches fully)** | Verify and proof gen | Pulls p99 closer to p50 |

### Parallelism: the big lever, not yet enabled

The bench is single-threaded. Real production deployments will want to
parallelize ingest. The two natural cut points:

1. **Per-document parallel fingerprinting.** Each chunk's SHA-256 is
   independent; a `concurrent.futures.ProcessPoolExecutor` over chunks
   would scale near-linearly in cores until SQLite write contention
   dominates. On a 16-core box: expect **8-12× ingest speedup** from
   this alone, dropping a 1M-chunk run from ~12 min to **~1-2 min**.
2. **Sharded indexes per document range.** For multi-tenant workloads
   where tenants don't share a tree, run N independent indexes. Scales
   linearly in cores and disks.

The Merkle root must still be computed serially over the leaves the
sharded workers produced. That's a low-microsecond step once you have
all the leaf hashes.

**We have not run these experiments yet.** The numbers in this section
are upper bounds based on the workload's structure, not measurements.
Production deployments should benchmark their actual concurrency
pattern before sizing.

### Putting it together

For an enterprise sizing the system, a defensible projection is:

| | This laptop (measured) | Modern server, single-process (estimate) | Modern server, parallel (estimate) |
|---|---|---|---|
| Ingest (chunks/sec) | 1.4k | 3-5k | 15-40k |
| Verify p99 | 599 µs | 250-400 µs | same (verify is per-request) |
| Proof gen p99 | 444 µs | 200-300 µs | same |
| Offline-verify p99 | 51 µs | 20-30 µs | same |
| 1M-chunk ingest wall time | 12.2 min | 3-6 min | **~1-2 min** |

Verify, proof gen, and offline verify don't benefit from server-side
parallelism because each is already a single request. They benefit
from clock and SHA-NI.

---

## Reproducing

```bash
# Synthetic 1M:
python -m bench.scale --scale 1m

# Synthetic 100k (~30 s):
python -m bench.scale --scale 100k

# Real text (Wikipedia snapshot, requires one-time fetch):
python -m bench.wiki_fetch --count 8000  # ~10-15 min, one-time
python -m bench.scale --scale 100k --corpus wiki
```

Same `--seed` reproduces bit-identical fingerprints and the same tree
head; latency distributions will vary with hardware noise but the shape
should hold.

Each run writes `bench_<scale>_<corpus>_<timestamp>.{json,md}` into
`bench_reports/`. The JSON file has the full histograms (`p50`, `p95`,
`p99`, `p999`, `max`, mean) and is the source of truth. The markdown
is a human summary.

---

## Design: end-to-end RAG overhead bench

The numbers above answer "how fast is Provenex on its own?" They do not
answer the question a buyer will ask, which is:

> If I bolt Provenex onto our existing RAG pipeline, how much slower
> does it get?

The answer ought to be: very little on the query side, and on the
ingest side the cost is dominated by your embedder, not by us. The
overhead bench would measure that directly.

### Proposed harness

```
ingest path (measured per chunk):
    text  →  chunker  →  embedder  →  vector_store_add
                                  └→  provenex.add        # the new cost

query path (measured per query):
    query →  embedder  →  vector_store.search(top-k)
                                          ↓
                                 [top-k chunk ids + scores]
                                          ↓
                                  provenex.verify(*)      # the new cost
                                          ↓
                                  answer + receipts
```

Two configurations, A/B compared:

| Config | Ingest steps per chunk | Query steps per request |
|---|---|---|
| **Baseline RAG** | chunk, embed, vector-add | embed query, ANN search top-k |
| **+ Provenex** | chunk, embed, vector-add, **provenex.add** | embed query, ANN search top-k, **verify top-k** |

The deltas are what we publish.

### Component choices

| Component | Pick | Why |
|---|---|---|
| Embedder | `sentence-transformers/all-MiniLM-L6-v2` (22 MB, ~10 ms/chunk on CPU) | Smallest credible model; well-known; CPU-only so the bench stays portable |
| Vector store | FAISS CPU (`IndexFlatIP` or `IndexHNSWFlat`) | The standard OSS baseline; no service to stand up |
| Corpus | The same Wikipedia snapshot the [validation bench](#real-data-validation-wikipedia-100k) uses | One snapshot, one set of results to reason about |
| Query set | 1,000 article-derived queries (first paragraph of held-out articles) | Deterministic and self-contained, no BEIR dependency |

### What we'd expect

- **Ingest overhead:** `provenex.add` at 184 µs vs an embedder at ~10 ms is **~2% extra latency**. The marketing-true sentence is "Provenex is a rounding error on your ingest pipeline."
- **Query overhead:** verify at 371 µs × top-k (say k=10) = **~3.7 ms** added to a query that already costs ~10 ms (embed) + 1-5 ms (ANN). Roughly **30-50% additive on query latency**, which is honest. Verification isn't free, but it's bounded and predictable.

Those numbers are the prediction; the phase-2 bench is what turns them
into measurements.

### Why this isn't built yet

Adding sentence-transformers + faiss-cpu as dependencies takes the
bench out of "stdlib-only-friendly" territory. Building this is a
separate, deliberate step, not something to bolt on to the existing
scale bench.

---

## Multi-node deployment shape (Postgres backend)

The benchmarks above were run against `MerkleSQLiteProvenanceIndex` -
single process, single file, the simplest possible deployment. Real
enterprise deployments run multiple application pods across multiple
clusters and need a backend that handles concurrent ingest and
horizontally-scaling reads. For that, point Provenex at Postgres:

```python
from provenex import PostgresProvenanceIndex

index = PostgresProvenanceIndex(
    dsn="postgresql://provenex:secret@db.internal:5432/provenex",
)
```

Same `ProvenanceIndex` interface as the SQLite backend, same canonical
HMAC payload, same receipt schema. A receipt produced against one
backend verifies identically against the other - so you can develop on
SQLite locally and run on Postgres in production without any signing
or audit-trail discontinuity.

### Recommended topology

| Tier | Backend | Pods | Reason |
|---|---|---|---|
| **Verify** (per-request, latency-critical) | Postgres read replicas | Many | Verify is a point-lookup on the indexed `fingerprint` column. Scales horizontally across replicas. |
| **Ingest** (batch, throughput-oriented) | Postgres primary | One ingester pod recommended | Postgres handles multi-writer ingest correctly (row-locked supersession), but the Merkle-augmented index keeps an in-process tree that is per-process. Single ingester avoids tree-divergence under multi-writer until that becomes a multi-process tree (commercial roadmap). |

For deployments that only need the non-Merkle properties - verification,
five outcomes, signed rows, no transparency log - multiple ingester pods
are fully supported on `PostgresProvenanceIndex`. The single-ingester
recommendation only applies to `MerklePostgresProvenanceIndex`.

### What we expect on Postgres

We have not yet published Postgres-specific benchmarks. Two things to
keep in mind when sizing:

1. **Verify latency** is dominated by a single B-tree point-lookup on
   `fingerprint`. On a warm Postgres with the index resident in shared
   buffers, expect **p50 sub-millisecond, p99 < 5 ms** including network
   round-trip from the application pod. The previous SQLite numbers
   (verify p50 371 µs) are a useful floor; Postgres adds RTT but parallelises
   across pods.
2. **Ingest throughput** on a single primary is bounded by
   transaction commit and WAL flush - typically **5-15k commits/sec**
   on managed Postgres with the write cache enabled. Batching ingest
   across documents (multiple chunks per transaction) is the right
   tuning lever.

### Deployment patterns for big-enterprise / polyglot stacks

The benchmark numbers above are for one Python process. Real enterprise
deployments have three structural questions on top of that:

1. **Does every host need the SDK?** The short answer is: every host
   that *ingests* or *verifies* needs the SDK. The witness pod is a
   single cron job; the auditor is the regulator's machine and runs
   offline. So "every host" really means "every retrieval-path pod" -
   the same set of pods that already call your vector store.

2. **What about Java / Go / Rust / Node stacks?** The Python SDK
   doesn't run inside those. Three patterns cover this, and the right
   choice depends on how much per-pod state you tolerate.

3. **How does this scale past one verify pod's RPS limit?** Postgres
   reads are a B-tree point-lookup, so they scale with replicas.
   Connection count is the bottleneck before query latency.

The three SDK distribution patterns:

| Pattern | What it looks like | When to use | Trade-off |
|---|---|---|---|
| **A. SDK on every host** | Each app pod imports `provenex`, connects directly to Postgres, signs locally. The library shape the demos show. | Python-native stacks. The default. | Per-pod Python overhead; pod density limited by Python runtime size. |
| **B. Sidecar container** | One Provenex sidecar per app pod, app talks to it via local HTTP / gRPC over the pod network. Sidecar handles fingerprinting, verify, signing, and the Postgres pool. | Polyglot enterprises - Java, Go, Rust, Node apps need only a thin HTTP client. | Extra hop (microseconds within a pod), one container per app pod. |
| **C. Centralized verify service** | Three to five Provenex pods serving as a shared HTTP service. All app pods call it. | Enterprises that refuse per-pod runtime cost; "treat Provenex like any other internal microservice." | Introduces a service dependency. "Decision and proof, not execution" still holds (we never sit on the data path), but Provenex becomes a critical-path internal service rather than a library. |

The HTTP-server side of patterns B and C is not part of the OSS
core today. The library exposes the primitives a server wrapper
needs (`verify_chunks`, `admission_check`, `compute_request_binding`);
a thin FastAPI or aiohttp wrapper of roughly 200 lines closes the
gap.

### Sizing the Postgres connection layer

The single biggest scale lever for pattern A or C is not Provenex
itself - it is **PgBouncer in front of Postgres**. Each verify pod opens
its own `psycopg_pool.ConnectionPool` (default min 1, max 10). At 100
verify pods that is 1,000 direct connections to Postgres, which most
managed Postgres tiers cap below.

Recommended topology for enterprise scale:

```
[ app pods x N ]
       |
       |   (or sidecar, or centralized service)
       v
[ Provenex pods x N - same library, same DSN ]
       |
       v
[ PgBouncer in transaction mode ] - 50-200 server connections
       |
       v
[ Postgres primary + N read replicas ]
       |
       +--> WAL --> [ archival / cross-region replica ]
```

What this buys you:

- **Connection multiplexing**: 10,000 client connections to PgBouncer
  collapse to ~100 server connections to Postgres. The benchmark
  bottleneck shifts from "Postgres ran out of connection slots" to
  actual query throughput.
- **Read replicas absorb verify load**: Provenex's verify path is a
  pure `SELECT` against an indexed column. Point verify pods at a
  read replica DSN; point the ingester pod at the primary. Postgres
  read replicas scale linearly with replicas added.
- **WAL archival**: orthogonal to Provenex; standard Postgres backup
  discipline. Provenex receipts and the witness log live outside
  Postgres, so even total Postgres loss does not invalidate
  already-issued receipts.

### Which pods need Provenex installed?

| Pod / process | Provenex SDK required? | Postgres connection? | Signing key? |
|---|---|---|---|
| Ingester (batch) | Yes | Yes (primary) | Yes (index secret) |
| Verify (per-request retrieval) | Yes | Yes (read replica OK) | Yes (receipt secret) |
| Witness publisher (cron) | Yes | Yes (read replica) | Yes (receipt secret) |
| App pods (request handlers, in pattern A) | Yes | Yes | Yes |
| App pods (pattern B with sidecar) | **No** | No | No |
| App pods (pattern C with central service) | **No** | No | No |
| Regulator / external auditor | Optional - the auditor logic is in `provenex audit`, but receipts are also verifiable in any language that does SHA-256 + Ed25519 | **No** | **No** (only the Ed25519 public key) |

The "no" rows are the polyglot-stack unlocks. Pattern B is the standard
sidecar idiom; pattern C is the standard internal-service idiom. Both
treat Provenex as a black box from the app's perspective.

### When the SDK overhead actually shows up

The benchmark numbers (verify p50 371 µs on SQLite) translate to roughly
**2,500 verify-per-second per Python process** on commodity hardware
before Python overhead dominates. Above that, the levers in order:

1. **Add verify pods** - linear scaling up to PgBouncer connection
   limits.
2. **Add Postgres read replicas** - point new verify pods at new
   replicas.
3. **Move to a batched `verify_chunks_batch` API** (not yet shipped) -
   amortises the per-call Python overhead (parsing, receipt
   construction, signing) across N chunks. Roughly 5-10x throughput
   improvement on multi-chunk-per-request workloads.
4. **Bloom filter acceleration** (commercial) - the `BloomFilterIndex`
   ABC is in the OSS core; a production implementation absorbs the
   "fingerprint not in index" case in process memory, eliminating the
   Postgres round-trip for UNVERIFIED chunks. Material when UNVERIFIED
   is a small-but-nonzero fraction of traffic at scale.
5. **Rust core with language bindings** (not in the OSS core today) -
   the algorithm is small enough that a Rust core would 50-100x
   per-call throughput and remove the install-Python constraint
   entirely.

Levers 1 and 2 are operational and require no Provenex changes. Lever 3
is a library API addition. Levers 4 and 5 are out of scope for the OSS
core today.

### What this doc does not yet cover

- **Postgres benchmarks** at 1M and 10M chunks against managed
  Postgres (RDS, Aurora, Cloud SQL). Pending.
- **Multi-process ingest scaling on the SQLite backend.** See the
  parallelism caveat above. Use the Postgres backend if you need this.
- **Hot-cache vs cold-cache verify.** Current verify numbers are
  steady-state with the index hot in the OS page cache. A cold-start
  verify would be slower; bench doesn't isolate that yet.
- **Concurrent reader-writer p99 under load.** What verify p99 looks
  like while ingest is running into the same index - measured against
  Postgres, will be the more useful number than the current SQLite
  single-process figure.
- **Network-attached storage.** All current measurements are on a
  local SSD. EBS, GP3, and managed-disk performance will differ.
