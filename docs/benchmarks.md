# Provenex benchmarks (v1.0.0)

Measured numbers for the Provenex hot paths plus the methodology to reproduce them. The headline numbers below come from `provenex bench` on the hardware listed under [Hardware under test](#hardware-under-test). Run it yourself; the numbers should land within noise.

> **Caveat (every chart).** Measured on the hardware below. Single-threaded unless noted. Reproducible via `provenex bench` (see [Reproduce on your hardware](#reproduce-on-your-hardware)).

For the Merkle-backed (transparency-log) index numbers, see [scaling.md](scaling.md) — the same data path with the additional cost of RFC 6962 tree updates on every ingest. The numbers here are for the plain `SQLiteProvenanceIndex`, the default backend.

---

## What is measured

`provenex bench` runs four discrete passes after building an in-memory SQLite index of the requested size:

| Pass | What it exercises | What the operator sees |
| --- | --- | --- |
| **Ingest** | Fingerprint synthetic chunks, write the signed row to SQLite, in a tight per-chunk loop. | Per-call latency and chunks-per-second throughput. |
| **Verify (index lookup)** | `index.verify(fingerprint)` only -- the raw lookup, no fingerprinting on the verify side. Mix of known + unknown fingerprints (10% unknown by default). | Lookup-only latency for downstream callers that have already fingerprinted. |
| **Receipt generation (end-to-end)** | The full producer path: fingerprint the chunk, look up the index, evaluate policy, canonicalise the receipt, Ed25519-sign. The same code path `verify_chunks(...)` runs in a production call. | What a real receipt costs to produce. |
| **Receipt verification (offline)** | Each receipt produced above is passed to `provenex_verifier.verify_receipt(...)` -- the standalone third-party verifier library. No index, just cryptographic envelope verification. | What an auditor pays per receipt. |

A peak-RSS sample (`resource.getrusage(RUSAGE_SELF).ru_maxrss`, normalised to bytes) is captured at the end of the run so the memory footprint is part of the JSON report.

The bench is **single-threaded by design**. The numbers describe what one Python process does end-to-end, not the architectural ceiling. For threadpool / async measurements against Postgres, see [`bench/async_verify.py`](../bench/async_verify.py). For batched verify, see [`bench/batch_verify.py`](../bench/batch_verify.py).

---

## Hardware under test

| Component | Value |
| --- | --- |
| CPU | Intel Core i7-8750H (Coffee Lake-H, 6c/12t, base 2.2 GHz, turbo 4.1 GHz) |
| Memory | 16 GB DDR4 |
| Storage | Internal NVMe SSD |
| OS | macOS 12.4 (Darwin 21.5.0) |
| Python | 3.12.10 (Python.org build, OpenSSL 3.0.16) |
| `provenex-core` | 1.0.0 |
| `provenex-verifier` | 1.0.0 |
| `cryptography` | latest (Ed25519 path) |

Two caveats interpreting these numbers on different silicon:

1. **No SHA-NI.** Coffee Lake-H does not have Intel's SHA-256 hardware acceleration. All SHA-256 work is software. Server CPUs from ~2019 onward (Ice Lake-SP, Cascade Lake, EPYC Rome+, Graviton2+, Apple M1+) ship hardware SHA-256 and run the fingerprint path roughly 3-5x faster.
2. **Mobile thermal envelope.** Sustained turbo isn't guaranteed for ingest, a multi-minute hot loop. Desktop or server parts hold boost clocks indefinitely.

---

## Headline numbers

### 100,000-chunk corpus

Plain `SQLiteProvenanceIndex`, 800-char synthetic chunks, seed 42. Raw JSON reports live in [`bench_reports/`](../bench_reports/).

| Pass | p50 | p95 | p99 | Throughput |
| --- | --- | --- | --- | --- |
| Ingest | -- | -- | -- | **733 chunks/s** |
| Verify (index lookup) | **45.8 µs** | 51.5 µs | 70.9 µs | 21,744 ops/s |
| Receipt generation (Ed25519, end-to-end) | **911 µs** | 1.04 ms | 1.11 ms | 1,065 receipts/s |
| Receipt verification (standalone provenex-verifier) | **288 µs** | 329 µs | 376 µs | 3,367 ops/s |

| Footprint | Value |
| --- | --- |
| Index on disk | 64.8 MB (~648 bytes/chunk) |
| Peak process RSS | 57.2 MB |

### 1,000,000-chunk corpus

Same workload, 10x larger corpus. Raw JSON reports live in [`bench_reports/`](../bench_reports/).

<!-- 1m-numbers-start -->
| Pass | p50 | p95 | p99 | Throughput |
| --- | --- | --- | --- | --- |
| Ingest | -- | -- | -- | **710 chunks/s** (23.5 min wall clock) |
| Verify (index lookup) | **48.9 µs** | 58.4 µs | 86.0 µs | 19,852 ops/s |
| Receipt generation (Ed25519, end-to-end) | **922 µs** | 1.01 ms | 1.11 ms | 1,056 receipts/s |
| Receipt verification (standalone provenex-verifier) | **296 µs** | 317 µs | 349 µs | 3,378 ops/s |

| Footprint | Value |
| --- | --- |
| Index on disk | 657.3 MB (~689 bytes/chunk) |
| Peak process RSS | 227.7 MB |

**The scaling shape holds.** Verify latency moved 45.8 → 48.9 µs going from 100K to 1M chunks (B-tree depth at ~log₂(1M) ≈ 20). Receipt generation moved 911 → 922 µs. Both pass-rates are nearly identical at the two scales -- the receipt hot path is corpus-size-independent and the cryptographic envelope is constant.
<!-- 1m-numbers-end -->

---

## Reading the numbers

**Verify latency is nearly corpus-size-independent.** B-tree lookups grow with log₂(N): 45.8 µs at 100K vs 48.9 µs at 1M is essentially the depth difference. Plan for ~50-100 µs verify lookup latency at any practical corpus size on commodity hardware.

**Receipt-generation latency is dominated by canonicalisation, not crypto.** A 911-922 µs receipt-generation p50 breaks down approximately as: fingerprint a 800-char chunk (~70 µs), index lookup (~50 µs), canonical-JSON serialisation of the full receipt (~400 µs), Ed25519 signature (~100 µs), Python-level overhead (~300 µs). The canonicalisation cost is the surprise; we keep it because it is the *same* cost the verifier pays, and that symmetry is what makes the receipt portable across languages. For typical RAG (one retrieval per query) this is invisible. For agentic flows with many tool calls per query, it amortises across calls.

**1 ms per gate is the floor for honest cryptographic provenance.** Sub-100 µs end-to-end claims for "signed cryptographic provenance per call" typically skip canonicalisation (= the receipt cannot be verified by a third party who did not write the JSON), use HMAC-only (= the verifier holds the same secret and can forge), or both. Provenex pays the 1 ms because the receipt is meant to be handed to an external party.

**Ingest throughput at 710-733 chunks/s is the cost of per-row commits.** The bench commits one row at a time; SQLite's WAL serialises around the page flush. The OSS index does not currently expose a batch-add API; future work could surface one (`executemany`-style) for ~5-10x ingest throughput. For multi-writer scale-out, the Postgres backend is the recommended path -- see [`bench/postgres_scale.py`](../bench/postgres_scale.py) for the concurrent-writer numbers.

---

## What is NOT measured here

Three measurements the spec calls for that are not yet in this document, and the honest reason:

1. **10,000,000-chunk and 100,000,000-chunk runs.** A 100M run would take roughly 1-2 days at the ingest throughput above and produce a ~10 GB index on disk. We do not publish those numbers from a laptop benchmark; they need dedicated hardware and a longer wall-clock budget. The [`bench/postgres_scale.py`](../bench/postgres_scale.py) harness is the right place to run them when that hardware is available -- it already supports the 10M scale parameter.

2. **Bloom-filter acceleration numbers (commercial path).** The Bloom acceleration is a commercial feature; this OSS repo ships a no-op stub. We publish the numbers when the commercial path is available alongside.

3. **Multi-threaded ingest throughput.** The hot path is the SQLite WAL write, which serialises across writers; multi-threaded ingest does not buy throughput on a single SQLite file. The Postgres backend does scale with concurrent writers -- see [`bench/postgres_scale.py`](../bench/postgres_scale.py) and [`bench/async_verify.py`](../bench/async_verify.py).

---

## Reproduce on your hardware

```bash
pip install "provenex-core[policy]" provenex-verifier
provenex bench --scale 100k --verify-samples 50000 \
    --receipt-samples 2000 --verifier-samples 2000 \
    --out my-100k-report.json
```

For the smoke-test tier (under 10 seconds):

```bash
provenex bench --scale 1k
```

For the 1M tier (~25 minutes on the reference hardware):

```bash
provenex bench --scale 1m --verify-samples 100000 \
    --receipt-samples 5000 --verifier-samples 5000 \
    --out my-1m-report.json
```

The JSON report has stable keys; the schema in [`provenex/bench/scale.py`](../provenex/bench/scale.py) `BenchResult.to_dict()` is the source of truth. Run it on your hardware and the numbers should fall within the noise floor of the reference machine modulo the SHA-256 acceleration delta noted above.

---

## What is not on the hot path

The bench measures the producer + auditor hot paths only. Three pieces of the Provenex story are deliberately not in `provenex bench`:

* **Policy evaluation.** Covered separately in [`bench/scale.py`](../bench/scale.py) (the broader research harness, not the user-facing CLI). The native YAML evaluator clears 30,000+ decisions/second on the reference hardware.
* **Tool-call admission.** Same data path as receipt generation above plus a YAML rule evaluation; the receipt-generation number is the right ballpark.
* **Witness-log writes.** Out-of-band, batched. Not in the verify hot path.

For the methodology behind each measurement, see [scaling.md](scaling.md). For the deployment topology that holds these numbers at production scale, see [scaling.md § What changes on enterprise hardware](scaling.md#what-changes-on-enterprise-hardware).
