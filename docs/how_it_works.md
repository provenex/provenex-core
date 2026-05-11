# How Provenex works

This document is for someone who needs to audit the algorithm — a security reviewer, a regulator, an internal compliance team. It walks through every step from ingestion to receipt verification, with enough detail to reimplement the system from scratch.

The matching source is in [`provenex/`](../provenex/) and is small: roughly 1,200 lines across normalizer, hasher, fingerprinter, index, policy, and receipt. Anyone reading this doc should also read the code.

## The problem

A RAG pipeline retrieves chunks of text and passes them to an LLM. After the LLM produces an answer, no record exists of which chunks it actually used, whether those chunks were current, whether the user was authorized to see them, or whether anything was injected mid-pipeline. Compliance teams holding a transcript of "the model said X" have no way to prove X was grounded in authorized sources.

Provenex fixes this by attaching a cryptographically signed receipt to every retrieval that records, per chunk: a one-way fingerprint, the source document's identity and version, when it was ingested, whether it was authorized at retrieval time, and the verification outcome. The receipt covers an LLM-output hash and is signed end-to-end.

## Three components

### 1. Fingerprinting

A chunk of text is reduced to a deterministic SHA-256 fingerprint in three steps.

**Step 1 — Normalize.** Cosmetic differences that shouldn't affect identity are removed. The default pipeline:

| Step | What it does | Why |
| --- | --- | --- |
| `unicode_nfc` | Apply Unicode Normalization Form C | `café` (precomposed) and `cafe + combining acute` are byte-different but semantically identical. NFC unifies them. |
| `strip_zero_width` | Remove ZWSP, ZWJ, ZWNJ, BOM, WJ | Zero-width characters are a well-known fingerprint-evasion trick. Stripping them defeats the trick. |
| `case_fold` *(off by default)* | Unicode-aware lower-casing | Off because regulatory/legal text is usually case-sensitive. Enable per use case. |
| `whitespace_collapse` | Collapse runs of whitespace, strip ends | Reformatting (different line wrapping, tab vs. space) shouldn't change identity. |

The exact list of normalizations applied to a chunk is recorded on the receipt under `normalization_applied`, so a verifier can reproduce the pipeline byte for byte.

**Step 2 — Slide a window.** The normalized text is scanned with a fixed-width sliding window (default `window_size=128`, `stride=64`). Each window position becomes one fingerprint.

The window advances using Rabin-Karp recurrence:

```
H(i+1) = (H(i) - text[i] * B^(W-1)) * B + text[i+W]    (mod MOD)
```

where `B = 1_000_003` and `MOD = 2^61 - 1` (Mersenne prime). The math is O(1) per slide, so the whole document is fingerprinted in O(N) regardless of window size. Source: [`provenex/core/hasher.py`](../provenex/core/hasher.py), `RollingHasher`.

The rolling hash itself is **not cryptographic**. It exists to make windowing cheap, not to be secure. Collisions on a 61-bit hash are expected for adversarial input.

**Step 3 — Strengthen with SHA-256.** The text content of each window is hashed with SHA-256. The output, in the form `sha256:<64 hex chars>`, is what we store and compare. SHA-256 over a small window costs roughly 50-100x what the Rabin-Karp slide costs, but it's what gives us cryptographic identity — collisions are infeasible.

This two-stage design — fast rolling hash for windowing, cryptographic hash for identity — is a standard technique in content-defined chunking and document fingerprinting. We chose Rabin-Karp specifically over alternatives (Buzhash, polynomial hashing variants) because the recurrence is recognizable to any security reviewer; auditability beats microbenchmark wins on a non-bottleneck.

The chunk's text content is also fingerprinted as a single SHA-256 over the whole normalized chunk. The provenance index stores both the chunk-level and the sliding-window fingerprints, so verification succeeds whether the retriever returns chunks shaped exactly as ingested or further re-chunked.

### 2. The provenance index

The index stores fingerprint → metadata mappings. Each row contains:

- `fingerprint` — `sha256:<hex>`
- `document_id` — the caller's stable ID for the source document
- `document_version` — SHA-256 over the normalized full document content
- `ingested_at` — ISO-8601 UTC timestamp
- `chunk_offset`, `chunk_length` — position within the normalized document
- `authorized` — current authorization state for the document
- `superseded` — whether this row has been replaced by a newer version
- `signature` — HMAC-SHA256 over the row's canonical serialization

Every row is signed when it's written. At read time the signature is recomputed and compared in constant time. If the row was modified outside Provenex — by a SQL injection, by a misbehaving operator, by a corrupted backup — the signature check fails and the verification outcome becomes `TAMPERED`.

The open source implementation uses SQLite ([`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py)). Production deployments swap in the hosted Provenex index, which implements the same `ProvenanceIndex` abstract interface ([`provenex/index/base.py`](../provenex/index/base.py)). The swap is one line of code.

### 3. Verification

When a retriever returns a chunk, Provenex:

1. Runs the same normalization + SHA-256 pipeline to get a fingerprint.
2. Looks up that fingerprint in the index.
3. Verifies the row signature.
4. Reads the document's current authorization state.
5. Checks whether the row is superseded.

The result is one of five outcomes:

| Outcome | Condition |
| --- | --- |
| `UNVERIFIED` | Fingerprint not in index. Chunk was not ingested through Provenex. |
| `TAMPERED` | Fingerprint in index, signature check failed. Index was modified outside Provenex. |
| `UNAUTHORIZED` | Fingerprint in index, signature OK, but document is not authorized for retrieval. |
| `STALE` | Fingerprint in index, signature OK, document authorized, but row is superseded by a newer version. |
| `VERIFIED` | All checks pass. |

A configurable `VerificationPolicy` decides which outcomes block the chunk before it reaches the LLM. The receipt records both the kept chunks and the blocked chunks, so the picture is complete regardless of policy.

## The receipt

After verification, a `ReceiptBuilder` assembles a `ProvenanceReceipt`:

- A fresh `receipt_id`
- `schema_version` (currently `1.0.0`) and `issuer` (`provenex-core/0.1.0`)
- `issued_at` UTC timestamp
- SHA-256 of the LLM output text (the text itself is not stored, just its hash)
- The per-chunk source records (fingerprint, document metadata, verification outcome, normalization applied)
- The policy in effect
- A summary (`total_chunks`, counts per outcome, `overall_status` of `PASS` / `PARTIAL` / `FAIL`)
- A signature block (`algorithm`, `value`)

The signature is computed over the canonical JSON serialization of the receipt — keys sorted, no whitespace, the signature block itself omitted from the payload. Anyone with the receipt and the signing key can recompute the payload, recompute the signature, and confirm a match.

The default signer is HMAC-SHA256 (`HmacSha256Signer`). For asymmetric verification (so auditors can verify without holding the signing key), implement the `ReceiptSigner` interface with Ed25519 and pass it in. The receipt structure does not change. Source: [`provenex/core/receipt.py`](../provenex/core/receipt.py).

## Determinism

The whole pipeline is deterministic. Given the same input text, the same normalization options, and the same window/stride settings, fingerprinting always produces the same fingerprints. The `document_version` hash is stable across re-chunking. Receipts produced from the same inputs differ only in `receipt_id` and `issued_at`; the rest of the content is bit-identical. The signature payload sorts keys to make this cross-implementation portable.

## Privacy

Nothing the index or the receipt stores can be reversed to document content. Fingerprints are one-way SHA-256 hashes. The receipt records hashes, document IDs (caller-chosen — usually random or opaque), offsets and lengths, and timestamps. Document text never leaves the customer's control through the Provenex layer.

## Threat model

The system is designed against three threats.

**Tampering with the index.** Mitigated: every row is HMAC-signed; a modification anywhere in `fingerprint, document_id, document_version, ingested_at, chunk_offset, chunk_length` invalidates the signature, and the verification outcome is `TAMPERED`. An attacker would need the signing key to forge a row that verifies.

**Injection of unindexed content.** Mitigated: a chunk that wasn't ingested through Provenex has no matching fingerprint, returns `UNVERIFIED`, and is surfaced on the receipt. A strict policy (`block_unverified=True`) refuses to pass it to the LLM at all.

**Tampering with the receipt.** Mitigated: the receipt is signed end-to-end. Any change to the receipt body invalidates the signature. An auditor running `verify_receipt_signature` detects the change.

What this system explicitly does not protect against:

- **Compromised signing keys.** If the signing key is exfiltrated, an attacker can forge receipts. Standard key-rotation hygiene applies. The hosted Provenex commercial product uses an HSM-backed asymmetric key.
- **Compromise of the LLM itself.** Provenex records what the LLM saw, not what it did with it. Hallucinations on top of authorized sources are out of scope here.
- **Coordinated insider tampering at both index-write and verify time.** No purely software solution covers this.

## Source map

- [`provenex/core/normalizer.py`](../provenex/core/normalizer.py) — text normalization pipeline
- [`provenex/core/hasher.py`](../provenex/core/hasher.py) — Rabin-Karp rolling hash, SHA-256 strengthening, window iterator
- [`provenex/core/fingerprinter.py`](../provenex/core/fingerprinter.py) — top-level fingerprint API
- [`provenex/index/base.py`](../provenex/index/base.py) — abstract `ProvenanceIndex` and `VerificationOutcome`
- [`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py) — SQLite implementation with HMAC-signed rows
- [`provenex/policy/policy.py`](../provenex/policy/policy.py) — `VerificationPolicy`, block/flag matrix, status reduction
- [`provenex/core/receipt.py`](../provenex/core/receipt.py) — receipt model, builder, signer interface, signature verification

The total is small. Read it.
