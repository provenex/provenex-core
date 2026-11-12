# How Provenex works

This document is for someone who needs to audit the algorithm: a security reviewer, a regulator, an internal compliance team. It walks through every step from ingestion to receipt verification, with enough detail to reimplement the system from scratch.

The matching source is in [`provenex/`](../provenex/). The security-critical surface (normalizer, hasher, fingerprinter, index, policy, receipt, ed25519, merkle, witness) is the part this document walks through; the source pointers below take you straight to it. Anyone reading this doc should also read the code. We deliberately keep this surface small and pure-stdlib for the same reason banks demand JSON-able policy files: a reviewer who needs to certify the algorithm should be able to read every load-bearing function in one sitting.

## The problem

A RAG pipeline retrieves chunks of text and passes them to an LLM. After the LLM produces an answer, no record exists of which chunks it actually used, whether those chunks were current, whether the user was authorized to see them, or whether anything was injected mid-pipeline. Compliance teams holding a transcript of "the model said X" have no way to prove X was grounded in authorized sources.

Provenex fixes this by attaching a cryptographically signed receipt to every retrieval that records, per chunk: a one-way fingerprint, the source document's identity and version, when it was ingested, whether it was authorized at retrieval time, the verification outcome, and the per-chunk access-control decision. The receipt covers an LLM-output hash and is signed end-to-end.

> **Decision and proof, not execution.** Provenex is an admission controller for AI data access - it evaluates each chunk against policy at the access point, records the decision, and returns allow / deny / verdict. It does NOT become the data path: the retriever still calls the vector DB; Provenex does not hold OAuth tokens, proxy network calls, or sit on the critical path between caller and storage. Kubernetes admission controllers do not run workloads; they decide whether workloads are admitted. That is the model. This scope discipline is what keeps Provenex a policy engine rather than an integration platform with the operational burden of one. (The same scope line applies to tool-call enforcement in a separate repo - it intercepts at the MCP boundary and emits a signed receipt, never brokers the actual tool call.)

## Four components

### 1. Fingerprinting

A chunk of text is reduced to a deterministic SHA-256 fingerprint in three steps.

**Step 1. Normalize.** Cosmetic differences that shouldn't affect identity are removed. The default pipeline:

| Step | What it does | Why |
| --- | --- | --- |
| `unicode_nfc` | Apply Unicode Normalization Form C | `café` (precomposed) and `cafe + combining acute` are byte-different but semantically identical. NFC unifies them. |
| `strip_zero_width` | Remove ZWSP, ZWJ, ZWNJ, BOM, WJ | Zero-width characters are a well-known fingerprint-evasion trick. Stripping them defeats the trick. |
| `case_fold` *(off by default)* | Unicode-aware lower-casing | Off because regulatory/legal text is usually case-sensitive. Enable per use case. |
| `whitespace_collapse` | Collapse runs of whitespace, strip ends | Reformatting (different line wrapping, tab vs. space) shouldn't change identity. |

The exact list of normalizations applied to a chunk is recorded on the receipt under `normalization_applied`, so a verifier can reproduce the pipeline byte for byte.

**Step 2. Slide a window.** The normalized text is scanned with a fixed-width sliding window (default `window_size=128`, `stride=64`). Each window position becomes one fingerprint.

The window advances using Rabin-Karp recurrence:

```
H(i+1) = (H(i) - text[i] * B^(W-1)) * B + text[i+W]    (mod MOD)
```

where `B = 1_000_003` and `MOD = 2^61 - 1` (Mersenne prime). The math is O(1) per slide, so the whole document is fingerprinted in O(N) regardless of window size. Source: [`provenex/core/hasher.py`](../provenex/core/hasher.py), `RollingHasher`.

The rolling hash itself is **not cryptographic**. It exists to make windowing cheap, not to be secure. Collisions on a 61-bit hash are expected for adversarial input.

**Step 3. Strengthen with SHA-256.** The text content of each window is hashed with SHA-256. The output, in the form `sha256:<64 hex chars>`, is what we store and compare. SHA-256 over a small window costs roughly 50-100x what the Rabin-Karp slide costs, but it's what gives us cryptographic identity. Collisions are infeasible.

This two-stage design (fast rolling hash for windowing, cryptographic hash for identity) is a standard technique in content-defined chunking and document fingerprinting. We chose Rabin-Karp specifically over alternatives (Buzhash, polynomial hashing variants) because the recurrence is recognizable to any security reviewer; auditability beats microbenchmark wins on a non-bottleneck.

The chunk's text content is also fingerprinted as a single SHA-256 over the whole normalized chunk. The provenance index stores both the chunk-level entry (with `entry_kind="whole_chunk"`) and the sliding-window entries (with `entry_kind="window"`). Only whole-chunk entries are eligible for `VERIFIED` at verify time; window entries are retained for structural locating only, and an auditor reading a window-locator UNVERIFIED outcome sees the offset and length of the locator that matched. This is the **window-aligned splice control**: a 128-codepoint substring of an authorized document does NOT promote to `VERIFIED` on its own, even though its hash is in the index, because the matched row is a window entry. Re-chunking robustness is therefore narrower than v0.7 advertised: a retriever that returns the operator-authorized chunks verifies cleanly, but a chunk shape that drifts to land on window boundaries is treated as unverified bytes rather than authorized content. The `entry_kind` field is part of the canonical row payload, so the classification is tamper-evident at the storage layer. See the threat-model section [Window-aligned splice (substring promotion to VERIFIED)](threat_model.md#window-aligned-splice-substring-promotion-to-verified) for the full control statement.

### 2. The provenance index

The index stores fingerprint → metadata mappings. Each row contains:

- `fingerprint`: `sha256:<hex>`
- `document_id`: the caller's stable ID for the source document
- `document_version`: SHA-256 over the normalized full document content
- `ingested_at`: ISO-8601 UTC timestamp
- `chunk_offset`, `chunk_length`: position within the normalized document
- `authorized`: current authorization state for the document
- `superseded`: whether this row has been replaced by a newer version
- `signature`: HMAC-SHA256 over the row's canonical serialization

Every row is signed when it's written. At read time the signature is recomputed and compared in constant time. If the row was modified outside Provenex (a SQL injection, a misbehaving operator, a corrupted backup), the signature check fails and the verification outcome becomes `TAMPERED`.

The open source implementation uses SQLite ([`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py)). Production deployments swap in the hosted Provenex index, which implements the same `ProvenanceIndex` abstract interface ([`provenex/index/base.py`](../provenex/index/base.py)). The swap is one line of code.

#### Transparency log

The per-row HMAC detects tampering with any single row. It does not detect insertion or removal of rows by an attacker who holds the signing key. To close that gap, the optional [`MerkleSQLiteProvenanceIndex`](../provenex/index/merkle_sqlite_index.py) extends the SQLite index with an [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) Merkle transparency log over the same rows.

The leaf bytes for each row are the canonical payload the HMAC already signs:

```
leaf = fingerprint \n document_id \n document_version \n ingested_at \n chunk_offset \n chunk_length
leaf_hash = SHA256(0x00 || leaf)
node_hash = SHA256(0x01 || left || right)
```

Two operations matter for verification:

- **`tree_root()`** returns the current tree head. The hosted commercial product publishes signed tree heads periodically; a witness can gossip them and detect divergence (the standard CT pattern). The OSS reference implementation does not gossip (that's a hosted-product feature), but the tree head is still useful as a local anchor.
- **`inclusion_proof(fingerprint)`** returns a logarithmic-size audit path. Anyone holding the receipt and the tree head can verify offline that a specific fingerprint was committed to the log at the claimed position, using `provenex.core.merkle.verify_inclusion_proof`. No need to scan the whole index.

When a receipt is produced against a `MerkleSQLiteProvenanceIndex`, each source record carries its `leaf_index` and `inclusion_proof`, and the receipt as a whole carries `transparency_log.tree_size` and `transparency_log.tree_root`. The signature covers all of it, so tampering with any field, including the log head, invalidates the receipt. See [`docs/receipt_format.md`](receipt_format.md) for the on-the-wire schema.

The two layers compose: HMAC for per-row integrity (a single forged row is detectable by anyone with the key), Merkle log for whole-log integrity (insertion or removal of rows changes the tree head, detectable by anyone with the previous head).

### 3. Verification

When a retriever returns a chunk, Provenex:

1. Runs the same normalization + SHA-256 pipeline to get a fingerprint.
2. Looks up that fingerprint in the index.
3. Verifies the row signature.
4. Reads the document's current authorization state.
5. Checks whether the row is superseded.

The result is one of six outcomes:

| Outcome | Condition |
| --- | --- |
| `UNVERIFIED` | Fingerprint not in index. Chunk was not ingested through Provenex. |
| `TAMPERED` | Fingerprint in index, signature check failed. Index was modified outside Provenex. |
| `PURGED` | Fingerprint in index, signature OK, and the operator recorded a purge tombstone (deletion attestation). |
| `UNAUTHORIZED` | Fingerprint in index, signature OK, but document is not authorized for retrieval. |
| `STALE` | Fingerprint in index, signature OK, document authorized, but row is superseded by a newer version. |
| `VERIFIED` | All checks pass. |

A configurable `verification` gate (the verification half of the unified `Policy`) decides which outcomes block the chunk before reaching the next stage. The receipt records both the kept chunks and the blocked chunks, so the picture is complete regardless of policy.

**Precedence among outcomes when several could apply.** A row may satisfy more than one outcome condition simultaneously: the signature is broken AND the document is unauthorized, the document is unauthorized AND the row is superseded, and so on. The engine picks a single dominant outcome via a fixed precedence:

```
TAMPERED > PURGED > UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED
```

The order encodes a defensive priority: an integrity break is the most important thing to surface, an authorisation revocation outranks a version-supersession concern, and `VERIFIED` is the only "all clear" state. UNVERIFIED is the absent-entry sentinel; it applies only when no row matched at all, so it cannot shadow any other outcome. The precedence is exposed as `OUTCOME_PRECEDENCE` and `reduce_outcomes()` in [`provenex.index.base`](../provenex/index/base.py) so callers and downstream tools reason about it the same way the engine does. The corresponding red-team coverage lives in [`tests/test_outcome_precedence.py`](../tests/test_outcome_precedence.py).

**Supersession is an operational contract, not a heuristic.** When a document is re-ingested with new content, the index's `add()` (called with the same `document_id` and a new `document_version`) marks all older fingerprints as superseded automatically. The contract: **whoever owns the ingest path is responsible for invoking that call against every Provenex index that holds the old version**, every time the underlying document changes. If a document is re-ingested only to the vector store but the Provenex index never sees a new version, the old chunks stay `VERIFIED` forever and the access decision silently uses out-of-date content. The CLI's `provenex index audit --index <db>` command surfaces two failure modes the contract guards against (stale documents that have not been re-ingested in N days; unsuperseded older versions still flagged not-superseded after a re-ingest skipped the API). Wire that command into CI / cron at a cadence matching your re-ingest discipline.

### Peppered fingerprint mode (for low-entropy corpora)

Plain SHA-256 is one-way but not unguessable: an attacker with candidate plaintexts (HR template snippets, fixed policy boilerplate, an enumerable form) can recompute the SHA-256 of each candidate and confirm presence in the index. The hash is not reversible, but it is testable. For low-entropy corpora this re-links a hash to its plaintext given enough context.

The pepper option turns the hash into `HMAC-SHA256(pepper, normalized_bytes)`. A per-deployment secret pepper means an attacker who guesses the plaintext also needs the pepper to confirm presence. Two deployments with different peppers produce different fingerprints for identical content (per-deployment unlinkability of fingerprints). The prefix on disk stays `sha256:` because the output is still a SHA-256-based digest of the same width; downstream tooling reads the same. **Pepper must be identical at ingest and at verify**, and rotating it requires re-ingesting the corpus. Source: [`provenex.core.fingerprinter.FingerprinterConfig.pepper`](../provenex/core/fingerprinter.py).

### 4. Data-access policy evaluation

The verification outcome answers "did this chunk come from where we said, and is it intact?" A separate question - "is the caller allowed to see this chunk?" - is answered by the data-access policy evaluator (the `access_control` half of the unified `Policy`, schema 2.0.0).

Provenex ships an evaluator-agnostic `PolicyEvaluator` protocol with one reference backend in the open-source core: the native YAML DSL ([`provenex/policy/yaml_evaluator.py`](../provenex/policy/yaml_evaluator.py)). The Rego adapter and the OPA-service adapter ship commercially. The decision shape on the receipt is the same regardless of backend.

The flow for each chunk:

1. Re-fingerprint, look up in the index, assign one of the five verification outcomes (unchanged from v0.3).
2. If `policy.access_control` is configured, build a `ChunkContext` (document_id, document_version, ingested_at, opaque metadata tags, content_source) and pass it with the operator-supplied `RequestContext` (caller, jurisdiction, purpose, timestamp) to `evaluator.evaluate(...)`. The evaluator returns `allow` or `deny` plus the names of rules that fired.
3. The chunk reaches the LLM only if BOTH gates pass: the verification policy AND the access-control policy.

The verification outcome and the policy decision are independent. A `VERIFIED` chunk can still be policy-denied (wrong jurisdiction, missing role). A `STALE` chunk can still be policy-allowed (the policy explicitly accepts stale chunks for non-critical contexts). The receipt records both verdicts on every chunk - `sources[i].verification_outcome` and `policy.access_control.decisions[i].decision` - so an auditor can reason about them independently.

The policy bundle is canonicalized (key-sorted JSON, no whitespace) and hashed with SHA-256 to produce the `policy_version_hash`. Two policies that differ only in formatting hash to the same value. This is the field that would be published to a transparency log in the commercial transparency-log integration, so auditors can independently confirm which policy was in effect at the time of a decision.

See [`docs/policy.md`](policy.md) for the full DSL reference, the evaluator protocol, and worked examples. See [`docs/threat_model.md`](threat_model.md#trust-model-for-policy-decisions) for the trust model for policy decisions specifically.

## The receipt

After verification, a `ReceiptBuilder` assembles a `ProvenanceReceipt`:

- A fresh `receipt_id`
- `schema_version` (currently `2.7.0`) and `issuer` (`provenex-core/1.1.0`)
- `issued_at` UTC timestamp
- SHA-256 of the LLM output text (the text itself is not stored, just its hash)
- The per-chunk source records (fingerprint, document metadata, verification outcome, normalization applied, `entry_kind`)
- The unified `policy` block: `policy.verification` (always present) and `policy.access_control` (optional, with per-chunk decisions)
- A `caller_hash` top-level field (schema 2.3.0+), a `request_binding` block (schema 2.4.0+, see below), and an optional `index_status` block (schema 2.5.0+) when the index was unreachable under a `degrade`-mode availability policy
- A summary (`total_chunks`, counts per outcome, `overall_status` of `PASS` / `PARTIAL` / `FAIL`)
- A signature block (`algorithm`, `value`)

The signature is computed over the canonical JSON serialization of the receipt: keys sorted, no whitespace, the signature block itself omitted from the payload. Anyone with the receipt and the signing key can recompute the payload, recompute the signature, and confirm a match.

The default signer (v1.0.0+) is `Ed25519Signer`. `resolve_default_signer()` reads `PROVENEX_RECEIPT_PRIVATE_KEY_PATH` (a PEM private key path) and returns an Ed25519 signer; an auditor verifies with only the public key and cannot forge. For in-house deployments that prefer HMAC-SHA256, `HmacSha256Signer()` still works and reads `PROVENEX_RECEIPT_SECRET` from the environment. Both implement the same `ReceiptSigner` interface; the receipt structure is identical. Source: [`provenex/core/receipt.py`](../provenex/core/receipt.py) and [`provenex/core/ed25519.py`](../provenex/core/ed25519.py).

### Request-to-receipt binding (schema 2.4.0+)

The link between a receipt and the request that produced it is no longer implicit: every receipt carries a top-level `request_binding` block that hashes the triggering query and the canonical request_context into the signed payload.

```json
"request_binding": {
  "algorithm": "sha256",
  "query_hash": "sha256:b7a1e09c...",
  "request_context_hash": "sha256:31d8e94c...",
  "request_hash": "sha256:c2f6a18d..."
}
```

`query_hash` is `SHA-256(utf8(request_text))` when `verify_chunks(..., request_text=...)` or `admission_check(..., request_text=...)` is called; absent otherwise (recorded as `null` so the omission is explicit). `request_context_hash` is `SHA-256` over the canonical JSON of the request_context's `caller / jurisdiction / purpose / timestamp` (session_id is excluded by the same rule that excludes it from `inputs_hash`). `request_hash` is the SHA-256 join of the two so an auditor compares one value rather than two. The block is part of the canonical signing payload, so editing any of the three hashes invalidates the receipt signature. A regulator who holds the original query and request_context re-derives the hashes and confirms a match.

The verbatim query text is never stored on the receipt. Operators who include `request_text` are buying receipt-to-request binding for their compliance posture; those who skip it leave the binding incomplete and the auditor can see exactly which half is missing.

## Determinism

The whole pipeline is deterministic. Given the same input text, the same normalization options, and the same window/stride settings, fingerprinting always produces the same fingerprints. The `document_version` hash is stable across re-chunking. Receipts produced from the same inputs differ only in `receipt_id` and `issued_at`; the rest of the content is bit-identical. The signature payload sorts keys to make this cross-implementation portable.

## Privacy

Nothing the index or the receipt stores can be reversed to document content. Fingerprints are one-way SHA-256 hashes. The receipt records hashes, document IDs (caller-chosen, usually random or opaque), offsets and lengths, and timestamps. Document text never leaves the customer's control through the Provenex layer.

## Threat model

The short version: every row is HMAC-signed (catches tampering by anyone without the key), the optional Merkle transparency log catches insertion/removal even by a key-holder, the receipt is signed end-to-end, and any chunk not in the index produces `UNVERIFIED` at retrieval. Compromised signing keys, compromised LLMs, and coordinated insider attack are explicitly out of scope; rotate keys and audit operationally.

For the full attacker model, defended and undefended threats, and the security FAQ compliance teams have asked us, see [`threat_model.md`](threat_model.md).

## Source map

- [`provenex/core/normalizer.py`](../provenex/core/normalizer.py): text normalization pipeline
- [`provenex/core/hasher.py`](../provenex/core/hasher.py): Rabin-Karp rolling hash, SHA-256 strengthening, window iterator
- [`provenex/core/fingerprinter.py`](../provenex/core/fingerprinter.py): top-level fingerprint API
- [`provenex/index/base.py`](../provenex/index/base.py): abstract `ProvenanceIndex` and `VerificationOutcome`
- [`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py): SQLite implementation with HMAC-signed rows
- [`provenex/index/merkle_sqlite_index.py`](../provenex/index/merkle_sqlite_index.py): SQLite index with an RFC 6962 transparency log layered over the same rows
- [`provenex/core/merkle.py`](../provenex/core/merkle.py): RFC 6962 Merkle tree primitive and stateless inclusion-proof verifier
- [`provenex/policy/policy.py`](../provenex/policy/policy.py): `VerificationPolicy`, block/flag matrix, status reduction
- [`provenex/core/receipt.py`](../provenex/core/receipt.py): receipt model, builder, signer interface, signature verification, `compute_request_binding`
- [`provenex/core/witness.py`](../provenex/core/witness.py): hash-chained signed checkpoint log over the Merkle tree head
- [`provenex/cli/main.py`](../provenex/cli/main.py): CLI including `provenex selftest` (conformance), `provenex index audit` (supersession lint)

Run `provenex selftest` after install to confirm the binary's pipeline matches every property this document describes.
