# Threat model + security FAQ

The audience for this document is a security architect, a compliance reviewer, or an internal red team evaluating whether Provenex meets their threat-modelling bar. We cover what attacks Provenex defends against, what it explicitly does not, and the questions teams have asked us in practice.

If you only have time for one section, read the **what we don't protect against** part. Most of what kills software-security posture is a real attacker doing a thing the architecture was never designed to stop.

## Attacker model

Provenex is designed against three attackers with different capabilities. Throughout this doc, when we say "the attacker can detect / can't forge" we are stating that explicitly.

| Attacker | Has | Goal |
| --- | --- | --- |
| **Malicious operator (read-only)** | Read access to the provenance database + receipts | Tell us something different from what was actually retrieved |
| **Malicious operator (read-write)** | Write access to the provenance database. Does NOT have the receipt-signing key. | Modify rows or insert fake ones, then have verification still pass |
| **Compromised signing-key holder** | The receipt-signing private key (HMAC secret or Ed25519 private key) | Mint forged receipts that look real |

There are also non-adversarial threats: accidental corruption (a buggy script overwrites rows), backup divergence (a restore brings back stale data), and so on. The same mechanisms that catch attacker tampering catch these incidents, so we don't treat them separately.

## Threats we mitigate, and how

### Tampering with an existing row in the provenance database

**Mechanism:** every row is signed with HMAC-SHA256 over its canonical payload (`fingerprint, document_id, document_version, ingested_at, chunk_offset, chunk_length`). At read time the signature is re-derived from the row and compared in constant time.

**Result:** if any field has changed, verification returns `TAMPERED`. The policy can be configured to refuse to pass tampered chunks to the LLM. The receipt records the `TAMPERED` outcome regardless.

**Limitation:** the row signature is symmetric. An attacker who steals the signing key can both forge and verify. The transparency-log layer below addresses that case.

### Insertion or removal of rows by a key-holding attacker

**Mechanism:** when the optional `MerkleSQLiteProvenanceIndex` is in use, every row is also a leaf in an RFC 6962 Merkle transparency log. The tree root is a SHA-256 over the whole log. Any insertion, removal, or reordering produces a different tree root.

**Result:** a verifier who has previously seen any earlier tree-root publication can detect that the log diverged. The standard CT pattern (witness gossip, signed checkpoints) closes this against a key-holder.

**Limitation:** the OSS reference implementation does not gossip tree heads to witnesses. That is a hosted-product feature. Self-hosted deployments need to publish tree heads themselves (signed, immutable, periodic) to gain the full benefit.

### Injection of content that was never ingested

**Mechanism:** any chunk that comes out of a retriever is re-fingerprinted and looked up in the provenance index. A chunk whose fingerprint isn't present in the index produces an `UNVERIFIED` outcome.

**Result:** with `VerificationPolicy(block_unverified=True)` the chunk is removed before reaching the LLM. With looser policy the chunk is still flagged on the receipt. Either way an auditor sees that an un-ingested chunk attempted to enter the answer.

**Use cases this catches in practice:** dataset poisoning, prompt-injected web scraping, mislabeled "freshly added" chunks that bypass the proper ingest pipeline, a colleague who added documents to the vector DB without running them through Provenex.

### Tampering with the receipt itself

**Mechanism:** the receipt is signed end-to-end. The signature covers the JSON canonical serialization of every field on the receipt (sources, policy, summary, transparency log head, output hash, timestamps) minus the signature block itself.

**Result:** any modification to the receipt body invalidates the signature. An auditor running `verify_receipt_signature` (or `provenex audit receipt.json`) detects the change and returns FAIL.

### External verification without revealing the signing key

**Mechanism:** Ed25519 signing (asymmetric). The receipt producer holds a private key. Anyone with the public key can verify but cannot forge. The auditor never sees, and does not need, the producer's secret.

**Result:** receipts can be handed to external regulators or cross-organisation auditors with no key-material risk. The `provenex-core[ed25519]` extra adds this; HMAC remains the default for in-house deployments.

## Threats we explicitly do not protect against

This section is deliberately blunt. Knowing what a tool *doesn't* do is more useful than knowing what it does.

### A compromised signing key

If the signing key is exfiltrated, the attacker can mint receipts that verify cleanly. There is no software-only defence against this. The mitigation is operational:

- Store signing keys in a secrets manager or HSM, not in source code or `.env` files.
- Rotate keys on a schedule and on suspected compromise. Provenex doesn't bind to a specific key over time; rotated receipts can be re-signed under the new key during rotation windows.
- For maximum assurance, use Ed25519 signing and treat the private key the way you would treat your TLS server key. The hosted Provenex commercial product backs the private key in an HSM.

### A compromised LLM

Provenex records *what chunks the retriever returned*, not *what the model did with them*. If the model hallucinates content that wasn't in any retrieved chunk, that is not detectable from the Provenex receipt alone. The receipt is honest about which chunks went in; accurate hallucination detection is the job of a different layer (faithfulness evaluation, output grounding, etc.).

The receipt does include a SHA-256 of the LLM output text, so an auditor can confirm the model's answer hasn't been modified after the fact. But "did the answer accurately reflect the chunks" is out of scope.

### Coordinated tampering at both ingest and verify time

If an attacker controls both the code that writes to the provenance index *and* the code that reads from it (and holds the signing key), they can produce a fully internally-consistent fake provenance trail. No purely software-side solution catches this. Defence here is organizational: separation of duties, code review on the ingest path, independent verification by a party that doesn't share the operations team's access.

### Vector database tampering that doesn't involve Provenex at all

If an attacker rewrites embeddings in Pinecone/Weaviate/Milvus, the chunks the retriever returns at query time may be semantically different from what was authorized, but if the *text* of the returned chunk still matches a Provenex-fingerprinted chunk, Provenex returns `VERIFIED`. Provenex protects against tampering with **chunk identity**, not against retrieval-quality attacks on the similarity search itself.

Mitigation: vector-DB-level integrity (vendor controls, IAM, audit logs on the vector DB itself). Provenex composes alongside these, it does not replace them.

### Resource exhaustion

Provenex is a verification layer; rate-limit calls at the application boundary the same as any verification dependency.

### Side-channel attacks on the signing key

We use `hmac.compare_digest` for constant-time HMAC comparison and the underlying `cryptography` library's primitives (libsodium / OpenSSL) for Ed25519, which are also constant-time. Treat the signing host as you would treat any host that has access to a production secret.

## Trust model for policy decisions

Schema 2.0.0 (Provenex v0.4) adds a unified `Policy` to receipts: a `policy.verification` half and an optional `policy.access_control` half carrying the per-chunk decision record. This section spells out the trust boundaries that record can and cannot speak to.

### The policy file is trust-rooted to the operator

The native YAML evaluator loads a policy file the operator configured. The evaluator does not validate that the policy is "correct" in any business sense — it only validates that the YAML parses and that no reserved-but-unimplemented features are present. An operator who controls the signing key AND the policy file can author any policy they want and produce decisions that verify cleanly under that policy.

The commercial transparency-log integration is the planned mitigation: `policy_version_hash` would be published to an append-only log, so an auditor handed a receipt can independently confirm the policy in effect at the time of the decision was the one the operator publicly committed to. In the open-source core, `policy_in_transparency_log` is always `false`. Until that field lights up, the policy file is trusted as configured by the operator, the same way the index signing key is trusted as configured by the operator.

### A decision is only as trustworthy as the metadata feeding it

Provenex's evaluator reads two kinds of input: chunk metadata (residency tags, classification, PII flags, freshness, content_source) and request context (caller, jurisdiction, purpose, timestamp). The trust property of each depends on **when** the value was bound:

- **Tag-at-ingest.** When a residency or classification tag is written into the chunk's record at ingest time, the tag is covered by the index row's HMAC and (with the Merkle log) the tree head. An attacker cannot retroactively flip a tag without invalidating the row's signature. This is the strongest case.
- **Tag-at-evaluate.** When a tag is looked up from an external system at decision time (a live IAM lookup, a feature-flag service, a sidecar with the user's current role), the decision is only as trustworthy as that external system. Provenex records the value it read in `policy.access_control.decisions[i].inputs`, but cannot vouch for whether it was the right value. If the external system is compromised or stale, the decision will be too.

A defensible deployment binds as much policy-relevant metadata at ingest time as practical, and treats tag-at-evaluate as a separate audit concern.

**Schema 2.1.0** makes this distinction explicit on the receipt. Every decision record carries a `metadata_binding` field declaring the trust class of each input:

```json
"metadata_binding": {
  "chunk_metadata": "at_ingest",     // signed by the index row
  "request_context": "at_evaluate"   // built fresh at retrieval
}
```

An auditor reading the receipt now sees, per chunk, whether the decision rested on signed-at-ingest tags or external-system-at-evaluate tags. `request_context` is always `at_evaluate` (the caller dict is constructed per-request). `chunk_metadata` is operator-declared via `verify_chunks(..., chunk_metadata_binding=...)`. The field is non-load-bearing for the decision itself — it does not change whether the chunk reaches the LLM — but it is load-bearing for *audit trust*: an auditor handed a receipt with everything `at_evaluate` is reading a weaker guarantee than one handed a receipt with `chunk_metadata: at_ingest`.

### Operator-with-everything can produce any decision

An operator who controls the signing key AND the policy file AND the metadata pipeline can produce a fully internally-consistent receipt that says anything they want. This is the policy-decision analog of the existing "Coordinated tampering at both ingest and verify time" threat. The defence is the same: separation of duties, code review on the policy file, transparency-log gossip with witnesses (commercial), and independent audit by a party that does not share the operations team's access.

### The receipt records what the policy decided, not whether the policy was right

The signed receipt is non-repudiable evidence that, under policy `policy_id` with version hash `policy_version_hash`, the evaluator returned the recorded decision for the recorded `(chunk, request)` pair. That is the strongest claim the receipt makes. Whether the policy itself was the right policy to apply, or whether the decision was the right decision under that policy, are upstream questions for governance review. Provenex makes those questions answerable; it does not answer them.

## Security FAQ

### Can a regulator verify our receipts without our infrastructure?

Yes. Hand them the receipt JSON and your public key (for Ed25519) or shared HMAC secret (for HMAC). They run `pip install provenex-core[ed25519]` and `provenex audit receipt.json --public-key your-audit.pub`. No database access, no API access, no network calls. The verification is purely arithmetic over the receipt and the key material.

### What if our signing key is compromised tomorrow?

Old receipts continue to verify as long as the verifier has the corresponding key material. New receipts signed under a compromised key can be forged by the attacker, so rotate. Decision points:

- **Rotate immediately**: a new key is generated, the old one is revoked, all new receipts use the new key. Auditors are notified of the rotation event and add the new public key to their verification chain.
- **Reissue compromised-window receipts**: if you can re-derive the receipts (e.g., from preserved input chunks and the surviving provenance index), reissue them under the new key. Old key + old receipts get a "compromised window" note in your compliance record.

The hosted Provenex commercial product offers automated key-rotation tooling that handles this without manual rebuild. The OSS core ships the cryptographic primitives; the orchestration is your call.

### What if the provenance database is leaked?

The provenance database is **not** sensitive in the same way a customer-data store is. It contains:

- SHA-256 fingerprints (one-way; cannot be reversed to text)
- Document IDs (caller-chosen, usually opaque)
- Document versions (also SHA-256 hashes)
- Timestamps and authorization flags
- HMAC signatures over the rows

It does **not** contain:

- Document content
- Chunk text
- Embeddings (those live in your vector DB)
- PII (unless you chose to encode PII into `document_id`, which you shouldn't)

A leaked Provenex database would let an attacker enumerate fingerprints (useless without matching plaintext) and infer ingest timing and rough document sizes (low-information). Treat it like a structural log file, not like a database of customer data.

### What's the practical difference between HMAC and Ed25519, and when do we use each?

| | HMAC-SHA256 | Ed25519 |
| --- | --- | --- |
| Key material | One shared secret | Private + public keypair |
| Signer + verifier | Anyone with the secret can do both | Producer signs (private), auditor verifies (public) |
| Forgery resistance against the verifier | No (the verifier can forge) | Yes |
| Signature size | 32 bytes | 64 bytes |
| Verification speed | Slightly faster (just HMAC) | Fast (Ed25519 is ~50µs typical) |
| Dependency | None (stdlib) | `cryptography>=42.0` (optional extra) |
| Default for | In-house compliance: receipt producer and verifier are the same org | External auditors, cross-org provenance, regulator handoff |

If in doubt, start with HMAC. Move to Ed25519 the moment a receipt needs to be verified by anyone outside your trust boundary.

### What does Provenex *do* when it detects tampering?

By itself, nothing. Provenex is a verification layer; it returns an outcome (`TAMPERED`, `UNVERIFIED`, etc.) and a signed receipt. What to do with that outcome is policy:

- **`block_*=True`**: the chunk is removed before reaching the LLM. The receipt still records the blocked attempt. The application can take additional action (alert, page, refuse to answer).
- **`flag_*=True`** (default for most outcomes): the chunk is allowed through, the outcome is on the receipt. Suitable for surveillance-only deployments where you want telemetry but not interruption.

Wire your alerting to the receipt summary's `overall_status` field (PASS / PARTIAL / FAIL) or to specific outcomes in the per-source records.

### What about adversarial inputs designed to collide with legit fingerprints?

SHA-256 is collision-resistant for any computationally feasible attacker. A second-preimage attack would require ~2^128 operations. Practical adversarial inputs designed to clash with a specific authorized fingerprint are infeasible.

The Rabin-Karp rolling hash used to *find* sliding-window positions is NOT cryptographic and is collision-prone for adversarial input. That's intentional. The rolling hash exists only to make windowing cheap, not to be secure. The SHA-256 over each window is what gives cryptographic identity, and adversarial collisions there are not feasible.

### Can the index ingest content I don't actually have authorization to fingerprint?

The ingest API takes whatever bytes you give it. If your application calls `ingestor.ingest(...)` on content the user wasn't authorized to provide, Provenex will dutifully fingerprint it. **Authorization is your application's job, not Provenex's.** What Provenex offers is a way to *record* and *prove* the authorization state at ingest time, via the `authorized=True/False` flag and the `set_authorization(doc_id, ...)` mutation. Misuse of that API is operational, not cryptographic.

### How does this interact with PII / GDPR / data residency?

Provenex stores SHA-256 hashes of normalized chunk text plus caller-chosen identifiers. We do not consider one-way hashes to be PII in most regulatory frameworks (notably, GDPR Recital 26: pseudonymous data that cannot reasonably be linked back to a person without additional information). Consult your DPO / regulatory counsel.

Caller-chosen `document_id` is the variable here: if you encode PII into `document_id`, the provenance index now contains that PII. Don't do that. Use stable opaque identifiers (UUIDs, hashes of source URLs, etc.).

### Where is the audited reference implementation?

[`provenex/`](../provenex/) is about 1,200 lines across normalizer, hasher, fingerprinter, index, policy, receipt, and ed25519. The algorithm is small enough to be reviewed end-to-end in an afternoon. That is the point of open-sourcing the core.

## Reference implementations of specific defences

- HMAC row-signing: [`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py), `_canonical_payload` + `_sign`
- Merkle transparency log: [`provenex/index/merkle_sqlite_index.py`](../provenex/index/merkle_sqlite_index.py), [`provenex/core/merkle.py`](../provenex/core/merkle.py)
- Receipt signing (HMAC + Ed25519 + signer interface): [`provenex/core/receipt.py`](../provenex/core/receipt.py), [`provenex/core/ed25519.py`](../provenex/core/ed25519.py)
- Offline verification: [`provenex/core/merkle.py`](../provenex/core/merkle.py) `verify_inclusion_proof`, `provenex/cli/main.py` `_cmd_audit`

If you find a security issue, please report it privately to `security@provenex.ai` rather than via a public issue.
