# Threat model + security FAQ

The audience for this document is a security architect, a compliance reviewer, or an internal red team evaluating whether Provenex meets their threat-modelling bar. We cover what attacks Provenex defends against, what it explicitly does not, and the questions teams have asked us in practice.

If you only have time for one section, read the **what we don't protect against** part. Most of what kills software-security posture is a real attacker doing a thing the architecture was never designed to stop.

## Trust root, stated up front

Provenex's guarantees are rooted in **one piece of cryptographic key material** (HMAC secret or Ed25519 private key) and the **integrity of the index storage**. If either of those is fully compromised, no Provenex check catches it; defence at that point is operational (separation of duties, HSM-backed keys, witness gossip to a party the operator does not control). We say this first, in plain terms, because every detailed property below assumes this baseline. The OSS core ships the cryptographic primitives and a minimal local witness log ([Witness / checkpoint log (v0.8.0)](#witness--checkpoint-log-v080)); a hosted gossip cluster, transparency-log-backed policy bundles, and HSM key management are the commercial layer.

Specific consequences operators should plan around:

- A leaked signing key lets an attacker mint receipts that verify cleanly. Rotation and revocation are operational, not cryptographic; see [What if our signing key is compromised tomorrow?](#what-if-our-signing-key-is-compromised-tomorrow).
- A read-write attacker who also has the index secret can append fake history that internally verifies. The Merkle log on its own catches insertions and removals to anyone who has previously seen a tree head; the witness log puts that property within the OSS layer. Split-view resistance against a key-holding operator additionally requires external publication of witness records.
- The policy file is trust-rooted to the operator. The native YAML evaluator validates syntax, not business semantics. See [The policy file is trust-rooted to the operator](#the-policy-file-is-trust-rooted-to-the-operator).

The rest of this document is precise about which threat each mechanism handles and which threat it does not.

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

### Window-aligned splice (substring promotion to VERIFIED)

**Threat:** the ingest pipeline writes both a whole-document SHA-256 and many sliding-window fingerprints into the same provenance index. Pre-v0.8.0, both kinds of row were treated identically at verify time, so any 128-codepoint substring of an authorized document promoted to `VERIFIED` on its own. An attacker could carve a chunk that lines up with an indexed window and have it pass as authorized, even though no operator ever signed off on that substring as a discrete chunk. The strongest form of the same attack is to splice two authentic windows from two authorized documents and present the join as one authorized chunk.

**Mechanism:** v0.8.0 added an `entry_kind` field on every index row, signed as part of the canonical row payload. Whole-chunk entries (`entry_kind="whole_chunk"`) are eligible for `VERIFIED` at verify time; sliding-window entries (`entry_kind="window"`) are retained only for structural locating and STALE reasoning, never for promotion. An attacker who flips the field via a storage-layer write invalidates the row signature and triggers `TAMPERED`.

**Result:** a window-aligned substring returns `UNVERIFIED`; the receipt records the window locator metadata so an auditor can see that the bytes came from a known document at a known offset, but were not the operator-authorized chunk. Spliced concatenations of authentic windows also return `UNVERIFIED` because the splice's whole-chunk SHA-256 matches no whole-chunk row.

**Reference:** [`tests/test_window_splice_redteam.py`](../tests/test_window_splice_redteam.py) carries the red-team coverage that asserts this property end-to-end.

### Injection of content that was never ingested

**Mechanism:** any chunk that comes out of a retriever is re-fingerprinted and looked up in the provenance index. A chunk whose fingerprint isn't present in the index produces an `UNVERIFIED` outcome.

**Result:** with `VerificationPolicy(block_unverified=True)` the chunk is removed before reaching the LLM. With looser policy the chunk is still flagged on the receipt. Either way an auditor sees that an un-ingested chunk attempted to enter the answer.

**Use cases this catches in practice:** dataset poisoning, prompt-injected web scraping, mislabeled "freshly added" chunks that bypass the proper ingest pipeline, a colleague who added documents to the vector DB without running them through Provenex.

### Tampering with the receipt itself

**Mechanism:** the receipt is signed end-to-end. The signature covers the JSON canonical serialization of every field on the receipt (sources, policy, summary, transparency log head, output hash, timestamps, `request_binding`, `caller_hash`) minus the signature block itself.

**Result:** any modification to the receipt body invalidates the signature. An auditor running `verify_receipt_signature` (or `provenex audit receipt.json`) detects the change and returns FAIL.

### Re-presenting a receipt as evidence for a different query

**Threat:** the link between a receipt and the request that produced it used to be implicit and operator-controlled. A valid signed receipt for query A could be presented downstream as evidence that query B was "grounded in authorized sources," because nothing on the receipt cryptographically committed to the actual triggering query.

**Mechanism:** v0.8.0 added a top-level `request_binding` block to every receipt. The block carries `query_hash` (SHA-256 of the query / prompt text) and `request_context_hash` (SHA-256 of the canonical `request_context` minus session_id, which is excluded by the same rule used for `inputs_hash`), plus a combined `request_hash`. The block is part of the canonical signing payload, so an attacker who edits any of those fields invalidates the receipt signature. An auditor who has the original query and request_context re-derives the hashes and confirms a match.

**Result:** a valid receipt is tied to one specific (query, request_context) pair. Re-presenting it as evidence for a different query is a forgery that any verifier with the originals will catch. The verbatim query text is never stored on the receipt; only its hash. Operators who omit `request_text` get `query_hash: null` recorded on the receipt so the absence is visible to an auditor reading the JSON.

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

### Unwrapped agent code that bypasses the SDK

Provenex is a library: an agent emits a receipt **only when its code calls into Provenex**. An agent that retrieves a chunk without going through `verify_chunks(...)` or invokes a tool without going through `admission_check(...)` produces no receipt at all. The absence of a receipt is not, on its own, proof of misbehavior; it is the absence of evidence.

This matters in two operationally distinct cases:

1. **Honest gaps in coverage.** An engineering team rolls out Provenex on the chat retrieval path but a sidecar pipeline (overnight batch enrichment, an evals harness, a customer-support tool) still calls the same retriever or the same external API directly. The omission is not adversarial; it is a coverage rollout problem. Treat it the way you would treat "we have IAM on the prod tier but not on the staging tier": find every code path that touches retrieval or tool execution and wrap it.

2. **Adversarial bypass.** An attacker who controls the agent process (RCE in the agent container, malicious extension, compromised CI that rebuilds the agent image) can simply remove the Provenex calls before invoking the retriever or the tool. The verify path can't catch this from the outside; from the verifier's point of view, the attacker's path produces no receipts, indistinguishable from honest gap (1).

**Why no in-band defence.** A library that lives in the same process as the caller cannot prove it was actually invoked. Any check we added inside the SDK is removable by the same attacker who removed the wrapper. This is the SDK-enforcement limit. It is the same boundary you accept when you say "OpenTelemetry tracing requires you to instrument your code" or "IAM SDKs only authorize calls that go through the SDK".

**Mitigation patterns:**

* **Proxy / gateway mode.** Put the tool or LLM provider behind a network endpoint that requires a Provenex receipt header on every request and rejects calls without one. The agent still has to mint the receipt, but a process that skips the wrapper now also loses access to the tool. This pushes the enforcement boundary out of the agent process. Provenex composes with this pattern but does not ship the gateway in the OSS core; common gateways (Envoy, Kong, Apigee, custom MCP proxies) can validate the receipt header against the public key.
* **Tool-side acceptance check.** For tools you control, have the tool itself require a fresh signed Provenex receipt bound to the request (via `request_binding.query_hash`) before executing. A tool that refuses requests without a valid recent receipt forces the agent to go through Provenex even on attacker-controlled paths.
* **Receipt-rate alerting.** A path that should produce one receipt per request but suddenly produces fewer (or none) is a strong signal. Alert on the ratio of `provenex_verify_total` / inferred-traffic, or on a sudden caller-side drop in the SIEM. This catches both honest gaps and adversarial bypass after the fact.
* **Build / lint enforcement.** Static checks at CI time that flag direct calls to the unwrapped retriever or the bare tool client. This catches case (1) at the code-review boundary, but does not defend against (2): an attacker rewriting the binary at runtime is not constrained by your lint rules.

**What the receipt itself can offer.** When a *wrapped* request is honest, the receipt's `request_binding` block ties the receipt to the specific query and request context. If a downstream tool acceptance check (mitigation 2) validates this binding, the agent has no path that produces a useful artifact without going through Provenex; the wrapper is enforced not by us, but by the system that consumes the receipt.

This threat is the reason the gateway / proxy story matters more than additional in-SDK hardening would. We have prioritized the binding primitives (`request_binding`, `caller_hash`) so downstream enforcement layers have something concrete to validate against.

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

The native YAML evaluator loads a policy file the operator configured. The evaluator does not validate that the policy is "correct" in any business sense - it only validates that the YAML parses and that no reserved-but-unimplemented features are present. An operator who controls the signing key AND the policy file can author any policy they want and produce decisions that verify cleanly under that policy.

The commercial transparency-log integration is the planned mitigation: `policy_version_hash` would be published to an append-only log, so an auditor handed a receipt can independently confirm the policy in effect at the time of the decision was the one the operator publicly committed to. In the open-source core, `policy_in_transparency_log` is always `false`. Until that field lights up, the policy file is trusted as configured by the operator, the same way the index signing key is trusted as configured by the operator.

### A decision is only as trustworthy as the metadata feeding it

Provenex's evaluator reads two kinds of input: chunk metadata (residency tags, classification, PII flags, freshness, content_source) and request context (caller, jurisdiction, purpose, timestamp). The trust property of each depends on **when** the value was bound:

- **Tag-at-ingest.** When a residency or classification tag is written into the chunk's record at ingest time, the tag is covered by the index row's HMAC and (with the Merkle log) the tree head. An attacker cannot retroactively flip a tag without invalidating the row's signature. This is the strongest case.
- **Tag-at-evaluate.** When a tag is looked up from an external system at decision time (a live IAM lookup, a feature-flag service, a sidecar with the user's current role), the decision is only as trustworthy as that external system. Provenex records the value it read in `policy.access_control.decisions[i].inputs`, but cannot vouch for whether it was the right value. If the external system is compromised or stale, the decision will be too.

A defensible deployment binds as much policy-relevant metadata at ingest time as practical, and treats tag-at-evaluate as a separate audit concern.

**Caller-predicated rules are necessarily at_evaluate.** Any rule that gates on `request.caller.role`, `request.caller.id`, `request.jurisdiction`, or `request.purpose` reads inputs that are inherently per-request and constructed at retrieval time. There is no at_ingest analog: the chunk did not "know" at ingest time who would later read it. So the tag-at-ingest story does not strengthen access-control rules of this shape; their trust class is fixed at `at_evaluate` regardless of how `chunk_metadata_binding` is declared. The receipt makes this explicit on every decision via `metadata_binding.request_context = "at_evaluate"`. Operators who want stronger guarantees over caller identity should harden the identity provider feeding `request_context.caller`, since that is the upstream trust root.

**Schema 2.1.0** makes this distinction explicit on the receipt. Every decision record carries a `metadata_binding` field declaring the trust class of each input:

```json
"metadata_binding": {
  "chunk_metadata": "at_ingest",     // signed by the index row
  "request_context": "at_evaluate"   // built fresh at retrieval
}
```

An auditor reading the receipt now sees, per chunk, whether the decision rested on signed-at-ingest tags or external-system-at-evaluate tags. `request_context` is always `at_evaluate` (the caller dict is constructed per-request). `chunk_metadata` is operator-declared via `verify_chunks(..., chunk_metadata_binding=...)`. The field is non-load-bearing for the decision itself - it does not change whether the chunk reaches the LLM - but it is load-bearing for *audit trust*: an auditor handed a receipt with everything `at_evaluate` is reading a weaker guarantee than one handed a receipt with `chunk_metadata: at_ingest`.

### Operator-with-everything can produce any decision

An operator who controls the signing key AND the policy file AND the metadata pipeline can produce a fully internally-consistent receipt that says anything they want. This is the policy-decision analog of the existing "Coordinated tampering at both ingest and verify time" threat. The defence is the same: separation of duties, code review on the policy file, transparency-log gossip with witnesses (commercial), and independent audit by a party that does not share the operations team's access.

### The receipt records what the policy decided, not whether the policy was right

The signed receipt is non-repudiable evidence that, under policy `policy_id` with version hash `policy_version_hash`, the evaluator returned the recorded decision for the recorded `(chunk, request)` pair. That is the strongest claim the receipt makes. Whether the policy itself was the right policy to apply, or whether the decision was the right decision under that policy, are upstream questions for governance review. Provenex makes those questions answerable; it does not answer them.

## Security FAQ

### Can a regulator verify our receipts without our infrastructure?

Yes. Hand them the receipt JSON and your public key (for Ed25519) or shared HMAC secret (for HMAC). They run `pip install provenex-core[ed25519]` and `provenex audit receipt.json --public-key your-audit.pub`. No database access, no API access, no network calls. The verification is purely arithmetic over the receipt and the key material.

A leaner alternative for third-party auditors who do not want the full `provenex-core` install is the standalone [`provenex-verifier`](https://github.com/aoptimystic/provenex-verifier-python) library: `pip install provenex-verifier && provenex-verify receipt.json --public-key your-audit.pub`. Single dependency (`cryptography`), MIT-licensed, no network, no `provenex-core` import. Same canonicalisation and signature rules; the two implementations agree byte-for-byte.

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

If in doubt, start with HMAC. Move to Ed25519 the moment a receipt needs to be verified by anyone outside your trust boundary. For receipts that may end up in a regulator's hands, Ed25519 is the right default; the OSS core ships it under the `[ed25519]` extra.

### What security properties are in OSS vs commercial?

We describe the split by property, not by feature, because operators need to know which threat is and is not addressed in the OSS layer before they pick a deployment shape.

| Security property | OSS layer | Requires commercial |
| --- | --- | --- |
| Detect tampering with any single index row (without the index secret) | Yes (HMAC-signed rows, since v0.1). | n/a |
| Detect insertion / removal of rows by an attacker WITHOUT the index secret | Yes (Merkle transparency log, optional). | n/a |
| Detect insertion / removal of rows by an attacker WITH the index secret | Partial: an external party who has seen any earlier tree head detects divergence locally. The local witness log (v0.8.0) gives operators the signed checkpoint record. | **Split-view resistance against a key-holding operator requires external witness gossip:** publish witness records to a store the operator does not control, or use a hosted Provenex witness cluster that gossips signed tree heads. The OSS layer emits the producer-side artifact; closing the property end-to-end requires either operator-disciplined publication or the hosted cluster. |
| **Non-repudiation against the operator (no plausible-deniability via retroactive history rewrite)** | Partial: the witness log + Ed25519 signing gives the cryptographic backbone. | Same as split-view: needs external gossip to a third party. HSM-backed key storage closes the "exfiltrate the key, rewrite anyway" residual. |
| Verifiable offline by a regulator (no Provenex infrastructure dependency) | Yes (Ed25519 + signed receipts). | n/a |
| Window-aligned splice control (substrings cannot promote to VERIFIED) | Yes (entry_kind, v0.8.0). | n/a |
| Receipt-to-request binding (a receipt cannot be re-presented for a different query) | Yes (`request_binding`, v0.8.0). | n/a |
| Five-outcome precedence (TAMPERED > UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED) | Yes (codified in `OUTCOME_PRECEDENCE`, v0.8.0). | n/a |
| Peppered fingerprints (blunts confirmation attack on low-entropy corpora) | Yes (`FingerprinterConfig.pepper`, v0.8.0). | n/a |
| Trajectory-level rules / cross-decision aggregations / external-data lookups in the policy engine | No (deliberately refused, see [`docs/policy.md`](policy.md)). | Available via the Rego adapter; trade-off: trajectory rules in-engine give up the audit-anchor guarantees that per-decision purity provides. |
| Compliance-grade export formats (PDF, CSV, JSON-LD) | No. | Yes. |
| Hosted distributed signed-append-only index, Bloom-filter acceleration at 10M+ scale, transparency-log-backed policy bundle publication | No. | Yes. |
| HSM-backed Ed25519 key custody, IdP integration, dedicated support / SLA | No. | Yes. |

The OSS layer covers every cryptographic property a single-operator deployment needs to defend itself against external attackers and accidental corruption. The commercial layer adds the properties that require coordination outside the operator's own infrastructure: gossip witnesses, hosted append-only storage, HSM custody, and the policy-language layer (Rego / OPA service) that brings stateful enforcement at the cost of per-decision purity.

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

Provenex stores SHA-256 hashes of normalized chunk text plus caller-chosen identifiers. One-way SHA-256 hashes are not directly reversible, which is the property GDPR Recital 26 cites in the pseudonymisation guidance. That property is necessary but not sufficient: for a **low-entropy corpus**, an attacker who has plausible candidate plaintexts (an HR template library, a fixed policy boilerplate, an enumerable form) can recompute the unpeppered SHA-256 of each candidate and confirm presence in the index. The hash is not reversible, but it is testable, and a confirmation attack against an enumerable space can effectively re-link a hash to its plaintext given enough context. v0.8.0 added a per-deployment **pepper** ([Item 8 / `FingerprinterConfig.pepper`](how_it_works.md#peppered-fingerprint-mode-for-low-entropy-corpora)) that turns the hash into HMAC-SHA256(pepper, normalized) and blunts the confirmation channel, but the underlying point stands: regulatory categorisation of fingerprints in your corpus depends on the corpus's entropy and the specific test your regulator applies. **Consult your DPO / regulatory counsel.** Don't take a sentence in this README as a substitute for that conversation.

Caller-chosen `document_id` is the variable that operators most often get wrong: if you encode PII into `document_id`, the provenance index now contains that PII. Don't do that. Use stable opaque identifiers (UUIDs, hashes of source URLs, etc.).

### Where is the audited reference implementation?

[`provenex/`](../provenex/) is the OSS core. See [`docs/how_it_works.md`](how_it_works.md) for the line-by-line walkthrough with source pointers, and `provenex selftest` for a self-contained conformance check of the installed binary against the documented properties.

## Witness / checkpoint log (v0.8.0)

Source: [`provenex/core/witness.py`](../provenex/core/witness.py); tests: [`tests/test_witness_log.py`](../tests/test_witness_log.py).

The witness log is a hash-chained, signed, append-only JSONL log of `(checkpoint_index, tree_size, tree_root, issued_at)` records. Each record's `previous_checkpoint_hash` is the SHA-256 over the prior record's canonical JSON including its signature, and the signature covers `previous_checkpoint_hash`, so retroactively editing record N requires also reforging every record after N (otherwise the chain link fails at N+1). The class is the producer-side artifact of the standard CT witness pattern: the operator publishes each line to a store the operator does not retroactively control, which is what closes split-view resistance against a key-holding attacker. The class docstring spells out which properties the local log alone provides (tamper-detection on past records, truncation detection if the verifier has seen any earlier record) and which require external publication (split-view across two parallel histories).

`provenex selftest` includes a check that the chain integrity property still holds on the installed binary.

## Reference implementations of specific defences

- HMAC row-signing: [`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py), `_canonical_payload` + `_sign`
- Merkle transparency log: [`provenex/index/merkle_sqlite_index.py`](../provenex/index/merkle_sqlite_index.py), [`provenex/core/merkle.py`](../provenex/core/merkle.py)
- Receipt signing (HMAC + Ed25519 + signer interface): [`provenex/core/receipt.py`](../provenex/core/receipt.py), [`provenex/core/ed25519.py`](../provenex/core/ed25519.py)
- Offline verification: [`provenex/core/merkle.py`](../provenex/core/merkle.py) `verify_inclusion_proof`, `provenex/cli/main.py` `_cmd_audit`
- Window-splice control: [`provenex/index/base.py`](../provenex/index/base.py) `ENTRY_KIND_*` + [`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py) `verify()`
- Receipt-to-request binding: [`provenex/core/receipt.py`](../provenex/core/receipt.py) `compute_request_binding`
- Witness / checkpoint log: [`provenex/core/witness.py`](../provenex/core/witness.py)
- Conformance self-test: [`provenex/cli/main.py`](../provenex/cli/main.py) `_cmd_selftest`

If you find a security issue, please report it privately to `contact@provenex.ai` rather than via a public issue.
