# Data sovereignty

How to deploy Provenex when data must stay within a jurisdiction. This doc covers two deployment patterns (one-region-per-jurisdiction, shared-index-with-residency-tags), the privacy properties of the provenance index that make either pattern defensible, and what those properties mean for GDPR Article 17 (right to erasure).

The trust model is in [threat_model.md](threat_model.md); the multi-region operations are in [runbooks/disaster_recovery.md § Multi-region replication patterns](runbooks/disaster_recovery.md#scenario-4-multi-region-replication-patterns).

## What is in the Provenex index

The Provenex index stores:

- SHA-256 fingerprints (one-way hashes of normalised chunk text)
- Caller-chosen `document_id`
- `document_version` (SHA-256 of the normalised full document)
- `ingested_at` timestamp
- `chunk_offset`, `chunk_length` (positions within the normalised document)
- `authorized` flag, `superseded` flag, `entry_kind` field
- HMAC signature over the canonical row payload

It does **not** store:

- Document content
- Chunk text
- Embeddings
- Caller PII (unless the operator encodes it into `document_id`; don't)

The fingerprints are one-way. A SHA-256 hash of normalised text is not directly reversible to the original text; a regulator asking "can the index be used to reconstruct a document" has a clear no. For low-entropy corpora where an attacker has plausible candidate plaintexts (HR templates, fixed policy boilerplate), the peppered-fingerprint mode (`FingerprinterConfig.pepper`) closes the confirmation channel by switching to HMAC-SHA256(pepper, normalized). See [threat_model.md § How does this interact with PII / GDPR / data residency?](threat_model.md#how-does-this-interact-with-pii--gdpr--data-residency).

The receipt stores hashes, metadata, and the SHA-256 of the LLM output. The verbatim query text is never recorded; only `request_binding.query_hash`. Per-decision `inputs` can be redacted to `null` while keeping `inputs_hash`. Verbatim tool-call parameters, memory values, and model-inference prompts can be redacted the same way.

**Consequence for residency analysis:** the Provenex index is structurally not a copy of the regulated data. It is a tamper-evident record of *what was accessed*, with the data itself out of scope. Two regulators with the same Provenex index reach the same conclusions about who accessed what; neither can reach the underlying content from the index alone. The audit trail can therefore live in a different jurisdiction from the underlying data, **if** the operator's compliance counsel agrees. (Most regulators care less about hashes than about content; the exact analysis depends on the corpus, the regulator, and the specific test being applied. Consult counsel.)

## Pattern A: one Provenex instance per jurisdiction

The most defensible deployment for strict residency rules. Each region (EU, US, APAC) has its own Provenex instance: its own Postgres, its own signing key, its own ingester pod, its own receipt archive, its own witness log.

```
+----------------- EU region -----------------+
|  Postgres (EU)                              |
|  Provenex signing key #1                    |
|  Receipts archived to EU S3 bucket          |
|  Witness log published to EU-resident store |
+---------------------------------------------+

+----------------- US region -----------------+
|  Postgres (US)                              |
|  Provenex signing key #2                    |
|  Receipts archived to US S3 bucket          |
+---------------------------------------------+

+----------------- APAC region ---------------+
|  Postgres (APAC)                            |
|  Provenex signing key #3                    |
|  Receipts archived to APAC S3 bucket        |
+---------------------------------------------+
```

**Cross-region retrieval is impossible by construction** (or forbidden by policy if technically possible). A request from the EU never sees US content because the EU instance does not have US fingerprints in its index. The audit story is per-region; an auditor verifying EU receipts uses the EU public key.

**Trade-offs:**

- The three indexes are siloed. A document re-ingested in region A is not visible in region B. This is usually the right answer for residency reasons; cross-region knowledge sharing is the application's problem to solve, not Provenex's.
- Three signing keys to rotate, three witness logs to publish, three secrets-manager entries to maintain. Operational overhead per region is roughly the single-region operational overhead times three.
- Auditors verifying receipts from multiple regions hold multiple public keys. Standard practice; not an audit-trail problem.

**When to choose Pattern A:**

- Regulated industries with strict residency rules (financial services in EU under GDPR plus EBA guidelines; healthcare in EU under GDPR; defence contractors under ITAR or local equivalent).
- Multi-tenant SaaS where tenants' data must not cross regional boundaries even at the audit layer.
- Operational simplicity preference: "this region's data never leaves this region, by construction."

## Pattern B: shared index with residency tags

One Provenex instance: one Postgres primary plus regional read replicas, one signing key, one witness log. Documents carry residency tags (`chunk.metadata.residency = "EU" | "US" | "APAC"`); the policy `access_control` rules gate retrieval by `request.jurisdiction` against `chunk.metadata.residency`.

```
+------------------ Single Provenex instance ------------------+
|  Postgres primary (home region)                              |
|  Read replicas in EU, US, APAC                               |
|  One signing key, one witness log                            |
|  Per-region verify pods read from local replicas             |
|  Policy enforces residency via chunk.metadata.residency tag  |
+--------------------------------------------------------------+
```

The policy rule:

```yaml
access_control:
  rules:
    - name: residency_gate
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency: { in: [EU, EEA] }
      on_violation: deny
    - name: residency_gate_us
      when:
        request.jurisdiction: US
      require:
        chunk.metadata.residency: US
      on_violation: deny
    # ... per-region rules ...
  defaults:
    unknown_metadata: deny
```

**Trade-offs:**

- One signing key, one tree, one set of witness records. Auditor verification is simple.
- The residency enforcement depends on the policy file being correct. A misconfiguration can leak cross-region content. Defensible only if the policy authoring process has tight controls (CI policy validation, peer review, the `provenex policy hash` discipline to catch silent changes).
- The Postgres replicas in each region carry the full index, including fingerprints of other regions' content. The fingerprints are not the content, so most regulators do not treat this as a residency violation, **but the residency analysis depends on the regulator and the corpus**. Consult counsel before assuming a fingerprint of EU content stored in a US replica is acceptable under EU rules.

**When to choose Pattern B:**

- Single-region by data nature, multi-region by user nature (a single-tenant SaaS with users in multiple regions but data in one).
- Residency rules that turn on *access* rather than *storage* (the audit log can live anywhere; the data and the access decisions are tagged appropriately).
- Operational preference for one audit story over three.

## GDPR Article 17: right to erasure

Article 17 grants the data subject a right to erasure of personal data concerning them, under certain conditions. The Provenex implications:

**The index does not contain personal data in the GDPR sense.** Recital 26 of GDPR distinguishes data rendered "irreversibly anonymous" from personal data. SHA-256 of normalised chunk text plus caller-chosen identifiers is not directly reversible; whether it qualifies as anonymised depends on the corpus's entropy and the specific test the regulator applies. For high-entropy corpora (free-form documents, narrative text), the fingerprints are practically irreversible; for low-entropy corpora (HR templates, enumerable forms), use the peppered-fingerprint mode and consult counsel.

**The receipts may contain personal data.** Each receipt's `inputs` block (under `policy.access_control.decisions[i].inputs.request_context.caller`) contains the verbatim caller dict; this often includes identifiers like `caller.id` that are personal data. The operator's options:

- **Redact `inputs` while keeping `inputs_hash`.** Set `inputs: null` on emission via the relevant evaluator setting; the audit anchor (`inputs_hash`) remains, but the verbatim caller dict does not. An auditor with the original `RequestContext` (held out-of-band by the operator) can re-derive the hash; a third party reading the receipt cannot recover the caller identity.
- **Salt `caller_hash`.** Pass `caller_hash_salt=b"..."` on every emission entrypoint. `caller_hash` is then an HMAC keyed by the salt; without the salt, the hash cannot be linked to an identity. Two deployments with different salts produce different hashes for the same user.
- **Erase the receipt entirely.** A specific receipt can be deleted from the receipt archive without invalidating any other receipt (each receipt is self-contained; receipts do not chain). The signed audit trail loses that one entry but is otherwise intact.

**The index does not need to change for an erasure request.** The fingerprints are not personal data; deleting them is neither required (the fingerprints don't reveal identity) nor especially meaningful (the same content re-ingested produces the same fingerprint anyway). If your compliance counsel determines a specific fingerprint must be removed, `index.delete_document(document_id)` is the API; the row is removed and the supersession state is unchanged for other documents.

**The witness log is append-only and signed.** A witness record cannot be retroactively edited without breaking the chain (which would be visible to anyone holding any earlier record). If an erasure request requires removing a witness record, the chain integrity breaks and the audit-trail discontinuity must be documented. Most regulators do not require erasure of witness records (which contain only `tree_size` and `tree_root`, no personal data); confirm with your DPO before assuming the witness log is in scope.

## Read next

- [threat_model.md § How does this interact with PII / GDPR / data residency?](threat_model.md#how-does-this-interact-with-pii--gdpr--data-residency): the threat-model framing.
- [runbooks/disaster_recovery.md § Multi-region replication patterns](runbooks/disaster_recovery.md#scenario-4-multi-region-replication-patterns): the operational recovery procedures.
- [secure_defaults.md § Peppered fingerprint mode](secure_defaults.md#peppered-fingerprint-mode): when to use the pepper.
