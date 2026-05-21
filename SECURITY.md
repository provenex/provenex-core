# Security policy

## Reporting a vulnerability

Please report security vulnerabilities to **contact@provenex.ai**.

Do not file public GitHub issues for security bugs. A public issue puts other Provenex users at risk before a fix is available.

When reporting, please include:

- A description of the issue and the security property it breaks.
- Steps to reproduce, ideally with a minimal proof-of-concept. Pseudocode is fine if a real PoC would publish a working exploit.
- Affected Provenex version(s), Python version, and platform.
- Any suggested fix or mitigation.

We will acknowledge receipt within **2 business days** and aim for an initial assessment within **5 business days**. Critical issues (key compromise, signature bypass, receipt forgery) are prioritised; everything else is triaged in order of severity.

## Safe harbor

We will not pursue legal action against researchers who follow this policy in good faith. This includes:

- Accessing only your own test data; never accessing other users' data or production systems we do not control.
- Stopping at the proof-of-concept stage; not exfiltrating data, not pivoting to other systems, not maintaining persistence.
- Reporting promptly via the channel above and giving us reasonable time to fix before public disclosure (see § Disclosure below).
- Not violating any other applicable law in the course of your research.

If you are unsure whether a specific research activity falls inside this safe harbor, email **contact@provenex.ai** before testing. We will respond quickly.

This policy is aligned with the conventions documented at [disclose.io](https://disclose.io/).

## Encrypted reports

A real signature-bypass or receipt-forgery PoC should not travel by cleartext email. Two ways to send an encrypted report.

### Option A: age (recommended)

[age](https://age-encryption.org/) is a small encryption tool with X25519-based recipients. Encrypt your report against the recipient below, then attach the resulting `.age` file to the email.

> **Provenex security age recipient:**
>
> ```
> age1qnrg4rue5lhqmzp437mr4uqx33wcc0jngv490xsn3me2kwy6jyyqaphavj
> ```

To encrypt:

```bash
# Install age first:
#   macOS:  brew install age
#   Linux:  apt install age   (or)   go install filippo.io/age/cmd/age@latest

age -r age1qnrg4rue5lhqmzp437mr4uqx33wcc0jngv490xsn3me2kwy6jyyqaphavj \
    -o report.age report.md

# Attach report.age to the email; subject line ok in cleartext.
```

### Option B: PGP

If your workflow is PGP-based, look up the key for `contact@provenex.ai` on [keys.openpgp.org](https://keys.openpgp.org/) or request the public key via the contact address. We will reply with the current fingerprint inline.

### Note on algorithm choice

Provenex receipts are signed with Ed25519 (a signing-only EdDSA scheme). The encrypted-report channel uses age's X25519 (an encryption-only ECDH scheme) because Ed25519 cannot decrypt. Both are EdDSA-family curves; the operational difference is a property of the operations, not of the trust root.

## Supported versions

Provenex is in active development. Security fixes are issued for:

| Version | Supported |
| --- | --- |
| 0.9.x (current minor) | Yes |
| 0.8.x | Critical fixes only |
| <= 0.7.x | No |

Receipts produced under any version remain verifiable: rotation does not invalidate prior receipts, and the signature primitives (HMAC-SHA256, Ed25519) are not version-gated. The "supported" column governs which version we will publish a patched release of, not which receipts remain auditable.

## Scope

In scope:

- The OSS core under [`provenex/`](provenex/): fingerprinter, normalizer, hasher, the `ProvenanceIndex` implementations (sync + async Postgres, SQLite, Merkle variants), the policy evaluator, the receipt builder and signers, the witness log, the CLI, the HTTP server under [`provenex/server/`](provenex/server/), the operator under [`provenex/operator/`](provenex/operator/), the KMS adapters under [`provenex/kms/`](provenex/kms/), the multi-tenant signer registry, the drift detector under [`provenex/drift/`](provenex/drift/), and the integrations under `provenex/integrations/` and `provenex/tool_call/integrations/`.
- The streaming-export sinks under [`provenex/export/`](provenex/export/).
- The reference container ([`Dockerfile.server`](Dockerfile.server)), the Helm chart ([`deploy/helm/provenex-server/`](deploy/helm/provenex-server/)), the Policy CRD + operator ([`deploy/operator/`](deploy/operator/)), and the retention Terraform module ([`deploy/terraform/receipt_archive/`](deploy/terraform/receipt_archive/)).
- Documented security properties in [docs/threat_model.md](docs/threat_model.md), [docs/how_it_works.md](docs/how_it_works.md), [docs/receipt_format.md](docs/receipt_format.md), [docs/key_management.md](docs/key_management.md), and [docs/secure_defaults.md](docs/secure_defaults.md).

Out of scope (please do not report):

- Threats Provenex does not protect against. See [docs/threat_model.md § Threats we explicitly do not protect against](docs/threat_model.md#threats-we-explicitly-do-not-protect-against): compromised signing keys, compromised LLMs, coordinated tampering at both ingest and verify time, and vector-DB-level integrity. These are operational concerns and are explicitly documented as such.
- Third-party dependencies (PyYAML, psycopg, cryptography, kafka-python, boto3, google-cloud-pubsub, fastapi, uvicorn, kopf, kubernetes, PyJWT, and the rest). Report those upstream; we will track and adopt fixes when available.
- Theoretical attacks against the underlying primitives (SHA-256 collision, Ed25519 forgery) absent a concrete exploit. Cryptographic primitive choices are documented in [docs/how_it_works.md](docs/how_it_works.md).

## What Provenex does NOT prove

This is a deliberate non-claim list. A security or procurement reviewer should know what is out of scope *before* they ask. Each item here has a deeper treatment in [docs/threat_model.md § Threats we explicitly do not protect against](docs/threat_model.md#threats-we-explicitly-do-not-protect-against); this section is the index.

- **Provenex does not prove that an LLM answer is correct.** Receipts record what chunks the retriever returned and the SHA-256 of the answer text. They do NOT detect hallucinations, faithfulness violations, or wrong inferences over correct inputs. Use a separate grounding / faithfulness layer for that.
- **Provenex does not prove that a tool call ran.** Receipts record the admission decision before the tool was invoked. Whether the tool actually executed, succeeded, or had the side effects it claimed is outside the receipt's claim. The execution log is the customer's existing observability stack.
- **Provenex does not prove that the agent process called Provenex at all.** Provenex is a library the agent imports. An agent that bypasses the wrapper (or a parallel process running unwrapped) produces no Provenex evidence, and the absence of a receipt is not, on its own, proof of misbehavior. See [docs/threat_model.md § Unwrapped agent code that bypasses the SDK](docs/threat_model.md#unwrapped-agent-code-that-bypasses-the-sdk) for the mitigation pattern.
- **Provenex does not prove that retrieved chunks are safe to feed an LLM.** Prompt-injection content inside a chunk that was correctly fingerprinted and authorized by the operator still becomes part of the LLM context. Provenex verifies provenance, not content safety. Pair with an input-sanitization or jailbreak-detection layer when prompt injection matters.
- **Provenex does not prove that the policy was the right policy.** The receipt records the policy that was in effect and the decision it produced. Whether that policy was authored correctly is an upstream governance question; the receipt makes it answerable (every decision is tied to a `policy_version_hash`), but does not answer it.
- **Provenex does not prove that the operator and the auditor are different parties.** An operator who controls both the signing key and the policy file can produce internally-consistent receipts that say anything. Defence is organizational (separation of duties, transparency-log gossip with external witnesses on the commercial path). See [docs/threat_model.md § Operator-with-everything can produce any decision](docs/threat_model.md#operator-with-everything-can-produce-any-decision).
- **Provenex does not prove that the vector database returned authorized content.** If an attacker rewrites embeddings or row metadata in the vector DB itself, the retriever may return chunks that are semantically unrelated to what was authorized but whose *text* still matches a fingerprinted entry; that text verifies. Vector-DB-level integrity is a separate concern.
- **Provenex does not prove anything about a compromised signing key.** A held key forges receipts. The defence is operational: rotate, store in HSM / KMS, treat the signer host as you would a TLS server key. See [docs/runbooks/key_rotation.md](docs/runbooks/key_rotation.md).

What the receipt DOES prove is narrow and precise: under the named policy with the named version hash, evaluating the recorded `(chunk, request)` pair, the evaluator returned the recorded decision, and the SHA-256 of the LLM output text is bound to that evaluation by signature. Everything else listed above is somebody else's job.

## Disclosure

The default disclosure window is **90 days** from the date of the initial assessment, extended by mutual agreement if a fix is in progress. We credit reporters in the release notes for the fix unless asked to do so anonymously.

## Hardening guidance

For operators deploying Provenex, the secure-defaults checklist is [docs/secure_defaults.md](docs/secure_defaults.md) and the threat model is [docs/threat_model.md](docs/threat_model.md). Run `provenex selftest` after every install to confirm the binary's pipeline matches the documented algorithm.

The most-asked operational questions, with the doc that answers each:

| Concern | Answer lives in |
| --- | --- |
| **Key rotation cadence** for HMAC, Ed25519, or KMS-backed receipt signers | [docs/key_management.md § Rotation procedure](docs/key_management.md#rotation-procedure) plus [docs/runbooks/key_rotation.md](docs/runbooks/key_rotation.md). Default: rotate on compromise, on personnel changes, or annually for asymmetric keys; rotate HMAC secrets at least quarterly. |
| **SIEM integration for the receipt stream** | [`provenex/export/`](provenex/export/) (sinks); [docs/streaming_export_ops.md](docs/streaming_export_ops.md) (backpressure + recovery + OCSF quirks); [`siem/splunk/`](siem/splunk/) and [`siem/sentinel/`](siem/sentinel/) for ready-to-import detection content. |
| **Detecting a stuck or replayed signer** | The `request_binding` block (schema 2.4.0) ties each receipt to its triggering query; a signer that re-emits an old binding is detectable by `receipt_id` uniqueness in the witness log. See [docs/threat_model.md § Replay of a receipt across queries](docs/threat_model.md). |
| **Witness-log divergence** | Two cluster nodes producing different witness checkpoints for the same `tree_root` is the divergence signal. [docs/runbooks/witness_log.md](docs/runbooks/witness_log.md) and [docs/runbooks/disaster_recovery.md](docs/runbooks/disaster_recovery.md) cover detection, root-cause walk-through, and the operational response. |
| **Multi-tenant key isolation** | [`provenex.SignerRegistry`](provenex/core/signer_registry.py): receipts signed under tenant A do not verify under tenant B's public key (tested in `tests/test_signer_registry.py`). |
| **Index drift detection** | [`provenex.IndexDriftDetector`](provenex/drift/) plus the `PROVENEX_DRIFT_WEBHOOK_URL` env var on the HTTP server: coalesces distinct UNVERIFIED fingerprints over a sliding window and POSTs to your webhook. |
| **KMS / HSM signing** | [docs/key_management.md](docs/key_management.md) plus the four adapters under [`provenex/kms/`](provenex/kms/): AWS KMS, GCP KMS, Azure Key Vault, PKCS#11. Each implements the same `ReceiptSigner` protocol the OSS signers do. |
