# Secure defaults checklist

Every setting that affects security posture in Provenex OSS, its current default, and the recommended production value. The table is the contract; the prose underneath covers the non-trivial items. The intent is to make the footguns visible so an operator does not learn about them from an incident.

This is a reference checklist, not a runbook. The operational procedures (key rotation, witness-log cadence, sink durability tuning) live in [runbooks/](runbooks/).

## The checklist

| Setting | Current default | Production recommendation | Why it matters |
| --- | --- | --- | --- |
| `VerificationPolicy.block_unverified` | `None`, resolves to `False` with a one-time `DeprecationWarning` | `True` | Chunks not present in the Provenex index (`UNVERIFIED` outcome) pass through to the LLM by default. Operators wanting strict enforcement must set this explicitly; the default will flip in a future major release. See **block_unverified** below. |
| `VerificationPolicy.block_unauthorized` | `True` | `True` | Chunks from documents the operator marked `authorized=False` are blocked before reaching the LLM. The default is already strict. |
| `VerificationPolicy.block_tampered` | `True` | `True` | Chunks whose index-row HMAC signature failed are blocked. The default is already strict. |
| `VerificationPolicy.block_stale` | `False` | depends on use case | Chunks whose document version is superseded pass through by default. Block only when freshness is load-bearing for the use case; some workflows accept stale content explicitly. |
| Signer selection | HMAC-SHA256 (`HmacSha256Signer`) | Ed25519 (`Ed25519Signer`) whenever a receipt may cross an organisational boundary | HMAC verifiers can also sign and so can forge; Ed25519 separates signing (private key) from verification (public key). See **HMAC vs Ed25519** below. |
| Signing-key storage | Environment variable (`PROVENEX_RECEIPT_SECRET`, with a `PROVENEX_SIGNING_SECRET` legacy fallback that emits a `DeprecationWarning`) | Secrets manager (AWS Secrets Manager, HashiCorp Vault) for HMAC; HSM-backed storage for Ed25519 private key in regulated environments | Keys in env vars are convenient for development; production signing keys belong in a system that supports rotation, audit, and access control. See **signing-key storage** below. |
| `FingerprinterConfig.pepper` | `None` (plain SHA-256) | A 32-byte secret stored in the secrets manager for low-entropy corpora (HR template libraries, fixed policy boilerplate, enumerable forms) | Plain SHA-256 is one-way but not unguessable; an attacker with candidate plaintexts can confirm a fingerprint by recomputing the hash. Pepper turns the fingerprint into HMAC-SHA256(pepper, normalized) and blunts the confirmation channel. Rotating the pepper requires re-ingesting the corpus. See [how_it_works.md § Peppered fingerprint mode](how_it_works.md#peppered-fingerprint-mode-for-low-entropy-corpora). |
| `admission_check(..., redact_parameters=)` | `False` (verbatim parameters recorded) | `True` for tool calls whose parameters can contain user-supplied content (search queries, freeform fields) | The verbatim values land on the receipt at `actions[].parameters`. `parameters_hash` is always present and verifiable against the original values; redacting `parameters` keeps the audit anchor without persisting the verbatim content. |
| `admit_memory_write(..., redact_value=)` | `True` (verbatim value not recorded) | leave as `True` | Memory values often carry PII or customer data; the default redacts. `value_hash` is always recorded for offline verification. Only opt out (`redact_value=False`) for narrow debugging. |
| `admit_model_inference(..., redact_prompt=)` | `True` (verbatim prompt not recorded) | leave as `True` | Prompts can carry secrets and user data; the default redacts. `prompt_hash` is always recorded for offline verification. |
| Per-decision `inputs` field on `policy.access_control.decisions[]` | Recorded verbatim | Recorded verbatim, OR set to `null` for chunk metadata that includes regulated fields | `inputs_hash` is always present; the verbatim `inputs` can be redacted to `null` while keeping the hash. Redact when the chunk metadata itself is sensitive (residency tags that disclose internal segmentation, classification levels). |
| Receipt sink (`sink=`) | None (receipt returned via function value only) | A durable sink (Kafka with replication, SQS FIFO, S3 with versioning) wrapped in `RetryQueueSink` for transient broker hiccups | A receipt with no sink lives only in the calling process. Production deployments need at least one durable destination. See [streaming_export.md](streaming_export.md). |
| Witness-log publication | Local-only (the OSS `WitnessLog` writes to a local JSONL file) | Periodic publication of witness records to a store the operator does not retroactively control (S3 Object Lock, an external Git repo, a transparency log) | The witness log on its own gives tamper-detection on past records; closing split-view resistance against a key-holding operator requires external publication. See [threat_model.md § Witness / checkpoint log](threat_model.md#witness--checkpoint-log-v080). |
| Index backend | SQLite (`SQLiteProvenanceIndex`) | Postgres (`PostgresProvenanceIndex`) for multi-node production | SQLite is the development default and supports single-node deployments cleanly. Postgres is the production backend; identical receipt format, same `ProvenanceIndex` interface. See [scaling.md § Multi-node deployment shape](scaling.md#multi-node-deployment-shape-postgres-backend). |
| Transparency log | Off (`SQLiteProvenanceIndex` is HMAC-rows-only) | On (`MerkleSQLiteProvenanceIndex` or `MerklePostgresProvenanceIndex`) when an external auditor may hold receipts | Without the Merkle log, the per-row HMAC catches single-row tampering but not insertion / removal by a key-holder. The log closes that gap when paired with witness publication. |
| Caller-hash mode | Bare SHA-256 (`sha256:<hex>` prefix) | HMAC-SHA256 with a per-deployment salt (`hmac-sha256:<hex>` prefix) for multi-tenant deployments | Bare SHA-256 lets any auditor with the original caller dict re-derive `caller_hash`. In multi-tenant deployments where two customers' detectors should not cross-correlate users, salt via `caller_hash_salt=b"..."`. See [receipt_format.md § Top-level `caller_hash`](receipt_format.md#top-level-caller_hash-schema-230). |
| `policy.availability.on_index_error` | `"block"` (fail-closed) | `"block"` (fail-closed) for every deployment where a receipt that says `VERIFIED` must mean the index was consulted | When the provenance index is unreachable, `block` raises `IndexUnavailable` and the HTTP server returns 503. `degrade` issues a signed receipt with all-`UNVERIFIED` outcomes plus a signed top-level `index_status` block. Use `degrade` only for read-mostly workloads where the audit trail matters more than the gate. See [failure_modes.md](failure_modes.md) and [runbooks/index_unavailability.md](runbooks/index_unavailability.md). |
| `policy.availability.timeout_seconds` | `2.0` (async path) | `2.0` for most deployments; tune up if your Postgres p99 is consistently above 1s | Bounds the verify-path index call. Sync callers should set Postgres `statement_timeout` instead. A timeout counts as an index failure for the circuit breaker. |

## block_unverified: the default that will flip

Provenex 0.9.x defaults `block_unverified` to `False` and emits a one-time `DeprecationWarning` whenever a `VerificationPolicy` is constructed without `block_unverified` set explicitly. The warning text recommends `block_unverified=True` for strict enforcement and `block_unverified=False` to suppress the warning when the default behavior is intentional.

The intended trajectory is the default flips to `True` in a future major release. Operators who construct `VerificationPolicy()` without an explicit value today get unverified chunks reaching the LLM; after the flip they will get strict-by-default enforcement. The warning makes the choice visible so the flip is not a silent breaking change.

Recommended production posture: set `block_unverified=True` explicitly in code so the policy is unambiguous and the deprecation warning does not appear. Use `block_unverified=False` only when the policy genuinely permits unverified content (a live-tool-output retriever where the corpus claims no coverage, an audit-only deployment).

## HMAC vs Ed25519

Both signers implement the same `ReceiptSigner` interface; the receipt structure is identical. The difference is forgery resistance against the verifier.

| Property | HMAC-SHA256 | Ed25519 |
| --- | --- | --- |
| Key material | One shared secret | Private + public keypair |
| Signer + verifier | Anyone with the secret does both | Producer signs (private); auditor verifies (public) |
| Forgery resistance against the verifier | No | Yes |
| Dependency | None (stdlib) | `cryptography>=42.0` ([ed25519] extra) |
| Suitable for | In-house compliance | External auditors, regulator handoff |

Production posture: HMAC is acceptable when the producer and the verifier are inside the same organisation and the trust boundary contains the shared secret. The moment a receipt may be verified by anyone outside that boundary (regulator, external auditor, cross-org provenance), switch to Ed25519. The audit trail and signing payload do not change; only the signer class changes. Receipts produced with one signer cannot be verified with the other (the `signature.algorithm` field is set explicitly and the verifier checks it).

## Signing-key storage

The OSS core reads HMAC secrets from two environment variables in order: `PROVENEX_RECEIPT_SECRET` (role-specific, preferred) and `PROVENEX_SIGNING_SECRET` (legacy shared). Falling back to the legacy variable emits a one-time `DeprecationWarning`. Production deployments should not rely on environment variables for live signing material.

Recommended posture:

- **Development:** environment variables sourced from a developer-only secrets file, never committed.
- **Production HMAC:** the secret lives in your secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault). Application pods read it at startup or per-request via the secrets manager's SDK, never logged.
- **Production Ed25519:** the private key lives in an HSM or a KMS that exposes a sign-only interface. The OSS core's `Ed25519Signer` uses a private key in process memory; a KMS-backed signer is on the commercial roadmap. Until then, store the encrypted private key in your secrets manager (the `Ed25519Signer.private_key_pem(password=...)` helper produces an encrypted PEM) and decrypt at startup.

Rotation does not invalidate prior receipts: the public key (or the shared secret) is what an auditor needs to verify, and a rotated key joins the verification chain rather than replacing it. The rotation procedure is in [runbooks/key_rotation.md](runbooks/key_rotation.md).

## Peppered fingerprint mode

`FingerprinterConfig.pepper` is `None` by default; fingerprints are plain SHA-256 of the normalized chunk text. For corpora with low entropy where an attacker has plausible candidate plaintexts (HR templates, fixed boilerplate, enumerable forms), the attacker can confirm a fingerprint by recomputing the hash of each candidate. The hash is not reversible, but it is testable, and the corpus shape determines whether the confirmation channel matters in practice.

The pepper turns the fingerprint into `HMAC-SHA256(pepper, normalized_bytes)`. An attacker who guesses the plaintext also needs the pepper to confirm presence; two deployments with different peppers produce different fingerprints for identical content. The output prefix stays `sha256:` so downstream tooling reads the same.

Operational constraints:

- The pepper must be present at both ingest and verify; rotating it requires re-ingesting the corpus.
- The pepper belongs in the secrets manager alongside the signing keys.
- For high-entropy corpora (free-form documents, code, narrative text), the confirmation channel is not material; the default is fine.

For the regulatory analysis around peppered fingerprints and PII classification, see [threat_model.md § How does this interact with PII / GDPR / data residency?](threat_model.md#how-does-this-interact-with-pii--gdpr--data-residency).

## Read next

- [threat_model.md](threat_model.md): the attacker model that every default in the table above is calibrated against.
- [failure_modes.md](failure_modes.md): per-component fail-open / fail-closed behavior and the blast-radius table for every failure listed above.
- [runbooks/key_rotation.md](runbooks/key_rotation.md): the operational procedure for the signing-key storage row.
- [runbooks/witness_log.md](runbooks/witness_log.md): the operational procedure for the witness-log row.
- [runbooks/index_unavailability.md](runbooks/index_unavailability.md): operational procedure for the `availability` rows.
- [scaling.md](scaling.md): the Postgres / multi-node story that the index-backend row points at.

Conformance: `provenex selftest` exercises peppered-mode unlinkability, the five-outcome precedence, the receipt signature roundtrip, the request-binding determinism, and witness-log chain integrity against the installed binary. Run it after every change to the signer, the index, or the pepper.
