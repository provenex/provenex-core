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

## Supported versions

Provenex is in active development. Security fixes are issued for:

| Version | Supported |
| --- | --- |
| 0.8.x (current minor) | Yes |
| 0.7.x | Critical fixes only |
| <= 0.6.x | No |

Receipts produced under any version remain verifiable: rotation does not invalidate prior receipts, and the signature primitives (HMAC-SHA256, Ed25519) are not version-gated. The "supported" column governs which version we will publish a patched release of, not which receipts remain auditable.

## Scope

In scope:

- The OSS core under [`provenex/`](provenex/): fingerprinter, normalizer, hasher, the `ProvenanceIndex` implementations, the policy evaluator, the receipt builder and signer, the witness log, the CLI, and the integrations under `provenex/integrations/` and `provenex/tool_call/integrations/`.
- The streaming-export sinks under [`provenex/export/`](provenex/export/).
- Documented security properties in [docs/threat_model.md](docs/threat_model.md), [docs/how_it_works.md](docs/how_it_works.md), [docs/receipt_format.md](docs/receipt_format.md), and [docs/secure_defaults.md](docs/secure_defaults.md).

Out of scope (please do not report):

- Threats Provenex does not protect against. See [docs/threat_model.md § Threats we explicitly do not protect against](docs/threat_model.md#threats-we-explicitly-do-not-protect-against): compromised signing keys, compromised LLMs, coordinated tampering at both ingest and verify time, and vector-DB-level integrity. These are operational concerns and are explicitly documented as such.
- Third-party dependencies (PyYAML, psycopg, cryptography, kafka-python, boto3, google-cloud-pubsub). Report those upstream; we will track and adopt fixes when available.
- Theoretical attacks against the underlying primitives (SHA-256 collision, Ed25519 forgery) absent a concrete exploit. Cryptographic primitive choices are documented in [docs/how_it_works.md](docs/how_it_works.md).

## Disclosure

The default disclosure window is **90 days** from the date of the initial assessment, extended by mutual agreement if a fix is in progress. We credit reporters in the release notes for the fix unless asked to do so anonymously.

## Hardening guidance

For operators deploying Provenex, the secure-defaults checklist is [docs/secure_defaults.md](docs/secure_defaults.md) and the threat model is [docs/threat_model.md](docs/threat_model.md). Run `provenex selftest` after every install to confirm the binary's pipeline matches the documented algorithm.
