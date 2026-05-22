# Procurement and supply-chain FAQ

This document answers the questions a procurement team asks before approving an open-source dependency. It is for procurement, legal, supply-chain security, and platform reviewers. The threat model is in [threat_model.md](threat_model.md); this doc is the supply-chain and license side of the same review.

## License

`provenex-core` is licensed under the **MIT License**. Full text: [LICENSE](../LICENSE).

Optional extras pull in third-party dependencies under their own licenses; each dependency's license is published on PyPI and at the project's source repository. Common pulls: `PyYAML` (MIT), `psycopg` (LGPL with linking exception), `cryptography` (Apache 2.0 / BSD), `kafka-python` (Apache 2.0), `boto3` (Apache 2.0), `google-cloud-pubsub` (Apache 2.0), `langchain-core` and similar framework extras (MIT). Pull only the extras you need; the core stays MIT-only.

## Trademark and CLA posture

**Trademark.** "Provenex" is a trademark of Provenex Inc. Use of the name in derivative documentation, blog posts, marketing collateral, or comparison content is permitted under standard fair-use rules; do not represent a derivative or fork as an official Provenex product.

**Contributor License Agreement.** None. Contributions are accepted under the standard Developer Certificate of Origin (DCO) by signing off commits with `git commit -s`. The DCO does not assign copyright; the contributor retains ownership of their contribution and licenses it under MIT to the project. The contribution guidelines are in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Supply-chain hygiene

**Zero third-party dependencies in the core.** `provenex-core` with no extras pulls in nothing beyond the Python standard library. The `dependencies = []` line in [pyproject.toml](../pyproject.toml) is the declaration; the test suite runs against a fresh virtualenv with only `pytest` installed for CI verification.

**Optional extras are explicit and minimal.** Every third-party dependency lives behind a named extra. The current extras matrix:

| Extra | Pulls in | Purpose |
| --- | --- | --- |
| `[postgres]` | `psycopg[binary]>=3.1`, `psycopg-pool>=3.2` | Postgres provenance index for multi-node production |
| `[policy]` | `PyYAML>=6.0` | Native YAML policy DSL |
| `[ed25519]` | `cryptography>=42.0` | Asymmetric receipt signing (cross-organisation provenance) |
| `[langchain]` | `langchain-core>=0.3,<0.4` | LangChain integration |
| `[langgraph]` | `langgraph>=0.2,<0.3` | LangGraph integration |
| `[llamaindex]` | `llama-index-core>=0.10,<0.13` | LlamaIndex integration |
| `[crewai]` | `crewai>=0.55` | CrewAI session and tool wrappers |
| `[export-kafka]` | `kafka-python>=2.0` | KafkaSink streaming export |
| `[export-aws]` | `boto3>=1.34` | SQSSink and S3AppendSink streaming export |
| `[export-gcp]` | `google-cloud-pubsub>=2.20` | PubSubSink streaming export |

Pin the extras your environment needs and audit each at procurement time. Each is lazily imported; an environment that does not install a given extra never executes a line of its code.

**SBOM availability.** A CycloneDX-format SBOM is producible from the installed package via standard Python SBOM tooling (`cyclonedx-py`, `pip-audit --format=cyclonedx`). The OSS core's SBOM is the contents of [pyproject.toml](../pyproject.toml) since `dependencies = []`; extras add their own transitive trees. A pre-generated SBOM is not currently published as a release artifact.

## Supported Python versions

`requires-python = ">=3.10"` per [pyproject.toml](../pyproject.toml). The classifiers list 3.10, 3.11, and 3.12. CI runs against 3.12; cross-version sanity checks land before each release.

EOL policy: Provenex follows the Python core team's [official end-of-life schedule](https://devguide.python.org/versions/). A Python minor leaves Provenex's supported matrix when it reaches end-of-life upstream. We do not aggressively drop versions ahead of upstream EOL; we do not commit to supporting a Python minor after upstream drops security patches for it.

Type-checking and linting target 3.10 per `[tool.black]` / `[tool.ruff]` in `pyproject.toml`.

## Supported platforms

| Platform | Status |
| --- | --- |
| Linux x86_64 | Supported. CI runs here. |
| Linux arm64 | Supported. Used in production (AWS Graviton, Apple-silicon Linux containers). |
| macOS (Intel and Apple Silicon) | Supported. Common developer platform; CI runs locally. |
| Windows | Best-effort. The core is pure stdlib and should work; the `[postgres]` extra requires `psycopg[binary]`, which has Windows wheels but has had path-handling sharp edges historically. We do not run Windows CI. Customers running Provenex on Windows should hold their own coverage in their environment. |
| Containerised (Docker / OCI) | Supported. The core is a Python wheel; no native shared-object dependencies in the OSS core itself. The `[postgres]` and `[ed25519]` extras pull `psycopg[binary]` and `cryptography` respectively, both of which ship pre-built wheels for the standard manylinux platforms. |

## Vulnerability reporting

See [SECURITY.md](../SECURITY.md). Vulnerability reports go to `contact@provenex.ai`; do not file public GitHub issues for security bugs. Acknowledgement target: 2 business days. Initial assessment target: 5 business days.

## Backwards-compatibility commitments

Two distinct stability surfaces, each with its own commitment:

**Receipt schema stability.** The `schema_version` field on every receipt is governed by semantic versioning. Within one major version, minor bumps are additive: a verifier built against 2.0.0 validates a 2.4.0 receipt unchanged when it ignores unknown fields. Receipts at any minor in the 2.x line are verifiable. The current schema version is sourced from `SCHEMA_VERSION` in [provenex/core/receipt.py](../provenex/core/receipt.py); the full version-by-version history is in [docs/receipt_format.md § Schema history](receipt_format.md). Verifiers should reject receipts whose major they do not understand, per [receipt_format.md § Versioning](receipt_format.md#versioning).

**SDK API stability.** Within one minor (0.X), the public Python API is stable: arguments are not removed, kwargs are not renamed, return shapes are not changed. Deprecations land with a `DeprecationWarning` one minor version before removal. Past examples: `block_unverified` default-flip warning landed in 0.7.0 (will flip in a future major); `caller_hash_salt` opt-in landed in 0.6.5 with a deprecation warning on bare-SHA-256 use in 0.7.0.

**CLI surface stability.** The `provenex` subcommands and their flags are stable across minor versions. New flags are added; existing flags are not removed without a deprecation period. Output formats: human-readable output may evolve cosmetically (additional context lines, colour); `--json` output is stable per the same major-version rule as the schema.

The changelog ([CHANGELOG.md](../CHANGELOG.md)) records every customer-facing change with the version it landed in.

## Telemetry

**There is none.** Provenex does not phone home, does not ship usage metrics, does not call any third-party analytics service. The streaming-export sinks ([streaming_export.md](streaming_export.md)) ship receipts to a destination *you configure*; if you do not configure a sink, nothing leaves your process beyond the function return value. The CLI does not connect to the internet for any operation other than `pip install`.

## Cryptography provenance

The OSS core uses cryptographic primitives from the Python standard library. The `[ed25519]` extra is the one place that pulls in third-party crypto.

| Primitive | Where | Library |
| --- | --- | --- |
| SHA-256 (fingerprints, document versions, signing payloads, request binding, caller hash) | OSS core | `hashlib.sha256` (Python stdlib; CPython links its OpenSSL build) |
| HMAC-SHA256 (index row signing, receipt signing, peppered fingerprint mode, salted caller_hash) | OSS core | `hmac` (Python stdlib) |
| Constant-time comparison | OSS core | `hmac.compare_digest` (Python stdlib) |
| Secure random for receipt IDs and key generation | OSS core | `secrets` (Python stdlib) |
| Ed25519 sign / verify | `[ed25519]` extra | `cryptography>=42.0` (PyCA) which dispatches to the platform's OpenSSL build |

**Ed25519 implementation.** The `[ed25519]` extra wraps the PyCA `cryptography` package, which dispatches to the platform OpenSSL build. The OSS core does not ship its own Ed25519 implementation. FIPS posture depends on the linked OpenSSL build; a standard PyPI install of `cryptography` pulls a manylinux wheel that is not FIPS-validated.

**Algorithm choices.** SHA-256 for hashing (NIST FIPS 180-4); HMAC for symmetric signing (NIST FIPS 198-1); Ed25519 for asymmetric signing (RFC 8032). The Rabin-Karp rolling hash inside the fingerprinter is not cryptographic by design; the SHA-256 strengthening over each window is what gives cryptographic identity. See [how_it_works.md § Fingerprinting](how_it_works.md#1-fingerprinting).

## Read next

- [LICENSE](../LICENSE): MIT, full text.
- [SECURITY.md](../SECURITY.md): vulnerability reporting policy and supported-versions table.
- [CHANGELOG.md](../CHANGELOG.md): every customer-facing change with the version it landed in.
- [secure_defaults.md](secure_defaults.md): every setting that affects security posture, default value, recommended production value.
- [threat_model.md](threat_model.md): the attacker model, defended and undefended threats.
