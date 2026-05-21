# Architecture

This is the entry point into the technical documentation. It is not a separate
algorithm description; it points at where each part is specified in full so a
security reviewer can follow the surface in one sitting.

The core stays small on purpose. The fingerprinting, indexing, policy, and
receipt code is pure-stdlib Python so a reviewer reading the algorithm can also
read every load-bearing function. Optional extras (Postgres, Ed25519, framework
integrations, streaming sinks) are isolated behind interfaces and do not change
the canonical signing payload.

## What to read, in order

1. [`how_it_works.md`](how_it_works.md) - the algorithm end-to-end.
   - Normalization pipeline (Unicode NFC, zero-width stripping, whitespace
     collapse, optional case folding).
   - Rabin-Karp rolling hash (base `1_000_003`, modulo Mersenne prime
     `2^61 - 1`) for cheap windowing, strengthened with SHA-256 for
     cryptographic identity.
   - Sliding-window construction (`window_size=128`, `stride=64` defaults)
     and the `entry_kind` distinction (`whole_chunk` vs `window`) that
     gates promotion to `VERIFIED`.
   - The provenance index row format, HMAC-signed row payload, and the
     RFC 6962 Merkle transparency log layered over it
     (`SHA256(0x00 || leaf)`, `SHA256(0x01 || left || right)`).
   - The five verification outcomes and the `OUTCOME_PRECEDENCE` rule
     (`TAMPERED > UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED`).
   - Policy evaluation flow, canonical policy hash, and per-chunk decision
     record.
   - Receipt assembly, canonical-JSON signing payload, and the
     `request_binding` block.
   - Peppered fingerprint mode for low-entropy corpora.
   - The supersession operational contract.

2. [`threat_model.md`](threat_model.md) - what the system defends and what it
   does not.
   - Attacker model (caller, ingestor, retriever, vector-store operator,
     index-row attacker, key-holder).
   - Defended threats (chunk tampering, log insertion/removal with the
     witness log, replay across queries via `request_binding`,
     window-aligned splice).
   - Explicitly undefended threats (compromised signing key, compromised
     LLM, coordinated insider attack with operator access).
   - The witness / checkpoint log for split-view resistance against a
     key-holding operator.

3. [`receipt_format.md`](receipt_format.md) - the wire schema.
   - Field-by-field reference for receipts at schema version 2.4.0.
   - The schema-history table for every prior version.
   - Canonical JSON serialization rules used by the signature payload.

4. [`scaling.md`](scaling.md) - deployment shapes.
   - Recommended Postgres topology for multi-node verify pods.
   - Ingest-vs-verify separation, read-replica usage, PgBouncer notes.
   - 1M-chunk benchmark numbers and the policy-evaluation latency profile.

## By audience

**Policy and DSL:**

- [`policy.md`](policy.md) - the unified policy DSL (`verification`, `access_control`, `tool_call_control`); operators, expressions, worked examples, and the per-decision-purity rationale.

**Developer:**

- [`quickstart.md`](quickstart.md) - the five-minute getting-started across SQLite, Merkle, Ed25519, agentic flows, policy, tool-call admission, and memory / model inference.
- [`cookbook.md`](cookbook.md) - twenty short recipes for common tasks.
- [`vector_db_integration.md`](vector_db_integration.md) - the matrix across eleven vector backends (Pinecone, Weaviate, Milvus, Qdrant, Chroma, FAISS, pgvector, MongoDB Atlas, Elasticsearch, Vespa, OpenSearch).
- [`pinecone_integration.md`](pinecone_integration.md) - a Pinecone-specific deep dive.
- [`langchain_integration.md`](langchain_integration.md) - LangChain retriever and tool integration.
- [`mcp_integration.md`](mcp_integration.md) - MCP `tools/call` decorator deep dive plus a small worked example.
- [`streaming_export.md`](streaming_export.md) - the `ReceiptSink` Protocol and reference sinks.
- [`trajectory.md`](trajectory.md) - the agentic DAG model and the five step kinds.
- [`migration_guide.md`](migration_guide.md) - per-version upgrade notes back to 0.5.0.

**Operator (production):**

- [`secure_defaults.md`](secure_defaults.md) - every setting that affects security posture, current default, production recommendation.
- [`deployment_patterns.md`](deployment_patterns.md) - the three SDK distribution shapes (every-host, sidecar, centralized service) and when to use each.
- [`k8s_deployment.md`](k8s_deployment.md) - Helm chart walkthrough plus sizing guide for the `provenex-server` workload.
- [`key_management.md`](key_management.md) - HMAC vs Ed25519 vs KMS / HSM, rotation procedures, threat model.
- [`receipt_retention.md`](receipt_retention.md) - 7-year compliance retention pattern (S3 Object Lock + Glacier + Athena); maps to GCP and Azure.
- [`failure_modes.md`](failure_modes.md) - per-component fail-open/fail-closed behavior, blast-radius table, and pointers to every runbook.
- [`runbooks/key_rotation.md`](runbooks/key_rotation.md) - HMAC and Ed25519 rotation procedures.
- [`runbooks/witness_log.md`](runbooks/witness_log.md) - running the witness / checkpoint log in production.
- [`runbooks/postgres_operations.md`](runbooks/postgres_operations.md) - schema management, failover, replica lag, backup and restore, index rebuild.
- [`runbooks/disaster_recovery.md`](runbooks/disaster_recovery.md) - total Postgres loss, signing-key compromise, ingestion drift, multi-region patterns.
- [`runbooks/index_unavailability.md`](runbooks/index_unavailability.md) - block / degrade modes, the circuit breaker, `/healthz` vs `/readyz` semantics.
- [`runbooks/bad_policy_rollback.md`](runbooks/bad_policy_rollback.md) - detecting and rolling back a wrong policy push.
- [`runbooks/sizing_guide.md`](runbooks/sizing_guide.md) - reference deployment shapes and the SQLite-vs-Postgres-vs-shard decision tree.
- [`streaming_export_ops.md`](streaming_export_ops.md) - sink-failure semantics, backpressure, recovery, OCSF quirks.
- [`data_sovereignty.md`](data_sovereignty.md) - multi-region deployment patterns and GDPR Article 17 mechanics.

**Auditor and regulator:**

- [`regulator_verification.md`](regulator_verification.md) - offline verification walkthrough with a pure-stdlib reference verifier.

**Downstream detection:**

- [`anomaly_detection.md`](anomaly_detection.md) - admission vs detection architecture plus five worked detection patterns.
- [`ocsf_mapping.md`](ocsf_mapping.md) - OCSF v1.3 field-by-field mapping for SIEMs.

**Procurement:**

- [`procurement_faq.md`](procurement_faq.md) - license, supply chain, supported versions, vulnerability reporting, telemetry, cryptography provenance.
- [`supply_chain.md`](supply_chain.md) - per-release artifacts: PyPI Sigstore attestations (PEP 740), CycloneDX SBOM, and the local-verify recipe.

## Source map

The security-critical surface is small. A reviewer should read it directly.

- [`provenex/core/normalizer.py`](../provenex/core/normalizer.py) - text
  normalization pipeline.
- [`provenex/core/hasher.py`](../provenex/core/hasher.py) - Rabin-Karp rolling
  hash and SHA-256 strengthening.
- [`provenex/core/fingerprinter.py`](../provenex/core/fingerprinter.py) -
  top-level fingerprint API; `FingerprinterConfig.pepper` enables peppered
  mode.
- [`provenex/index/base.py`](../provenex/index/base.py) - the abstract
  `ProvenanceIndex` interface plus `VerificationOutcome` and
  `OUTCOME_PRECEDENCE`.
- [`provenex/index/sqlite_index.py`](../provenex/index/sqlite_index.py),
  [`provenex/index/postgres_index.py`](../provenex/index/postgres_index.py),
  [`provenex/index/merkle_sqlite_index.py`](../provenex/index/merkle_sqlite_index.py),
  [`provenex/index/merkle_postgres_index.py`](../provenex/index/merkle_postgres_index.py) -
  the four reference index implementations (SQLite, Postgres, Merkle-SQLite,
  Merkle-Postgres).
- [`provenex/index/bloom.py`](../provenex/index/bloom.py) - the
  `BloomFilterIndex` abstract base class for the negative-cache
  acceleration layer (commercial implementation; OSS ships the
  interface).
- [`provenex/core/merkle.py`](../provenex/core/merkle.py) - the RFC 6962
  Merkle primitive and stateless inclusion-proof verifier.
- [`provenex/policy/policy.py`](../provenex/policy/policy.py) - the unified
  `Policy` object with `verification`, `access_control`, and
  `tool_call_control` halves.
- [`provenex/policy/yaml_evaluator.py`](../provenex/policy/yaml_evaluator.py) -
  the reference native YAML evaluator (chunk decisions and tool-call
  admission).
- [`provenex/core/receipt.py`](../provenex/core/receipt.py) - the receipt
  model, the canonical signing payload, `compute_request_binding`,
  signature verification, and the `SCHEMA_VERSION` / `ISSUER` source of
  truth.
- [`provenex/core/ed25519.py`](../provenex/core/ed25519.py) - the Ed25519
  signer for cross-organisational receipts.
- [`provenex/core/witness.py`](../provenex/core/witness.py) - the
  hash-chained, signed checkpoint log over the Merkle tree head.
- [`provenex/cli/main.py`](../provenex/cli/main.py) - the CLI surface,
  including `provenex selftest` (in-process conformance) and
  `provenex index audit` (supersession lint).

## Conformance

`provenex selftest` is the one-command check that re-derives every property
this documentation set claims against the installed binary. Run it after every
install, and from CI for any deployment that produces receipts auditors will
hold onto.

```bash
provenex selftest
```

It exits 0 on every check passing and 1 on any failure. Use it as a release
gate on a signing key rotation or a corpus migration; it catches drift between
the documented algorithm and the running binary before a regulator sees the
receipts.
