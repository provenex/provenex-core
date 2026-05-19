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
  [`provenex/index/merkle_sqlite_index.py`](../provenex/index/merkle_sqlite_index.py) -
  the three reference index implementations (SQLite, Postgres, Merkle).
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
