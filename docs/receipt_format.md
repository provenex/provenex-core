# Receipt format

The provenance receipt is the public-facing artifact Provenex emits. It's what compliance teams hold onto, what auditors verify independently, and what downstream systems consume to decide whether to trust an AI output.

This document specifies the schema. The current schema version is **`1.0.0`**.

## Design properties

The schema is intentionally:

- **Self-describing.** `schema_version` is at the top. `issuer` identifies the software that produced the receipt.
- **Independently verifiable.** Everything needed to verify the receipt without contacting the issuer is in the receipt itself.
- **Stable.** `schema_version` exists so this schema can evolve without breaking older receipts. Breaking changes bump the major version.
- **Privacy-preserving.** No document content. No PII. Only hashes, IDs, metadata.

## Top-level fields

```json
{
  "receipt_id": "prx_<32 hex chars>",
  "schema_version": "1.0.0",
  "issued_at": "2026-05-08T14:32:07.441Z",
  "issuer": "provenex-core/0.1.0",
  "output": { ... },
  "sources": [ ... ],
  "policy": { ... },
  "summary": { ... },
  "signature": { ... }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `receipt_id` | string | Globally unique. Prefix `prx_` plus 32 hex characters (16 random bytes). |
| `schema_version` | string | Semver. `1.0.0` for this revision. |
| `issued_at` | string | ISO-8601 UTC with millisecond precision, `Z` suffix. |
| `issuer` | string | Software identifier, e.g. `provenex-core/0.1.0`. |
| `output` | object | See below. |
| `sources` | array | One entry per retrieved chunk. See below. |
| `policy` | object | The verification policy in effect. See below. |
| `summary` | object | Aggregate counts and overall status. See below. |
| `signature` | object | Optional. Present iff the receipt was signed. See below. |

## `output`

```json
{
  "output": {
    "hash": "sha256:<64 hex chars>",
    "hash_algorithm": "sha256"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `output.hash` | string | SHA-256 over the LLM output text, encoded as UTF-8. Prefixed with `sha256:`. |
| `output.hash_algorithm` | string | Always `sha256` in this schema version. |

The output text itself is **never** stored on the receipt. Only its hash.

## `sources[]`

One entry per chunk that was retrieved, in retrieval order. Both kept and policy-blocked chunks appear, so the receipt is a complete record.

```json
{
  "chunk_index": 0,
  "fingerprint": "sha256:<64 hex chars>",
  "document_id": "policy_v4",
  "document_version": "sha256:<64 hex chars>",
  "ingested_at": "2026-04-01T09:00:00.000Z",
  "chunk_offset": 0,
  "chunk_length": 936,
  "authorized": true,
  "verification_outcome": "VERIFIED",
  "normalization_applied": ["unicode_nfc", "strip_zero_width", "whitespace_collapse"]
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `chunk_index` | integer | 0-based position in the retrieval result. |
| `fingerprint` | string | SHA-256 of the normalized chunk text. `sha256:` prefix. |
| `document_id` | string \| null | Caller-chosen stable document identifier. `null` if outcome is `UNVERIFIED`. |
| `document_version` | string \| null | SHA-256 of the normalized full document. `null` if `UNVERIFIED`. |
| `ingested_at` | string \| null | ISO-8601 UTC when the fingerprint was written to the index. `null` if `UNVERIFIED`. |
| `chunk_offset` | integer \| null | Character offset of the chunk in the normalized document. `null` if `UNVERIFIED`. |
| `chunk_length` | integer \| null | Chunk length in characters. `null` if `UNVERIFIED`. |
| `authorized` | boolean \| null | Authorization state at retrieval time. `null` if `UNVERIFIED`. |
| `verification_outcome` | string | One of `VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`. |
| `normalization_applied` | array of string | Ordered list of normalization steps applied. Used to reproduce the pipeline byte-for-byte. |

### Verification outcomes

| Outcome | Meaning |
| --- | --- |
| `VERIFIED` | Fingerprint in index, signature OK, document authorized, version current. |
| `STALE` | Fingerprint in index, signature OK, document authorized, but version is superseded. |
| `UNAUTHORIZED` | Fingerprint in index, signature OK, but document is not currently authorized. |
| `UNVERIFIED` | Fingerprint not in index. The chunk was not ingested through Provenex. |
| `TAMPERED` | Fingerprint in index but the stored row's HMAC signature failed verification. |

## `policy`

The full `VerificationPolicy` configuration that was in effect when this receipt was issued.

```json
{
  "policy": {
    "block_stale": false,
    "block_unauthorized": true,
    "block_unverified": false,
    "block_tampered": true,
    "flag_stale": true,
    "flag_unauthorized": true,
    "flag_unverified": true,
    "flag_tampered": true
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `block_*` | boolean | If true, chunks with this outcome are removed before reaching the LLM. |
| `flag_*` | boolean | If true, chunks with this outcome are reflected in the summary even when not blocked. |

Recording the policy on the receipt means an auditor can reason about what happened *and* what would have happened under a stricter policy.

## `summary`

```json
{
  "summary": {
    "total_chunks": 3,
    "verified": 2,
    "stale": 0,
    "unauthorized": 0,
    "unverified": 1,
    "tampered": 0,
    "overall_status": "PARTIAL"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `total_chunks` | integer | Number of source records on this receipt. |
| `verified` / `stale` / `unauthorized` / `unverified` / `tampered` | integer | Counts per outcome. Sum equals `total_chunks`. |
| `overall_status` | string | One of `PASS`, `PARTIAL`, `FAIL`. See below. |

### `overall_status`

| Value | Meaning |
| --- | --- |
| `PASS` | Every chunk is `VERIFIED`. |
| `PARTIAL` | At least one non-`VERIFIED` outcome, but no chunks would be blocked under the policy in effect. |
| `FAIL` | At least one chunk would be blocked under the policy in effect. |

## `signature`

Optional. Present iff the receipt was signed.

```json
{
  "signature": {
    "algorithm": "hmac-sha256",
    "value": "<hex or base64>"
  }
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `signature.algorithm` | string | Identifier of the signing algorithm. `hmac-sha256` for the default signer. Pluggable. |
| `signature.value` | string | The signature itself, hex for HMAC. Other algorithms may use base64. |

### What is signed

The signature covers the canonical byte serialization of the receipt with the `signature` block omitted:

```python
payload = json.dumps(receipt_dict_without_signature, sort_keys=True, separators=(",", ":")).encode("utf-8")
signature = sign(payload)
```

Key properties:

- **`sort_keys=True`** so any JSON encoder produces the same bytes.
- **No whitespace** so encoder defaults don't change the payload.
- **Signature block omitted** from the payload so it can be added afterward.

This makes signatures portable across implementations: any verifier in any language that serializes JSON with these rules will recompute the same payload bytes.

## Verifying a receipt

```python
import json
from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature

with open("receipt.json") as f:
    receipt = json.load(f)

signer = HmacSha256Signer(secret=b"<the shared HMAC key>")
ok = verify_receipt_signature(receipt, signer)
assert ok, "receipt signature invalid"
```

For asymmetric verification, implement `ReceiptSigner` with Ed25519 (or your preferred scheme) and pass that signer instead. The receipt structure does not change; only the signer changes.

## Versioning

Breaking changes to this schema increment the major version of `schema_version`. Verifiers should reject receipts whose major `schema_version` they don't understand. Non-breaking additive changes (new optional fields) increment the minor version; verifiers may safely ignore unknown fields they don't recognize.
