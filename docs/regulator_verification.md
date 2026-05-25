# Regulator verification: how to verify a receipt offline

This document walks an external auditor through verifying a Provenex receipt with no access to Provenex infrastructure. No database connection, no live signer, no network calls. The signature math is pure arithmetic over the receipt JSON and the key material; the algorithm is SHA-256 plus either HMAC or Ed25519, and any standard crypto library reproduces it.

Audience: a regulator, an external compliance auditor, or an internal red team holding receipts produced by an organisation they do not control. The Provenex deployment that produced the receipts does not need to be reachable for this walkthrough to work.

## Two ways to verify

You can verify a Provenex receipt with either of the following:

* **`provenex-core`** (this package). Carries the full producer + auditor stack. Use this if you already have provenex-core installed, or if you want the bundled `provenex audit` CLI that runs all four checks below in one shot.
* **[`provenex-verifier`](https://github.com/aoptimystic/provenex-verifier-python)**, the standalone verifier library. Single dependency (`cryptography`), MIT-licensed, no network, no telemetry, no dependency on `provenex-core`. Use this if you are a third party who only needs to verify, not to issue; it is the smaller and more auditable installation footprint for regulator-side use.

Both implementations follow the same canonicalisation and signature rules and agree byte-for-byte. The walkthrough below uses `provenex-core`; a `provenex-verifier` example appears at the end of the CLI walkthrough.

## Inputs an auditor needs

| Input | When required |
| --- | --- |
| The receipt JSON file | Always. One file per receipt; the file is self-describing. |
| Ed25519 public key (PEM) | When the receipt's `signature.algorithm` is `ed25519`. The auditor verifies with the public key alone; the producer never shares the private key. |
| HMAC shared secret (bytes) | When `signature.algorithm` is `hmac-sha256`. Only meaningful for in-house auditors; the verifier can also forge under HMAC, so receipts that cross an organisational boundary should always be Ed25519-signed. |
| Optional: published tree head | When the receipt was produced against a Merkle-backed index. The receipt carries `transparency_log.tree_root` and `transparency_log.tree_size`; the auditor confirms these match a previously-published head if one is available. Inclusion proofs still verify against the head on the receipt without an external head; the external one defends against a key-holder operator publishing a forked tree. |
| Optional: original query and request_context | When the auditor wants to confirm `request_binding.request_hash` was produced by a specific query rather than any query. The receipt records hashes only; the auditor re-derives them and compares. |

The receipt JSON alone is enough to verify the signature. The optional inputs strengthen specific claims (request binding, transparency-log freshness) without weakening the base check.

## Four checks an auditor runs

A complete audit confirms four properties. Each one closes with the receipt fields it consumes.

**1. Signature integrity.** The signature covers the canonical JSON of the receipt body with the `signature` block omitted. Any modification (a fingerprint flip, a `verification_outcome` rewrite, a policy-decision swap) invalidates the signature. Canonicalisation rule: `json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. The signed payload is the canonical bytes; the signature is either an HMAC-SHA256 hex digest (32 bytes, 64 hex characters) or an Ed25519 signature (64 bytes, 128 hex characters). Receipt fields: `signature.algorithm`, `signature.value`, plus every other top-level field as input.

**2. Request binding.** If the receipt was produced under v0.8.0 or later with `request_text=` supplied, the top-level `request_binding` block ties the receipt cryptographically to one specific query and request_context. An auditor with the originals re-derives `query_hash = SHA-256(utf8(request_text))`, `request_context_hash = SHA-256(canonical_json(request_context_subset))`, and `request_hash = SHA-256(query_hash + "\n" + request_context_hash)`. If the originals reproduce the hashes, the receipt is bound to this exact query. The `request_binding` block is part of the canonical signing payload, so editing it invalidates the signature. Receipt fields: `request_binding.query_hash`, `request_binding.request_context_hash`, `request_binding.request_hash`. See [receipt_format.md § request_binding](receipt_format.md#top-level-request_binding-schema-240).

**3. Inclusion proofs (optional, present iff a Merkle-backed index was in use).** Every source carries `leaf_index` and `inclusion_proof`; the receipt as a whole carries `transparency_log.tree_root` and `transparency_log.tree_size`. The auditor reconstructs the canonical leaf bytes for each source (the same payload the index HMAC signs), hashes per RFC 6962 (`leaf_hash = SHA256(0x00 || leaf)`, `node_hash = SHA256(0x01 || left || right)`), walks the proof, and compares against the tree root. A verified proof shows that the row backing this source was committed to the log at the claimed position. Receipt fields: per-source `leaf_index` and `inclusion_proof`, plus `transparency_log.tree_size` and `transparency_log.tree_root`.

**4. Decision shape.** The auditor reads `sources[i].verification_outcome` and `policy.*.decisions[i].decision` per chunk or action. The five verification outcomes (`VERIFIED`, `STALE`, `UNAUTHORIZED`, `UNVERIFIED`, `TAMPERED`) are discrete cryptographic states with a fixed precedence (`TAMPERED > UNAUTHORIZED > STALE > UNVERIFIED > VERIFIED`); the policy decisions are `allow` or `deny`; the `rules_fired` array shows which rules participated. Verifying the signature confirms these were the values the producer signed off on. Receipt fields: `sources[].verification_outcome`, `policy.access_control.decisions[].decision`, `policy.tool_call_control.decisions[].decision`, `summary.overall_status`.

## CLI walkthrough

The `provenex audit` subcommand bundles all four checks into one command.

```bash
pip install "provenex-core[ed25519]"
provenex audit receipt.json --public-key audit.pub
```

Typical output on a clean receipt:

```
Receipt: prx_c486615764acfc1854920d8002c8a1a4
Schema:  2.4.0
Issued:  2026-05-18T21:17:34.169Z

  Signature ........... [OK] ed25519: valid
  Transparency log .... tree_size=25 tree_root=4080c581d6c87d6bfb832e6c8d9a330c...

  Source #0  [OK]  5 hashes against tree_size=25: valid
    fingerprint: sha256:5df8e5c2333e82c2a4f8a5f4ed6b8a9b4296f5b85072f3457261...
    document:    policy_v4 (VERIFIED)

  Overall: PASS
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--public-key audit.pub` | Verify Ed25519 signatures. Without it, HMAC is assumed and `PROVENEX_SIGNING_SECRET` is read from the environment. |
| `--unsigned` | Accept receipts whose signature cannot be verified. Useful for dev receipts; never appropriate for a production audit. |
| `--show-policy` | Print the unified policy block (evaluator, policy_id, policy_version_hash, per-decision verdicts, rules_fired). |
| `--trajectory <dir_or_glob>` | Validate a set of receipts as one trajectory DAG (shared `trajectory_id`, acyclic parent links, every signature verifies). Returns one overall PASS / FAIL. |
| `--json` | Emit machine-readable JSON instead of human-readable output. |

For a complete demo of an audit bundle (three receipts including a deliberately tampered one, the matching Ed25519 public key, and the policy file), see [scripts/generate_audit_bundle.py](../scripts/generate_audit_bundle.py). Running the script produces `dist/audit_bundle.zip`, which an auditor unpacks and runs through `provenex audit` to see PASS on two clean receipts and FAIL on the tampered one.

## Same audit with the standalone verifier

If you do not want to install `provenex-core`, install [`provenex-verifier`](https://github.com/aoptimystic/provenex-verifier-python) instead:

```bash
pip install provenex-verifier
provenex-verify receipt.json --public-key audit.pub
```

The standalone tool exits `0` on a valid signature, `1` on a tampered or wrongly-keyed receipt, and `2` on usage errors. It performs check 1 (signature integrity) only; checks 2 through 4 are layered on top by the caller using the same library's `canonicalize` and `verify_inclusion_proof` helpers. The library has no network surface area and is safe to run in an air-gapped environment.

## Re-deriving the signature payload by hand

A regulator who wants to confirm the algorithm rather than trust the CLI can re-derive the signed payload in a one-screen Python script. The canonical bytes the producer signed are:

```
payload = json.dumps(
    receipt_with_signature_block_removed,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")
```

For HMAC: `signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()`. For Ed25519: `signature = ed25519_private_key.sign(payload)`, hex-encoded. The verifier runs the same canonicalisation and compares.

Three rules make the payload portable across implementations and languages:

- **`sort_keys=True`** so any JSON encoder produces the same byte order.
- **No whitespace** so encoder defaults do not change the payload.
- **`ensure_ascii=False`** so non-ASCII content (smart quotes, accented characters, CJK in caller dicts) survives as native UTF-8 rather than `\uXXXX` escapes. A non-Python verifier that emits raw UTF-8 by default produces identical bytes.

The same canonicalisation governs `caller_hash`, `inputs_hash`, `value_hash`, `prompt_hash`, and `parameters_hash`. An auditor who can reproduce the receipt signature can reproduce all of them with the same rule.

## Verify in any language: 25-line pure-stdlib reference

Proof that no Provenex code is required to verify a receipt. The HMAC path uses Python stdlib only; the Ed25519 path needs one extra crypto library (any will do; `cryptography>=42.0` is shown for convenience).

```python
import hashlib
import hmac
import json


def verify_receipt(receipt_path: str, *,
                   hmac_secret: bytes | None = None,
                   ed25519_public_pem: bytes | None = None) -> bool:
    with open(receipt_path, "rb") as f:
        receipt = json.loads(f.read())

    sig = receipt.get("signature") or {}
    alg, value = sig.get("algorithm"), sig.get("value")

    payload_dict = {k: v for k, v in receipt.items() if k != "signature"}
    payload = json.dumps(
        payload_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")

    if alg == "hmac-sha256":
        if hmac_secret is None:
            raise SystemExit("hmac-sha256 receipt: pass hmac_secret=")
        expected = hmac.new(hmac_secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, value)

    if alg == "ed25519":
        if ed25519_public_pem is None:
            raise SystemExit("ed25519 receipt: pass ed25519_public_pem=")
        # The only non-stdlib import. Any Ed25519 library works; the
        # cryptography package is the most widely available.
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(ed25519_public_pem)
        try:
            pub.verify(bytes.fromhex(value), payload)
            return True
        except Exception:
            return False

    return False
```

Drop this into any environment with Python and `cryptography`, point it at a receipt and a public key, and the audit runs offline. The same logic transliterates to Go, Rust, Node, or Java in a screen of code each. There is no Provenex-specific verification protocol; the receipt is the artifact and the standard primitives are the verifier.

## Worked example

The fastest way to get a real Provenex receipt to audit is to run the
stdlib-only end-to-end demo. It builds a Merkle-backed index in a
tempdir, ingests a chunk, produces a signed receipt, and writes the
receipt to the current directory as `provenex_demo_receipt.json`.

```bash
pip install provenex-core

export PROVENEX_INDEX_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export PROVENEX_RECEIPT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

python -m provenex.cli.main selftest          # sanity check the install
python examples/standalone_demo.py            # produces provenex_demo_receipt.json in cwd

provenex audit provenex_demo_receipt.json
```

The receipt records one source chunk with outcome `VERIFIED`, an
inclusion proof against a small transparency log, and an HMAC
signature. Typical output on a matching secret:

```
Receipt: prx_<32 hex>
Schema:  2.5.0
Issued:  2026-05-21T...Z

  Signature ........... [OK] hmac-sha256: valid
  Transparency log .... tree_size=25 tree_root=...

  Source #0  [OK]  5 hashes against tree_size=25: valid
    fingerprint: sha256:...
    document:    policy_v4 (VERIFIED)

  Overall: PASS
```

The CLI reads the receipt, re-derives the canonical bytes, computes
the HMAC, compares in constant time, walks the inclusion proof, and
prints PASS or FAIL. Editing any field in the JSON (a fingerprint
hex character, the verification outcome, the tree root) and
re-running the audit produces FAIL.

For the Ed25519 path, run `scripts/generate_audit_bundle.py`. It
emits a zip containing two clean receipts, one tampered receipt, and
the matching Ed25519 public key. `provenex audit` against the clean
receipts returns PASS; against the tampered one it returns:

```
  Signature ........... [FAIL] ed25519: INVALID
  Overall: FAIL
```

That bundle is the artifact a regulator can download and run against
locally without any access to the producing organization's
infrastructure.

The auditor refused the receipt because the bytes the signature covers no longer match the bytes on disk.

## What this verification does and does not tell you

A successful audit confirms:

- The receipt has not been modified since it was signed.
- The producer, holding the corresponding key material, asserted every field on the receipt at the recorded `issued_at` timestamp.
- The recorded verification outcomes and policy decisions are exactly what the signer recorded.
- If a transparency-log block was present, each source was committed to the log at the recorded position relative to the recorded tree root.

A successful audit does **not** confirm:

- That the policy in effect at the time was the right policy. The receipt records the policy version hash; whether that policy was a sensible one is a governance question, not a cryptographic one. See [threat_model.md § Trust model for policy decisions](threat_model.md#trust-model-for-policy-decisions).
- That the LLM answer was a faithful summary of the chunks. Provenex records the chunks and an SHA-256 of the answer; "did the answer accurately reflect the chunks" is the job of an output-grounding or faithfulness layer.
- That the operator did not coordinate ingest, verify, signing, and policy authoring to produce an internally-consistent fake. Defence at that point is operational (separation of duties, witness gossip with an external party, code review). See [threat_model.md § Coordinated tampering at both ingest and verify time](threat_model.md#coordinated-tampering-at-both-ingest-and-verify-time).

The receipt's claim is narrow and load-bearing: under the recorded policy at the recorded time, the recorded decision was made about the recorded inputs, and the recorded artifact has not been altered since.

## Read next

- [receipt_format.md](receipt_format.md): every field on the receipt, with canonicalisation rules.
- [threat_model.md](threat_model.md): the attacker model, defended and undefended threats, and the security FAQ.
- [how_it_works.md](how_it_works.md): the algorithm walkthrough with source pointers.
- [scripts/generate_audit_bundle.py](../scripts/generate_audit_bundle.py): runnable bundle generator that produces three signed receipts, the Ed25519 public key, and the matching policy file.

Conformance: `provenex selftest` re-derives the request-binding determinism, signature roundtrip, fingerprint canonicalisation, and witness-log chain integrity against the installed binary. Exits 0 when every check passes. A regulator handed a receipt can also run `provenex selftest` against the binary on a fresh machine to confirm the verification pipeline matches the documented algorithm.
