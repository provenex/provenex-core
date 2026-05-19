#!/usr/bin/env python3
"""Generate the public audit bundle for the marketing site.

Produces ``dist/audit_bundle.zip``. Upload the resulting zip to the
website's static asset hosting; the site links to it as a downloadable
proof artifact.

The point of the bundle: the product's claim is "the receipt is the
artifact; anyone with the public key can verify it offline." This
script makes that claim runnable. A security reviewer downloads,
unzips, runs ``pip install provenex-core[ed25519]`` and a single
``provenex audit`` command per receipt. PASS on the two clean
receipts. FAIL on the tampered one. No database access, no signing
secret, only the public key.

Run once and check in the resulting zip if you want a stable artifact
across regens (the keypair, receipt ids, and signatures change every
run, so two consecutive runs produce different zip contents). The
script is deterministic in shape but not in cryptographic value.

Usage:
    PROVENEX_INDEX_SECRET=any-32-bytes \\
    PROVENEX_RECEIPT_SECRET=any-32-bytes \\
    python scripts/generate_audit_bundle.py

The two env vars are only used during bundle generation (they key
the index-row HMAC and any receipt-side HMAC fallback). The bundle
itself uses Ed25519 for receipt signatures, so the env-var secrets
are not needed to verify the bundle later.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from provenex import (
    Ed25519Signer,
    Fingerprinter,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    ToolCallContext,
    admission_check,
    verify_chunks,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "dist" / "audit_bundle"
ZIP_PATH = REPO_ROOT / "dist" / "audit_bundle.zip"


POLICY_YAML = """\
version: 1
policy_id: audit-bundle-demo-v1

# Five-outcome verification gate
verification:
  block_unauthorized: true
  block_tampered: true
  block_stale: false

# Data-access rules
access_control:
  rules:
    - name: us_jurisdiction_only
      when:
        request.jurisdiction: US
      require:
        chunk.metadata.residency:
          in: [US, US-East, US-West]
      on_violation: deny
  defaults:
    unknown_metadata: allow

# Tool-call admission rules
tool_call_control:
  rules:
    # fnmatch is glob, not regex - one rule per pattern.
    - name: web_search_provider_allowlist
      when: { tool.name: web_search }
      require:
        tool.target_system:
          in: [google_custom_search, bing_v7]
      on_violation: deny
    - name: no_api_key_in_query
      when: { tool.name: web_search }
      require:
        tool.parameters.q:
          not_matches_pattern: "*api_key=*"
      on_violation: deny
  defaults:
    unknown_metadata: allow
"""


CORPUS_CHUNK = (
    "Quarterly backup verification procedure. All production database "
    "backups must be encrypted with AES-256-GCM and keys managed by the "
    "central KMS. Restore drills run quarterly with verification that the "
    "decrypted backup matches the source-of-truth hash. Plaintext backups "
    "are not permitted under any circumstance. This chunk is ingested "
    "into the Provenex index for the audit-bundle demonstration."
)


README_TEMPLATE = """\
# Provenex audit bundle

This bundle contains real, signed receipts from a Provenex deployment.
The point of the bundle is to let you verify them yourself, offline,
without trust in our infrastructure or our claims.

## What's inside

- `receipt-1-retrieval-verified.json` - a clean retrieval receipt.
  One source chunk, `VERIFIED` outcome, US-jurisdiction policy allowed.
- `receipt-2-tool-call-allowed.json` - a clean tool-call admission
  receipt. One action (`web_search` against `google_custom_search`),
  allowed by the provider allowlist and the no-api-key rule.
- `receipt-3-retrieval-tampered.json` - a copy of receipt 1 with one
  field modified (a chunk fingerprint was rewritten). The signature
  no longer matches the payload; the audit will refuse it.
- `provenex_public_key.pem` - the Ed25519 public key for the
  deployment that signed these receipts. You verify with only this
  key; you do not need access to our infrastructure.
- `policy.yaml` - the unified policy that gated the decisions on the
  receipts above. The canonical hash of this file should match the
  `policy_version_hash` recorded inside each receipt.

## Verify

```bash
pip install "provenex-core[ed25519]"

provenex audit receipt-1-retrieval-verified.json \\
    --public-key provenex_public_key.pem

provenex audit receipt-2-tool-call-allowed.json \\
    --public-key provenex_public_key.pem

provenex audit receipt-3-retrieval-tampered.json \\
    --public-key provenex_public_key.pem
```

Expected output:

```
receipt-1: ... Overall: PASS
receipt-2: ... Overall: PASS
receipt-3: ... Signature ... INVALID ... Overall: FAIL
```

## What's being checked

`provenex audit` runs three independent checks per receipt:

1. The signature is valid against the public key over the canonical
   JSON of the receipt body. Editing any field invalidates the
   signature.
2. The receipt is internally consistent: source fingerprints, policy
   decisions, summary counts, request binding.
3. If the receipt was produced against a transparency-log-enabled
   index, the per-source Merkle inclusion proofs check against the
   tree root recorded on the receipt.

No database connection. No live signer. Only the public key and the
JSON files in this directory.

## What this proves

The product's claim is "the receipt is the artifact; anyone with the
public key can verify it offline." This bundle is that claim, made
runnable.

Try editing any field in `receipt-1-retrieval-verified.json` (a
fingerprint hex value, a verification outcome, the policy version
hash) and re-running `provenex audit` against it. The signature
verification will fail; the audit will refuse the receipt.

## More

- Source: https://github.com/provenex/provenex-core (MIT)
- Documentation: https://provenex.ai/
- Contact: skulk@provenex.ai

Bundle generated: {generated_at} UTC
Provenex version: provenex-core/{provenex_version}
Receipt schema:   {schema_version}
"""


def _build_signer_and_artifacts(work_dir: Path):
    """Produce the three receipts plus the public key.

    Uses a temporary SQLite index inside ``work_dir`` and a fresh
    Ed25519 keypair. Returns ``(receipt_dicts, public_pem)``.
    """
    db_path = work_dir / "ephemeral_index.db"
    index = SQLiteProvenanceIndex(str(db_path))

    fp = Fingerprinter()
    fingerprint_result = fp.fingerprint(CORPUS_CHUNK)
    chunk_fp = fp.fingerprint_chunk(CORPUS_CHUNK)
    index.add(
        fingerprint=chunk_fp,
        document_id="backup-procedure-v3",
        document_version=fingerprint_result.document_version,
        chunk_offset=0,
        chunk_length=len(CORPUS_CHUNK),
        authorized=True,
    )

    signer = Ed25519Signer.generate()
    policy = Policy.from_text(POLICY_YAML)

    request = RequestContext(
        caller={"id": "u_demo_auditor", "role": "compliance_auditor"},
        jurisdiction="US",
        purpose="compliance_review",
        timestamp="2026-05-19T12:00:00Z",
        session_id="audit-bundle-session-001",
    )

    # Receipt 1: clean retrieval, VERIFIED
    retrieval = verify_chunks(
        chunks=[CORPUS_CHUNK],
        index=index,
        signer=signer,
        policy=policy,
        request_context=request,
        request_text="what is the backup verification procedure?",
        chunk_metadata=[{"residency": "US-East", "contains_pii": False}],
    )

    # Receipt 2: clean tool-call admission, allowed
    tool_call = admission_check(
        tool=ToolCallContext(
            name="web_search",
            operation="query",
            parameters={"q": "AES-256-GCM key management best practices"},
            target_system="google_custom_search",
        ),
        request=request,
        policy=policy,
        signer=signer,
        request_text="research AES-256-GCM key management best practices",
    )

    # Receipt 3: tampered copy of receipt 1
    tampered = json.loads(json.dumps(retrieval.receipt.to_dict()))
    # Flip the first source's fingerprint. The signature was computed
    # over the original fingerprint; rewriting it invalidates the
    # signature without us touching the signature block itself, which
    # is the most realistic tampering scenario.
    original_fp = tampered["sources"][0]["fingerprint"]
    tampered["sources"][0]["fingerprint"] = (
        "sha256:" + "0" * 64
    )
    # Sanity check: we should have actually mutated the value.
    assert tampered["sources"][0]["fingerprint"] != original_fp

    receipt_dicts = {
        "receipt-1-retrieval-verified.json": retrieval.receipt.to_dict(),
        "receipt-2-tool-call-allowed.json": tool_call.receipt.to_dict(),
        "receipt-3-retrieval-tampered.json": tampered,
    }

    public_pem = signer.public_key_pem()

    index.close()
    db_path.unlink(missing_ok=True)

    return receipt_dicts, public_pem


def _read_provenex_version() -> str:
    text = (REPO_ROOT / "provenex" / "__init__.py").read_text()
    import re
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else "unknown"


def _read_schema_version() -> str:
    text = (REPO_ROOT / "provenex" / "core" / "receipt.py").read_text()
    import re
    m = re.search(r'^SCHEMA_VERSION\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m.group(1) if m else "unknown"


def main() -> int:
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)

    with tempfile.TemporaryDirectory(prefix="provenex_bundle_") as work_dir:
        work_path = Path(work_dir)
        receipt_dicts, public_pem = _build_signer_and_artifacts(work_path)

    for name, receipt_dict in receipt_dicts.items():
        (OUT_DIR / name).write_text(json.dumps(receipt_dict, indent=2))

    (OUT_DIR / "provenex_public_key.pem").write_bytes(public_pem)
    (OUT_DIR / "policy.yaml").write_text(POLICY_YAML)

    from datetime import datetime, timezone
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    (OUT_DIR / "README.md").write_text(
        README_TEMPLATE.format(
            generated_at=generated_at,
            provenex_version=_read_provenex_version(),
            schema_version=_read_schema_version(),
        )
    )

    if ZIP_PATH.exists():
        ZIP_PATH.unlink()
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(OUT_DIR.iterdir()):
            zf.write(f, arcname=f"audit_bundle/{f.name}")

    print(f"OK")
    print(f"  bundle:   {ZIP_PATH.relative_to(REPO_ROOT)}")
    print(f"  contents: {sorted(f.name for f in OUT_DIR.iterdir())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
