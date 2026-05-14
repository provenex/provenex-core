"""End-to-end example: policy-driven retrieval with the unified Provenex Policy.

This is the v0.4 showcase. It demonstrates BOTH halves of the policy
enforcement layer:

    * The verification gate — five-outcome check against the signed index
      (VERIFIED / STALE / UNAUTHORIZED / UNVERIFIED / TAMPERED).
    * The access-control gate — native YAML DSL evaluator with rules over
      chunk metadata (residency, classification, PII tags) and request
      context (caller, jurisdiction, purpose).

A chunk reaches the LLM only if BOTH gates allow it. The signed receipt
records the verdict from each gate on every chunk, so an auditor can
reason about them independently.

Run:
    PROVENEX_SIGNING_SECRET=demo-secret PYTHONPATH=. python3 examples/policy_driven_retrieval.py

Requires:
    pip install provenex-core[policy]   # adds PyYAML for the native DSL
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List

from provenex import (
    HmacSha256Signer,
    Policy,
    RequestContext,
    SQLiteProvenanceIndex,
    verify_chunks,
)


# Inline unified policy. In production you would author this in a file
# and load with ``Policy.from_yaml("hr_policy.yaml")``. Inline here so the
# example is self-contained.
HR_POLICY = """
version: 1
policy_id: hr-corpus-retrieval-v3

# The five-outcome verification gate.
verification:
  block_unauthorized: true
  block_tampered: true
  # STALE chunks are flagged on the receipt summary but reach the policy
  # gate; the policy decides whether stale data is acceptable per rule.
  block_stale: false

# The data-access policy. Three rules across the dimensions a real HR
# corpus actually cares about: jurisdiction, PII gating, freshness.
access_control:
  rules:
    - name: jurisdiction_eu_only
      when:
        request.jurisdiction: EU
      require:
        chunk.metadata.residency:
          in: [EU, EEA]
      on_violation: deny

    - name: pii_classification_gate
      when:
        chunk.metadata.contains_pii: true
      require:
        request.caller.role:
          in: [hr_admin, payroll]
      on_violation: deny

    - name: freshness_for_policy_corpus
      when:
        chunk.metadata.corpus: policy_documents
      require:
        chunk.ingested_at:
          not_older_than: 90d
      on_violation: deny

  defaults:
    unknown_metadata: deny           # fail closed
    policy_version_mismatch: deny
"""


@dataclass
class RetrievedChunk:
    """What a real retriever (Pinecone / Weaviate / LangChain / etc.) returns.

    The text is fingerprinted by Provenex; the metadata is surfaced to
    the policy evaluator under ``chunk.metadata.*``.
    """

    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def main() -> None:
    if "PROVENEX_SIGNING_SECRET" not in os.environ:
        os.environ["PROVENEX_SIGNING_SECRET"] = "demo-secret-only-for-example"

    # --- ONE-TIME SETUP ---
    index = SQLiteProvenanceIndex("policy_demo.db")
    policy = Policy.from_text(HR_POLICY)
    signer = HmacSha256Signer()

    # --- INGESTION ---
    # In production this happens once per document version; here we set
    # up three chunks that exercise all three rules.
    from provenex.core.fingerprinter import Fingerprinter

    fp = Fingerprinter()
    chunks = [
        RetrievedChunk(
            text="EU compensation policy: standard rates apply across all member states.",
            metadata={
                "residency": "EU",
                "corpus": "policy_documents",
                "contains_pii": False,
            },
        ),
        RetrievedChunk(
            text="US confidential roadmap: Q3 acquisition targets.",
            metadata={
                "residency": "US",
                "corpus": "strategy",
                "contains_pii": False,
            },
        ),
        RetrievedChunk(
            text="Employee record: name=Alice Smith, salary=$120k.",
            metadata={
                "residency": "EU",
                "corpus": "hr_records",
                "contains_pii": True,
            },
        ),
    ]
    for i, c in enumerate(chunks):
        cfp = fp.fingerprint_chunk(c.text)
        result = fp.fingerprint(c.text)
        index.add(
            fingerprint=cfp,
            document_id=f"doc_{i}",
            document_version=result.document_version,
            chunk_offset=0,
            chunk_length=len(c.text),
            authorized=True,
        )

    # --- RETRIEVAL TIME ---
    # Build the request context for the caller. In production this comes
    # from your IdP. In v0.4 we construct it explicitly.
    request = RequestContext(
        caller={"role": "hr_admin", "id": "u_4218"},
        jurisdiction="EU",
        purpose="customer_support",
        timestamp="2026-05-13T14:32:07Z",
    )

    # Pass chunk metadata so the evaluator can read chunk.metadata.* paths.
    # ``chunk_metadata_binding="at_ingest"`` declares that these tags were
    # bound to the chunk at ingest time and live in the signed index row.
    # The receipt will record that, so an auditor knows the trust class.
    result = verify_chunks(
        chunks=[c.text for c in chunks],
        index=index,
        signer=signer,
        policy=policy,
        request_context=request,
        chunk_metadata=[c.metadata for c in chunks],
        chunk_metadata_binding="at_ingest",
    )

    print(f"\n{'=' * 60}")
    print("Policy-driven retrieval result")
    print(f"{'=' * 60}")
    print(f"Kept (reach the LLM): {len(result.kept)} chunks")
    print(f"Blocked by policy:    {len(result.blocked)} chunks")
    print()

    receipt_dict = result.receipt.to_dict()
    print(f"Receipt id:        {receipt_dict['receipt_id']}")
    print(f"Schema version:    {receipt_dict['schema_version']}")
    print(f"Policy id:         {receipt_dict['policy']['access_control']['policy_id']}")
    print(f"Policy hash:       {receipt_dict['policy']['access_control']['policy_version_hash']}")
    print()
    print("Per-chunk decisions:")
    for d in receipt_dict["policy"]["access_control"]["decisions"]:
        verdict = d["decision"].upper()
        fired = ", ".join(d["rules_fired"]) or "(no rules fired)"
        binding = d["metadata_binding"]["chunk_metadata"]
        print(f"  [{verdict:5s}]  rules: {fired}")
        print(f"            metadata_binding={binding}")
        print()

    print(f"Full receipt JSON written to policy_demo_receipt.json")
    with open("policy_demo_receipt.json", "w", encoding="utf-8") as f:
        f.write(result.receipt.to_json())

    print()
    print("Audit the receipt independently:")
    print("  provenex audit policy_demo_receipt.json --show-policy")
    print()
    print("Or export as JSON-LD for regulator-side consumers:")
    print("  (call receipt.to_json_ld() in code; same signature verifies)")

    index.close()


if __name__ == "__main__":
    main()
