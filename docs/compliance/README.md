# Compliance mappings

This directory maps specific regulatory and standards clauses to the Provenex primitives that produce evidence for them. Each file is a clause-by-clause table: regulation text on the left, the receipt field or behaviour that produces the evidence on the right. No interpretation, no legal advice; just a pointer table a procurement reviewer can hand to compliance counsel.

| File | Framework | Scope |
| --- | --- | --- |
| [eu_ai_act_art12.md](eu_ai_act_art12.md) | EU AI Act (Regulation 2024/1689), Article 12 | Record-keeping requirements for high-risk AI systems |
| [dora.md](dora.md) | DORA (Regulation 2022/2554), Articles 17 to 19 | ICT-related incident management, classification, and reporting |
| [iso_42001.md](iso_42001.md) | ISO/IEC 42001:2023 | AI Management Systems, clauses 7.5 and 8.x (documented information and operational control) |
| [sr_11_7.md](sr_11_7.md) | Federal Reserve SR 11-7 / OCC 2011-12 | Model Risk Management for AI-as-models |

## What these mappings do and do not assert

These mappings describe **which Provenex artifacts can serve as evidence for which clauses**. They do not assert that running Provenex makes an organisation compliant with any framework. Compliance is a governance and operational property of the whole organisation; the receipts and the index are technical inputs.

In particular:

- A clause requiring "appropriate record-keeping" is satisfied by receipts only if retention, access control, and integrity verification are also in place. See [`docs/receipt_retention.md`](../receipt_retention.md) for the Terraform module that closes that gap.
- Receipts record what happened. They do not record whether the recorded decision was the *right* decision (a governance question; see [`docs/threat_model.md` § Trust model for policy decisions](../threat_model.md#trust-model-for-policy-decisions)).
- Clauses referring to model risk or model behaviour are satisfied only insofar as the agent's actions are policed by Provenex. Inference-quality and output-grounding claims are out of scope.

For the verification path an auditor uses against a single receipt, see [`docs/regulator_verification.md`](../regulator_verification.md).
