"""Regenerate the cross-version receipt-portability fixtures.

The fixtures under ``tests/fixtures/receipt_*.json`` are committed bytes that
:mod:`tests.test_receipt_portability` re-verifies under every build. They
catch any silent drift in the canonical receipt signing payload — adding a
new key, renaming one, changing the canonicalisation rules — which would
otherwise pass tests in isolation while breaking the customer promise that
older receipts keep verifying.

Run this script ONLY when intentionally bumping :data:`SCHEMA_VERSION` or
the canonical signing payload, then commit the regenerated fixtures
alongside the schema-history entry in ``docs/receipt_format.md``::

    python scripts/regenerate_portability_fixtures.py

The generator patches the receipt / trajectory module's clock and ID
sources so the output is byte-stable across runs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

# Hardcoded test material. NOT for production use anywhere. The HMAC secret
# is committed in the test fixture and would be a key-leak in real code.
HMAC_SECRET = b"phase-0-portability-fixture-secret"
CALLER_SALT = b"phase-0-portability-caller-salt"

# Frozen values so two generator runs produce identical bytes.
FROZEN_ISSUED_AT = "2026-05-20T12:00:00.000Z"
FROZEN_TRAJECTORY_STARTED_AT = "2026-05-20T11:59:00.000Z"
FROZEN_MINIMAL_RECEIPT_ID = "prx_" + "0" * 32
FROZEN_FULL_RECEIPT_ID = "prx_" + "1" * 32
FROZEN_TRAJECTORY_ID = "trj_" + "f" * 32
FROZEN_PARENT_STEP_ID = "prx_" + "2" * 32

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def _build_minimal_receipt():
    """A bare 2.4.0 receipt: one VERIFIED whole-chunk source, HMAC-signed.

    Captures the canonical signing payload over the minimum required shape:
    receipt_id / schema_version / issued_at / issuer / output / sources /
    policy.verification / summary / signature. Nothing optional set.
    """
    from provenex.core.receipt import HmacSha256Signer, ReceiptBuilder
    from provenex.index.base import (
        ENTRY_KIND_WHOLE_CHUNK,
        IndexEntry,
        VerificationOutcome,
    )
    from provenex.policy.policy import VerificationPolicy

    entry = IndexEntry(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc_policy_v4",
        document_version="sha256:" + "b" * 64,
        ingested_at="2026-04-01T09:00:00.000Z",
        chunk_offset=0,
        chunk_length=512,
        authorized=True,
        superseded=False,
        signature="deadbeef",
        entry_kind=ENTRY_KIND_WHOLE_CHUNK,
    )

    builder = ReceiptBuilder(policy=VerificationPolicy(block_unverified=False))
    builder.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=entry,
        normalization_applied=["unicode_nfc", "whitespace_collapse"],
    )
    return builder.finalize(
        output_text="The answer is 42.",
        signer=HmacSha256Signer(secret=HMAC_SECRET),
    )


def _build_full_receipt():
    """A 2.4.0 receipt exercising every optional block introduced through 2.4.0.

    Carries: mixed sources (VERIFIED whole_chunk + UNVERIFIED window locator
    + UNVERIFIED no-entry), one action with redacted parameters, a built
    ``policy.access_control`` block, a built ``policy.tool_call_control``
    block, a salted ``caller_hash``, a ``request_binding`` (both halves),
    a trajectory block with ``session_id`` / ``step_kind`` / ``agent_id`` /
    ``parent_step_ids``, smart-quote-bearing strings in the request text
    and caller dict, and HMAC signature.
    """
    from provenex.core.receipt import (
        HmacSha256Signer,
        ReceiptBuilder,
        compute_caller_hash,
        compute_request_binding,
    )
    from provenex.core.trajectory import start_trajectory
    from provenex.index.base import (
        ENTRY_KIND_WHOLE_CHUNK,
        ENTRY_KIND_WINDOW,
        IndexEntry,
        VerificationOutcome,
    )
    from provenex.policy.evaluator import RequestContext
    from provenex.policy.policy import VerificationPolicy

    # Smart quote (U+201C / U+201D) in the request text and caller name —
    # ``ensure_ascii=False`` should preserve these as native UTF-8 in the
    # signed payload. If a later change flips ensure_ascii, the fixture
    # signature breaks immediately.
    request_text = "What is the company’s encryption rotation policy?"

    request = RequestContext(
        caller={
            "id": "u_42",
            "role": "hr_admin",
            "display_name": "André “Andy” O’Brien",
        },
        jurisdiction="EU",
        purpose="customer_support",
        timestamp="2026-05-20T11:30:00.000Z",
    )

    # Three sources, mixed outcomes.
    verified_entry = IndexEntry(
        fingerprint="sha256:" + "a" * 64,
        document_id="doc_policy_v4",
        document_version="sha256:" + "b" * 64,
        ingested_at="2026-04-01T09:00:00.000Z",
        chunk_offset=0,
        chunk_length=512,
        authorized=True,
        superseded=False,
        signature="deadbeef",
        entry_kind=ENTRY_KIND_WHOLE_CHUNK,
    )
    window_locator_entry = IndexEntry(
        fingerprint="sha256:" + "c" * 64,
        document_id="doc_policy_v4",
        document_version="sha256:" + "b" * 64,
        ingested_at="2026-04-01T09:00:00.000Z",
        chunk_offset=128,
        chunk_length=128,
        authorized=True,
        superseded=False,
        signature="cafef00d",
        entry_kind=ENTRY_KIND_WINDOW,
    )

    builder = ReceiptBuilder(
        policy=VerificationPolicy(
            block_unverified=False,
            block_unauthorized=True,
            block_tampered=True,
        )
    )
    builder.add_source(
        fingerprint="sha256:" + "a" * 64,
        outcome=VerificationOutcome.VERIFIED,
        entry=verified_entry,
        normalization_applied=["unicode_nfc", "whitespace_collapse"],
    )
    builder.add_source(
        fingerprint="sha256:" + "c" * 64,
        outcome=VerificationOutcome.UNVERIFIED,
        entry=window_locator_entry,
        normalization_applied=["unicode_nfc"],
        content_source="indexed_corpus",
    )
    builder.add_source(
        fingerprint="sha256:" + "e" * 64,
        outcome=VerificationOutcome.UNVERIFIED,
        entry=None,
        normalization_applied=["unicode_nfc"],
        content_source="live_tool_output",
    )

    # One tool-call action with redacted parameters; the hash anchors it.
    params = {"q": "weather “today” in Berlin", "num": 10}
    canonical = json.dumps(
        params, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    params_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
    builder.add_action(
        name="web_search",
        operation="query",
        parameters_hash=params_hash,
        parameters=None,  # operator-redacted
        target_system="google_custom_search",
        invocation_id="inv_8e2c",
    )

    # Hand-built access_control / tool_call_control payloads. Constructing
    # these by hand keeps the generator stdlib-only (no PyYAML extra
    # required). The hashes inside are stable strings — they don't need to
    # be derived from real evaluator inputs; the fixture's job is to
    # freeze the receipt-shape bytes, not to re-prove the evaluator.
    access_control = {
        "evaluator": "native_yaml",
        "policy_id": "phase0-fixture-v1",
        "policy_version_hash": "sha256:" + "d" * 64,
        "policy_in_transparency_log": False,
        "decisions": [
            {
                "chunk_fingerprint": "sha256:" + "a" * 64,
                "decision": "allow",
                "rules_fired": ["jurisdiction_eu_only"],
                "inputs_hash": "sha256:" + "1" * 64,
                "inputs": {
                    "chunk_metadata": {"residency": "EU"},
                    "request_context": {
                        "caller": request.caller,
                        "jurisdiction": request.jurisdiction,
                        "purpose": request.purpose,
                        "timestamp": request.timestamp,
                    },
                },
                "metadata_binding": {
                    "chunk_metadata": "at_ingest",
                    "request_context": "at_evaluate",
                },
            },
            {
                "chunk_fingerprint": "sha256:" + "c" * 64,
                "decision": "allow",
                "rules_fired": [],
                "inputs_hash": "sha256:" + "2" * 64,
                "inputs": None,
                "metadata_binding": {
                    "chunk_metadata": "at_evaluate",
                    "request_context": "at_evaluate",
                },
            },
            {
                "chunk_fingerprint": "sha256:" + "e" * 64,
                "decision": "deny",
                "rules_fired": ["unknown_metadata_deny"],
                "inputs_hash": "sha256:" + "3" * 64,
                "inputs": None,
                "metadata_binding": {
                    "chunk_metadata": "at_evaluate",
                    "request_context": "at_evaluate",
                },
            },
        ],
    }
    tool_call_control = {
        "evaluator": "native_yaml",
        "policy_id": "phase0-fixture-v1",
        "policy_version_hash": "sha256:" + "9" * 64,
        "policy_in_transparency_log": False,
        "decisions": [
            {
                "action_index": 0,
                "decision": "allow",
                "rules_fired": ["web_search_provider_allowlist"],
                "inputs_hash": "sha256:" + "4" * 64,
                "inputs": None,
                "metadata_binding": {
                    "tool_parameters": "at_evaluate",
                    "request_context": "at_evaluate",
                },
            }
        ],
    }

    traj = start_trajectory(
        agent_id="research_agent",
        step_kind="retrieval",
        session_id="session-2026-001",
    )
    # Pretend this is a non-root step so parent_step_ids is non-empty.
    traj = traj.next_step(
        parent_step_ids=[FROZEN_PARENT_STEP_ID],
        step_kind="retrieval",
        agent_id="research_agent",
        session_id="session-2026-001",
    )

    caller_hash = compute_caller_hash(request.caller, salt=CALLER_SALT)
    request_binding = compute_request_binding(
        request_text=request_text,
        request_context=request,
    )

    return builder.finalize(
        output_text="Per policy, keys rotate every 90 days.",
        signer=HmacSha256Signer(secret=HMAC_SECRET),
        trajectory=traj,
        access_control=access_control,
        tool_call_control=tool_call_control,
        caller_hash=caller_hash,
        request_binding=request_binding,
    )


def _write_fixture(name: str, receipt) -> None:
    path = FIXTURES_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    # ``ensure_ascii=False`` preserves smart quotes / non-ASCII as native
    # UTF-8 in the fixture file — same rule as the canonical signing
    # payload, so the file is human-readable and survives the
    # smart-quote test.
    path.write_text(
        json.dumps(receipt.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {path.relative_to(FIXTURES_DIR.parent.parent)}")


def main() -> None:
    receipt_ids = iter([FROZEN_MINIMAL_RECEIPT_ID, FROZEN_FULL_RECEIPT_ID])
    with patch(
        "provenex.core.receipt._now_utc_iso", return_value=FROZEN_ISSUED_AT
    ), patch(
        "provenex.core.receipt._new_receipt_id",
        side_effect=lambda: next(receipt_ids),
    ), patch(
        "provenex.core.trajectory._now_utc_iso",
        return_value=FROZEN_TRAJECTORY_STARTED_AT,
    ), patch(
        "provenex.core.trajectory._new_trajectory_id",
        return_value=FROZEN_TRAJECTORY_ID,
    ):
        minimal = _build_minimal_receipt()
        full = _build_full_receipt()

    _write_fixture("receipt_0_8_2_minimal.json", minimal)
    _write_fixture("receipt_0_8_2_full.json", full)


if __name__ == "__main__":
    main()
