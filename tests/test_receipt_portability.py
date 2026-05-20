"""Cross-version receipt-portability regression tests.

Receipts issued under prior SDK versions must keep verifying bit-identically
under the current build — that is the cross-version portability promise
documented in ``docs/receipt_format.md`` and in the threat model ("Verifiable
offline by a regulator (no Provenex infrastructure dependency)").

If any change moves the canonical signing payload silently — a new
top-level key, a renamed field, a switch in canonicalisation rules —
:func:`verify_receipt_signature` below stops verifying the committed
fixtures and these tests fail. That forces a conscious bump of
:data:`provenex.core.receipt.SCHEMA_VERSION`, an entry in the
``docs/receipt_format.md`` schema-history table, and a regenerated fixture
via ``scripts/regenerate_portability_fixtures.py``.

Fixture bytes live under ``tests/fixtures/`` and are committed. The
generator script next to them is the source of truth for how they were
produced.
"""

from __future__ import annotations

import json
from pathlib import Path

from provenex.core.receipt import HmacSha256Signer, verify_receipt_signature


# Must match scripts/regenerate_portability_fixtures.py.
HMAC_SECRET = b"phase-0-portability-fixture-secret"
CALLER_SALT = b"phase-0-portability-caller-salt"

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    with open(FIXTURES_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------- #
# Minimal fixture                                                             #
# --------------------------------------------------------------------------- #


def test_minimal_fixture_verifies_under_current_build():
    receipt = _load("receipt_0_8_2_minimal.json")
    signer = HmacSha256Signer(secret=HMAC_SECRET)
    assert verify_receipt_signature(receipt, signer), (
        "Minimal 0.8.2 receipt fixture failed to verify. The canonical "
        "signing payload moved without a conscious SCHEMA_VERSION bump. "
        "Audit the change and, if intentional, run "
        "scripts/regenerate_portability_fixtures.py + update "
        "docs/receipt_format.md schema-history."
    )


def test_minimal_fixture_advertises_2_4_0_schema():
    receipt = _load("receipt_0_8_2_minimal.json")
    assert receipt["schema_version"] == "2.4.0"
    assert receipt["issuer"].startswith("provenex-core/0.8.2")


def test_minimal_fixture_signature_is_hmac_sha256():
    receipt = _load("receipt_0_8_2_minimal.json")
    assert receipt["signature"]["algorithm"] == "hmac-sha256"
    assert len(receipt["signature"]["value"]) == 64  # hex


# --------------------------------------------------------------------------- #
# Full fixture — exercises every optional 2.x block                           #
# --------------------------------------------------------------------------- #


def test_full_fixture_verifies_under_current_build():
    receipt = _load("receipt_0_8_2_full.json")
    signer = HmacSha256Signer(secret=HMAC_SECRET)
    assert verify_receipt_signature(receipt, signer), (
        "Full 0.8.2 receipt fixture failed to verify. The canonical signing "
        "payload over one of the optional 2.x blocks (access_control / "
        "tool_call_control / actions / trajectory / caller_hash / "
        "request_binding / entry_kind) moved without a conscious "
        "SCHEMA_VERSION bump. See the regen script next to the fixtures."
    )


def test_full_fixture_carries_every_2_4_0_block():
    """If a future change removes one of these blocks from the wire shape
    it would silently break 2.4.0 receipts in the wild. This test fails
    loudly so the change has to be conscious.
    """
    receipt = _load("receipt_0_8_2_full.json")
    assert "caller_hash" in receipt
    assert "request_binding" in receipt
    assert "actions" in receipt
    assert "trajectory" in receipt
    assert "access_control" in receipt["policy"]
    assert "tool_call_control" in receipt["policy"]
    assert any(
        s.get("entry_kind") == "whole_chunk" for s in receipt["sources"]
    )
    assert any(s.get("entry_kind") == "window" for s in receipt["sources"])


def test_full_fixture_request_binding_recomputable():
    """The request_binding fields are derived hashes; an auditor with the
    original query + request_context can re-derive them. This test
    re-derives them from the inputs recorded under
    ``policy.access_control.decisions[0].inputs.request_context`` plus a
    known query string, confirming the binding is honestly anchored to
    the recorded inputs.
    """
    import hashlib

    receipt = _load("receipt_0_8_2_full.json")
    rb = receipt["request_binding"]

    # The generator hashed this exact query text.
    query = "What is the company’s encryption rotation policy?"
    expected_query_hash = (
        "sha256:" + hashlib.sha256(query.encode("utf-8")).hexdigest()
    )
    assert rb["query_hash"] == expected_query_hash

    # The recorded request_context inputs must round-trip to the same
    # canonical hash recorded in request_binding.
    ctx = receipt["policy"]["access_control"]["decisions"][0]["inputs"][
        "request_context"
    ]
    payload = json.dumps(
        ctx, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    expected_ctx_hash = (
        "sha256:" + hashlib.sha256(payload).hexdigest()
    )
    assert rb["request_context_hash"] == expected_ctx_hash


def test_full_fixture_caller_hash_is_salted():
    """The full fixture uses the HMAC-keyed caller_hash mode. The prefix
    is the algorithm tag; a downstream consumer dispatches on it the
    same way it does for signature.algorithm.
    """
    receipt = _load("receipt_0_8_2_full.json")
    assert receipt["caller_hash"].startswith("hmac-sha256:")


def test_full_fixture_smart_quotes_survive_canonicalisation():
    """``ensure_ascii=False`` is part of the canonical signing payload
    rule. If a future change reverts to ``ensure_ascii=True`` the smart
    quotes in the caller dict get re-encoded to ``\\uXXXX`` escapes and
    the fixture signature breaks. This test makes the rule explicit so
    a reviewer sees the constraint.
    """
    receipt = _load("receipt_0_8_2_full.json")
    caller = receipt["policy"]["access_control"]["decisions"][0]["inputs"][
        "request_context"
    ]["caller"]
    # U+201C / U+201D (curly double quotes) and U+2019 (curly apostrophe).
    assert "“" in caller["display_name"]
    assert "”" in caller["display_name"]
    assert "’" in caller["display_name"]


def test_full_fixture_tampering_breaks_signature():
    """A signature that survives any local mutation isn't actually
    covering that field. This catches the regression where a new field is
    added at the top of the receipt but accidentally excluded from the
    canonical payload (would verify but be unbound).
    """
    receipt = _load("receipt_0_8_2_full.json")
    signer = HmacSha256Signer(secret=HMAC_SECRET)
    assert verify_receipt_signature(receipt, signer)

    # Flip one byte in the request_binding (2.4.0 addition) - the
    # signature MUST reject.
    tampered = json.loads(json.dumps(receipt))
    tampered["request_binding"]["query_hash"] = (
        "sha256:" + "0" * 64
    )
    assert not verify_receipt_signature(tampered, signer)

    # Flip one byte in a decision row inside access_control.
    tampered = json.loads(json.dumps(receipt))
    tampered["policy"]["access_control"]["decisions"][0]["decision"] = "deny"
    assert not verify_receipt_signature(tampered, signer)

    # Flip the entry_kind on a source (2.4.0 addition).
    tampered = json.loads(json.dumps(receipt))
    tampered["sources"][0]["entry_kind"] = "window"
    assert not verify_receipt_signature(tampered, signer)

    # Flip a tool-call decision.
    tampered = json.loads(json.dumps(receipt))
    tampered["policy"]["tool_call_control"]["decisions"][0]["decision"] = (
        "deny"
    )
    assert not verify_receipt_signature(tampered, signer)
