"""Tests for the Ed25519 receipt signer.

Asymmetric receipts let an auditor verify without holding the signing
key. These tests cover keypair generation, sign/verify round-trips,
verifier-only mode (no private key in scope), PEM round-tripping, and
integration with :func:`verify_receipt_signature`.

Skipped automatically when the ``cryptography`` extra is not installed.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

# Skip the whole module if cryptography isn't available.
crypto = pytest.importorskip("cryptography")

from provenex.core.ed25519 import Ed25519Signer  # noqa: E402
from provenex.core.fingerprinter import Fingerprinter  # noqa: E402
from provenex.core.receipt import (  # noqa: E402
    HmacSha256Signer,
    ReceiptBuilder,
    verify_receipt_signature,
)
from provenex.index.merkle_sqlite_index import MerkleSQLiteProvenanceIndex  # noqa: E402
from provenex.policy.policy import VerificationPolicy  # noqa: E402


# --------------------------------------------------------------------- primitives


def test_generate_round_trip():
    signer = Ed25519Signer.generate()
    sig = signer.sign(b"some payload bytes")
    assert isinstance(sig, str)
    assert len(sig) == 128  # 64-byte signature, hex-encoded
    assert signer.verify(b"some payload bytes", sig) is True


def test_verify_rejects_wrong_payload():
    signer = Ed25519Signer.generate()
    sig = signer.sign(b"payload A")
    assert signer.verify(b"payload B", sig) is False


def test_verify_rejects_wrong_signature():
    signer = Ed25519Signer.generate()
    bad_sig = "00" * 64
    assert signer.verify(b"anything", bad_sig) is False


def test_verify_rejects_malformed_signature_hex():
    signer = Ed25519Signer.generate()
    # Not valid hex.
    assert signer.verify(b"anything", "zz") is False
    # Wrong length but valid hex.
    assert signer.verify(b"anything", "deadbeef") is False


# --------------------------------------------------------------------- PEM round-trip


def test_private_key_pem_round_trip():
    original = Ed25519Signer.generate()
    pem = original.private_key_pem()
    assert b"BEGIN PRIVATE KEY" in pem
    restored = Ed25519Signer.from_private_key_pem(pem)
    sig = original.sign(b"msg")
    assert restored.verify(b"msg", sig) is True
    # And restored can sign too; same private key, same signature for the
    # same input (Ed25519 is deterministic).
    assert restored.sign(b"msg") == sig


def test_password_protected_private_key_round_trip():
    original = Ed25519Signer.generate()
    pem = original.private_key_pem(password=b"correct horse battery staple")
    restored = Ed25519Signer.from_private_key_pem(
        pem, password=b"correct horse battery staple"
    )
    sig = original.sign(b"hello")
    assert restored.verify(b"hello", sig) is True


def test_public_key_pem_load_is_verify_only():
    """An auditor with only the public key can verify but not sign."""
    producer = Ed25519Signer.generate()
    public_pem = producer.public_key_pem()
    assert b"BEGIN PUBLIC KEY" in public_pem

    auditor = Ed25519Signer.from_public_key_pem(public_pem)
    sig = producer.sign(b"audited payload")
    assert auditor.verify(b"audited payload", sig) is True
    with pytest.raises(RuntimeError):
        auditor.sign(b"forging not allowed")


def test_wrong_public_key_fails_verification():
    producer = Ed25519Signer.generate()
    impostor = Ed25519Signer.generate()
    sig = producer.sign(b"payload")
    # Verify against the wrong public key.
    assert impostor.verify(b"payload", sig) is False


# --------------------------------------------------------------------- receipt integration


def _build_receipt_with(signer) -> dict:
    """Produce a real receipt and return its dict form."""
    workdir = Path(tempfile.mkdtemp())
    # The row-level HMAC secret is separate from the receipt signer (here Ed25519).
    # The index won't open without one; we just feed it a fixed test secret.
    index = MerkleSQLiteProvenanceIndex(
        str(workdir / "p.db"), signing_secret=b"row-level-hmac-secret-test"
    )
    fp = Fingerprinter()
    text = "Encryption policy. AES-256-GCM. " * 5
    r = fp.fingerprint(text)
    for f in r.fingerprints:
        index.add(
            fingerprint=f.fingerprint,
            document_id="doc",
            document_version=r.document_version,
            chunk_offset=f.offset,
            chunk_length=f.length,
            authorized=True,
        )
    target = r.fingerprints[0].fingerprint
    builder = ReceiptBuilder(policy=VerificationPolicy())
    builder.add_source(
        fingerprint=target,
        outcome=index.verify(target),
        entry=index.lookup(target),
    )
    receipt = builder.finalize(output_text="answer", signer=signer)
    index.close()
    return json.loads(receipt.to_json())


def test_verify_receipt_signature_round_trip_ed25519():
    producer = Ed25519Signer.generate()
    receipt_dict = _build_receipt_with(producer)
    # Auditor only sees the public key.
    auditor = Ed25519Signer.from_public_key_pem(producer.public_key_pem())
    assert verify_receipt_signature(receipt_dict, auditor) is True


def test_verify_receipt_signature_rejects_tampered_ed25519():
    producer = Ed25519Signer.generate()
    receipt_dict = _build_receipt_with(producer)
    # Tamper with the body.
    receipt_dict["sources"][0]["document_id"] = "FORGED"
    auditor = Ed25519Signer.from_public_key_pem(producer.public_key_pem())
    assert verify_receipt_signature(receipt_dict, auditor) is False


def test_verify_receipt_signature_rejects_wrong_algorithm():
    """A receipt signed with HMAC can't be verified by an Ed25519 verifier."""
    hmac_signer = HmacSha256Signer(secret=b"shared-secret-for-this-test")
    receipt_dict = _build_receipt_with(hmac_signer)
    auditor = Ed25519Signer.generate()
    assert verify_receipt_signature(receipt_dict, auditor) is False
