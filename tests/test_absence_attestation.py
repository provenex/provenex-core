"""Deletion attestation: absence receipts, store manifests, tombstones.

Mirrors the ShareLess AI-Browser hygiene prototype end to end:
register an artifact plus short values embedded in it, verify them
PRESENT, purge the artifacts, then produce a native absence receipt
that verifies offline from the public key alone. Also covers the
whitespace caveat for short-secret scanning, unscanned-file honesty,
the purge tombstone lifecycle, and the schema-2.7.0 receipt-builder
changes (optional output, signed extensions).
"""

from __future__ import annotations

import pytest

from provenex.core.absence import (
    register_file,
    register_values,
    verify_absence,
    verify_absence_receipt,
)
from provenex.core.ed25519 import Ed25519Signer
from provenex.core.fingerprinter import Fingerprinter, FingerprinterConfig
from provenex.core.receipt import (
    HmacSha256Signer,
    ReceiptBuilder,
    verify_receipt_signature,
)
from provenex.core.stores import Store, StoreManifest
from provenex.index.base import VerificationOutcome
from provenex.index.sqlite_index import SQLiteProvenanceIndex
from provenex.policy.policy import VerificationPolicy

SECRET = b"absence-test-index-secret"


def _index(tmp_path):
    return SQLiteProvenanceIndex(str(tmp_path / "idx.db"), signing_secret=SECRET)


def _store(tmp_path, *globs):
    return Store(
        store_id="agent-logs",
        path_globs=tuple(globs or [str(tmp_path / "logs" / "*.log")]),
        store_class="runtime-log",
        owner="agent-runtime",
        links=("checkout-1",),
    )


# ----------------------------------------------------------------- round trip


def test_register_present_purge_absent_verifies_offline(tmp_path):
    idx = _index(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    artifact = logs / "checkout.log"
    artifact.write_text(
        "checkout done; card 4242 4242 4242 4242 charged; otp SECRET-42-XYZ\n"
    )
    fingerprints = register_values(
        idx, ["4242 4242 4242 4242", "SECRET-42-XYZ"], "checkout-1"
    )
    fingerprints.append(register_file(idx, artifact, "checkout-1"))
    signer = Ed25519Signer.generate()
    store = _store(tmp_path)

    present = verify_absence(idx, fingerprints, [store], signer)
    assert present.verdict == "PRESENT"
    assert all(r["verdict"] == "PRESENT" for r in present.results)
    assert present.files_scanned == 1

    artifact.unlink()  # the agent purges its artifacts

    absent = verify_absence(idx, fingerprints, [store], signer)
    assert absent.verdict == "ABSENT"
    assert all(r["verdict"] == "ABSENT" for r in absent.results)

    # Verifier-only: a fresh signer built from the public key alone,
    # no private key, no index, no database.
    verifier = Ed25519Signer.from_public_key_pem(signer.public_key_pem())
    assert verify_absence_receipt(absent.to_dict(), verifier)
    # And from the public key embedded in the receipt itself.
    assert verify_absence_receipt(absent.to_dict())
    # Tampering with the verdict breaks the signature.
    forged = absent.to_dict()
    forged["verdict"] = "PRESENT"
    assert not verify_absence_receipt(forged, verifier)


def test_unscanned_files_make_verdict_incomplete_and_are_named(tmp_path):
    idx = _index(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "binary.log").write_bytes(b"\xff\xfe\x00binary SECRET-42-XYZ")
    fingerprints = register_values(idx, ["SECRET-42-XYZ"], "checkout-1")
    receipt = verify_absence(idx, fingerprints, [_store(tmp_path)], Ed25519Signer.generate())
    assert receipt.verdict == "INCOMPLETE"
    assert receipt.files_scanned == 0
    assert receipt.unscanned_files[0]["store_id"] == "agent-logs"
    assert "binary.log" in receipt.unscanned_files[0]["path"]


def test_unregistered_fingerprint_fails_loud(tmp_path):
    idx = _index(tmp_path)
    with pytest.raises(ValueError, match="not registered"):
        verify_absence(
            idx, ["sha256:" + "0" * 64], [_store(tmp_path)], Ed25519Signer.generate()
        )


# ------------------------------------------------------------ whitespace case


def test_whitespace_bearing_secret_matches_after_normalization(tmp_path):
    """Registered '4242 4242' is found in a file holding '4242  4242'.

    Scanning works on normalized text, so whitespace runs are the same
    value. The caveat this documents: a secret broken up by more than
    whitespace (markup, punctuation) is a different normalized string
    and is NOT found; register the exact emitted form.
    """
    idx = _index(tmp_path)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "a.log").write_text("paid 4242  4242 today\n")
    fps = register_values(idx, ["4242 4242"], "checkout-1")
    receipt = verify_absence(idx, fps, [_store(tmp_path)], Ed25519Signer.generate())
    assert receipt.verdict == "PRESENT"

    (logs / "a.log").write_text("paid 4242<br>4242 today\n")
    receipt = verify_absence(idx, fps, [_store(tmp_path)], Ed25519Signer.generate())
    assert receipt.verdict == "ABSENT"


def test_short_secret_preset_and_supported_scan(tmp_path):
    config = FingerprinterConfig.short_secrets()
    assert config.stride == 1 and config.window_size < 32
    text = "prefix SECRET-42-XYZ suffix"
    fingerprints = {f.fingerprint for f in Fingerprinter(config).fingerprint(text).fingerprints}
    # Windows are locators sized by the config; at the value's own
    # length the window identity is the whole-chunk fingerprint.
    exact = Fingerprinter(FingerprinterConfig.short_secrets(window_size=13))
    assert Fingerprinter().fingerprint_chunk("SECRET-42-XYZ") in {
        f.fingerprint for f in exact.fingerprint(text).fingerprints
    }
    assert len(fingerprints) > len(text) // 8


# ----------------------------------------------------------------- tombstones


def test_purged_outcome_is_distinct_from_unauthorized(tmp_path):
    idx = _index(tmp_path)
    engine = Fingerprinter()
    fp = register_values(idx, ["SECRET-42-XYZ"], "checkout-1")[0]
    assert idx.verify(fp) == VerificationOutcome.VERIFIED

    idx.set_authorization("checkout-1", False)
    assert idx.verify(fp) == VerificationOutcome.UNAUTHORIZED

    idx.mark_purged(fp, receipt_ref="prx_abs_test")
    outcome = idx.verify(fp)
    assert outcome == VerificationOutcome.PURGED
    assert outcome != VerificationOutcome.UNAUTHORIZED
    assert idx.purged_info(fp)["receipt_ref"] == "prx_abs_test"

    # A purged source is counted in its own summary bucket, and the
    # policy layer always blocks a purged chunk presented again.
    builder = ReceiptBuilder()
    builder.add_source(fingerprint=fp, outcome=outcome)
    receipt = builder.finalize(output_text="x", signer=HmacSha256Signer(SECRET))
    assert receipt.to_dict()["summary"]["purged"] == 1
    assert VerificationPolicy().should_block(VerificationOutcome.PURGED)

    with pytest.raises(KeyError):
        idx.mark_purged("sha256:" + "0" * 64)


def test_receipt_summary_shape_unchanged_without_purged_sources():
    builder = ReceiptBuilder()
    builder.add_source(
        fingerprint="sha256:" + "a" * 64, outcome=VerificationOutcome.VERIFIED
    )
    receipt = builder.finalize(output_text="hello", signer=HmacSha256Signer(SECRET))
    d = receipt.to_dict()
    assert "purged" not in d["summary"]
    assert "extensions" not in d
    assert d["output"]["hash"].startswith("sha256:")


# ------------------------------------------------------- receipt builder (F5)


def test_finalize_without_output_omits_output_block_and_signs_extensions():
    signer = Ed25519Signer.generate()
    builder = ReceiptBuilder()
    receipt = builder.finalize(
        signer=signer, extensions={"hygiene": {"verdict": "ABSENT"}}
    )
    d = receipt.to_dict()
    assert "output" not in d
    assert d["extensions"] == {"hygiene": {"verdict": "ABSENT"}}
    verifier = Ed25519Signer.from_public_key_pem(signer.public_key_pem())
    assert verify_receipt_signature(d, verifier)
    d["extensions"]["hygiene"]["verdict"] = "PRESENT"
    assert not verify_receipt_signature(d, verifier)


# -------------------------------------------------------------- store manifest


def test_store_manifest_round_trip_and_completeness(tmp_path):
    manifest = StoreManifest(stores=(_store(tmp_path),))
    path = tmp_path / "manifest.json"
    manifest.save(path)
    loaded = StoreManifest.load(path)
    assert loaded == manifest
    assert loaded.stores[0].store_class == "runtime-log"
    assert loaded.stores[0].links == ("checkout-1",)
    receipt_index = _index(tmp_path)
    fps = register_values(receipt_index, ["SECRET-42-XYZ"], "checkout-1")
    receipt = verify_absence(
        receipt_index, fps, loaded, Ed25519Signer.generate()
    )
    # The store block in the receipt carries the manifest's enumeration.
    assert receipt.stores[0]["store_id"] == "agent-logs"
    assert receipt.stores[0]["links"] == ["checkout-1"]
    assert receipt.stores[0]["files_enumerated"] == 0
