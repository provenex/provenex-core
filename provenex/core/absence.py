"""Deletion attestation: signed proof of absence from enrolled stores.

ShareLess AI-Browser checkouts in ``ai_visible`` mode release payment
details to an AI agent, whose runtime logs then contain plaintext card
values after the purchase. The agent purges those artifacts, and the
user needs verifiable proof of absence: "these registered values are
no longer in these enumerated stores", as a signed, offline-verifiable
receipt.

Until now that meant smuggling the verdict through a retrieval receipt
(an UNVERIFIED outcome with the real answer in a custom signed envelope
an auditor could misread). This module makes absence a first-class
receipt type, produced by :func:`verify_absence` and checkable with
:func:`verify_absence_receipt` from the signer's public key alone. No
private key, no index, no network: verifier-only mode is the
load-bearing property for third-party audit.

How presence is detected without content: the index stores one-way
fingerprints only, never content. Values are registered with
:func:`register_value` / :func:`register_file`, which record the
*normalized length* of each value beside its fingerprint. Scanning a
store file normalizes its text the same way, slides a window of exactly
that length across it at stride 1, fingerprints every window, and
intersects with the registered set. A registered value embedded
anywhere in a larger file (the runtime-log case) is found; its absence
across every enrolled store is what the receipt attests.

Normalization caveat (read before relying on short-secret scans):
fingerprints are taken over normalized text (whitespace runs collapsed,
case folded by default). Scanning therefore treats values that differ
only in whitespace runs or case as the same value, and a secret whose
raw bytes in a file differ from its registered form by more than
normalization (for example a value split across a line break with
intervening markup) will not be found. Register the exact value the
agent will emit; when in doubt, register each plausible emitted form.

Cost: one SHA-256 per character per distinct registered length, per
file. Fine for log-sized stores; not a full-text search engine.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..index.base import ProvenanceIndex
from .fingerprinter import Fingerprinter
from .receipt import ReceiptSigner
from .stores import Store, StoreManifest, expand_store

ABSENCE_RECEIPT_TYPE = "absence_attestation"
ABSENCE_SCHEMA_VERSION = "1.0"


def _now_utc_iso() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


@dataclass
class AbsenceReceipt:
    """A signed attestation that registered values are absent (or not)."""

    receipt_id: str
    issued_at: str
    verdict: str  # "ABSENT" | "PRESENT" | "INCOMPLETE"
    results: List[Dict[str, Any]]
    stores: List[Dict[str, Any]]
    files_scanned: int
    unscanned_files: List[Dict[str, Any]]
    signer_block: Dict[str, Any]
    signature_b64: str = ""

    def payload(self) -> Dict[str, Any]:
        """The signed payload (everything except the signature itself)."""
        return {
            "receipt_type": ABSENCE_RECEIPT_TYPE,
            "schema_version": ABSENCE_SCHEMA_VERSION,
            "receipt_id": self.receipt_id,
            "issued_at": self.issued_at,
            "verdict": self.verdict,
            "results": self.results,
            "stores": self.stores,
            "files_scanned": self.files_scanned,
            "unscanned_files": self.unscanned_files,
            "signer": self.signer_block,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.payload()
        d["signature"] = {
            "algorithm": self.signer_block.get("algorithm", ""),
            "value": self.signature_b64,
        }
        return d

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def _signer_block(signer: ReceiptSigner) -> Dict[str, Any]:
    block: Dict[str, Any] = {"algorithm": signer.algorithm}
    public_key_pem = getattr(signer, "public_key_pem", None)
    if callable(public_key_pem):
        try:
            block["public_key_pem"] = public_key_pem().decode("ascii")
        except Exception:
            pass
    return block


def register_value(
    index: ProvenanceIndex,
    value: str,
    document_id: str,
    *,
    fingerprinter: Optional[Fingerprinter] = None,
    document_version: Optional[str] = None,
    chunk_offset: int = 0,
) -> str:
    """Register one short value (a secret) for later absence attestation.

    Stores the value's fingerprint plus its *normalized length* in the
    index, never the value. Returns the fingerprint.
    """
    fp_engine = fingerprinter or Fingerprinter()
    fingerprint = fp_engine.fingerprint_chunk(value)
    normalized = fp_engine.normalize(value)
    version = document_version or fp_engine.fingerprint(value).document_version
    index.add(
        fingerprint,
        document_id,
        version,
        chunk_offset,
        len(normalized),
    )
    return fingerprint


def register_values(
    index: ProvenanceIndex,
    values: Iterable[str],
    document_id: str,
    *,
    fingerprinter: Optional[Fingerprinter] = None,
    document_version: Optional[str] = None,
) -> List[str]:
    """Register several short values under one document id.

    All values share one document_version: registering them under
    different versions would supersede (hide) the earlier ones, since
    an index document carries a single current version.
    """
    fp_engine = fingerprinter or Fingerprinter()
    values = list(values)
    version = document_version or fp_engine.fingerprint(
        "\x00".join(values)
    ).document_version
    return [
        register_value(
            index, v, document_id,
            fingerprinter=fp_engine, document_version=version, chunk_offset=i,
        )
        for i, v in enumerate(values)
    ]


def register_file(
    index: ProvenanceIndex,
    path: Path | str,
    document_id: str,
    *,
    fingerprinter: Optional[Fingerprinter] = None,
    document_version: Optional[str] = None,
) -> str:
    """Register a whole file as one fingerprint of its normalized text."""
    fp_engine = fingerprinter or Fingerprinter()
    text = Path(path).read_text(encoding="utf-8")
    return register_value(
        index, text, document_id,
        fingerprinter=fp_engine, document_version=document_version,
    )


def _scan_text(
    normalized_text: str,
    targets_by_length: Dict[int, Set[str]],
) -> Set[str]:
    """Fingerprints from ``targets_by_length`` found in normalized text."""
    found: Set[str] = set()
    for length, targets in targets_by_length.items():
        if length <= 0 or length > len(normalized_text):
            if length == len(normalized_text) and length > 0:
                pass
            else:
                continue
        for i in range(0, len(normalized_text) - length + 1):
            window = normalized_text[i : i + length]
            digest = hashlib.sha256(window.encode("utf-8")).digest()
            fp = "sha256:" + digest.hex()
            if fp in targets:
                found.add(fp)
    return found


def verify_absence(
    index: ProvenanceIndex,
    fingerprints: Sequence[str],
    stores: Sequence[Store] | StoreManifest,
    signer: ReceiptSigner,
    *,
    fingerprinter: Optional[Fingerprinter] = None,
    base_dir: Optional[Path] = None,
    length_overrides: Optional[Dict[str, int]] = None,
) -> AbsenceReceipt:
    """Scan enrolled stores and sign an absence attestation.

    Args:
        index: The provenance index the fingerprints were registered in.
            Used for metadata (document id, normalized length, purge
            state) only; scanning reads store files, never content from
            the index.
        fingerprints: Registered fingerprints to attest about.
        stores: Enrolled stores (a list of :class:`Store` or a
            :class:`StoreManifest`). Every file each store's globs match
            is scanned; files that cannot be read or decoded are named
            in the receipt and make the verdict INCOMPLETE, never ABSENT.
        signer: Receipt signer. Only its public identity lands in the
            receipt; verification needs the public key alone.
        length_overrides: Normalized length per fingerprint, for entries
            registered outside :func:`register_value` (whose recorded
            chunk length is a raw length, not a normalized one).

    Returns:
        An :class:`AbsenceReceipt`. ``verdict`` is ``"ABSENT"`` only
        when every fingerprint was absent from every scanned file and
        nothing was unscanned; ``"PRESENT"`` when any value was found;
        ``"INCOMPLETE"`` when some files could not be scanned.

    Raises:
        ValueError: A fingerprint is not registered, or its normalized
            length is unknown and no override was supplied. Attesting
            absence for a value whose length is unknown would be a
            guess, so this fails loud instead.
    """
    fp_engine = fingerprinter or Fingerprinter()
    store_list = list(stores.stores) if isinstance(stores, StoreManifest) else list(stores)
    overrides = length_overrides or {}

    targets_by_length: Dict[int, Set[str]] = {}
    entries: Dict[str, Any] = {}
    for fp in fingerprints:
        entry = index.lookup(fp)
        if entry is None:
            raise ValueError(f"fingerprint not registered: {fp}")
        length = overrides.get(fp, entry.chunk_length)
        if not length or length <= 0:
            raise ValueError(
                f"normalized length unknown for {fp}; register it with "
                "register_value/register_file or pass length_overrides"
            )
        entries[fp] = entry
        targets_by_length.setdefault(length, set()).add(fp)

    found_in: Dict[str, Set[str]] = {fp: set() for fp in fingerprints}
    unscanned: List[Dict[str, Any]] = []
    files_scanned = 0
    store_blocks: List[Dict[str, Any]] = []

    for store in store_list:
        files = expand_store(store, base_dir)
        scanned_here = 0
        for path in files:
            try:
                raw = path.read_bytes()
                text = raw.decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                unscanned.append(
                    {
                        "store_id": store.store_id,
                        "path": str(path),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            normalized = fp_engine.normalize(text)
            for fp in _scan_text(normalized, targets_by_length):
                found_in[fp].add(store.store_id)
            scanned_here += 1
        files_scanned += scanned_here
        block = store.to_dict()
        block["files_enumerated"] = len(files)
        block["files_scanned"] = scanned_here
        store_blocks.append(block)

    results: List[Dict[str, Any]] = []
    any_present = False
    for fp in fingerprints:
        entry = entries[fp]
        present_stores = sorted(found_in[fp])
        any_present = any_present or bool(present_stores)
        results.append(
            {
                "fingerprint": fp,
                "document_id": entry.document_id,
                "document_version": entry.document_version,
                "verdict": "PRESENT" if present_stores else "ABSENT",
                "present_in_stores": present_stores,
                "stores_checked": [s.store_id for s in store_list],
                "purged": index.purged_info(fp) is not None,
            }
        )

    if any_present:
        verdict = "PRESENT"
    elif unscanned:
        verdict = "INCOMPLETE"
    else:
        verdict = "ABSENT"

    receipt = AbsenceReceipt(
        receipt_id="prx_abs_" + uuid.uuid4().hex,
        issued_at=_now_utc_iso(),
        verdict=verdict,
        results=results,
        stores=store_blocks,
        files_scanned=files_scanned,
        unscanned_files=unscanned,
        signer_block=_signer_block(signer),
    )
    receipt.signature_b64 = signer.sign(_canonical(receipt.payload()))
    return receipt


def verify_absence_receipt(
    receipt: Dict[str, Any] | AbsenceReceipt,
    signer: Optional[ReceiptSigner] = None,
) -> bool:
    """Verify an absence receipt offline.

    Pass a verifier-only ``signer`` (public key, no private key), or
    omit it to verify against the public key embedded in the receipt's
    signer block (Ed25519 receipts carry it; the auditor still compares
    that key against a trusted copy out-of-band).
    """
    d = receipt.to_dict() if isinstance(receipt, AbsenceReceipt) else dict(receipt)
    signature = d.pop("signature", None)
    if not isinstance(signature, dict) or "value" not in signature:
        return False
    verifier = signer
    if verifier is None:
        pem = (d.get("signer") or {}).get("public_key_pem")
        if not pem:
            return False
        from .ed25519 import Ed25519Signer

        verifier = Ed25519Signer.from_public_key_pem(pem.encode("ascii"))
    try:
        return verifier.verify(_canonical(d), signature["value"])
    except Exception:
        return False
