"""Minimal OSS witness / checkpoint log (v0.8.0).

Provenex's Merkle transparency log catches any insertion / removal of
rows by an attacker who DOES NOT hold the index secret. For an attacker
who DOES hold the secret (a malicious operator), the per-row HMAC and
the Merkle tree itself can be reforged consistently. The standard
counter is **witness gossip**: the operator periodically publishes a
signed tree head to an append-only store the operator does not
control, so a regulator who has seen the published heads can detect
any retroactive history rewrite by inconsistency with what they
already have.

This module ships the minimal local-side artefact: a hash-chained,
signed, append-only JSONL log of (tree_size, tree_root, issued_at)
records. Each record's signature covers the previous record's hash,
so any retroactive edit breaks the chain at the *next* signature
verification. The log is the producer-side input to the gossip
pattern: operators publish each line to an immutable external store
(an S3 bucket with versioning + WORM, a transparency-log-as-a-service,
a regulator's intake endpoint, a notarisation chain) which closes the
non-repudiation-against-operator property.

The OSS witnessing path is **decision and proof**, not gossip
infrastructure. Provenex emits the signed checkpoint; the operator
publishes it where they cannot retroactively edit it. Hosted gossip
to a Provenex-operated witness cluster is the commercial story.

Properties of the local log on its own (no external publication):

    * Detects local tampering: editing any past record breaks all
      subsequent signatures.
    * Detects local truncation if the verifier has previously seen
      checkpoint N: rolling back to N-1 leaves a checkpoint_index
      gap or a missing-record error.
    * Does **not** detect an operator who maintains TWO local logs
      (split-view): that requires external publication. The class
      docstring spells this trade-off out so the property a deployment
      buys is unambiguous.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from .receipt import ReceiptSigner, verify_receipt_signature


@contextlib.contextmanager
def _exclusive_file_lock(path: str) -> Iterator[None]:
    """Acquire an exclusive advisory file lock for the duration of the block.

    Uses a sidecar ``<path>.lock`` file so locking is independent of the
    main file's open mode. Platform-aware:

        * POSIX: ``fcntl.flock(LOCK_EX)`` (blocks until acquired).
        * Windows: ``msvcrt.locking(LK_LOCK, ...)`` (raises after a few
          seconds of waiting; the caller's retry policy decides).

    Advisory locking: cooperating processes that use the SAME lock-file
    path are serialised. A non-cooperating writer that opens the log
    directly is not blocked. The witness-log contract is that all writers
    go through this class.

    Caveat: ``fcntl.flock`` on NFS is unreliable without a working
    ``rpc.lockd`` daemon and can silently no-op. Operators running the
    log on NFS should either move the file to local disk, ensure NFSv4
    file delegation, or rely on a single-writer deployment (one cron
    job at a time).
    """
    lock_path = path + ".lock"
    # Create or open the lock file. O_CREAT plus 0o600 so a freshly-
    # created lock file is owner-only.
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl  # type: ignore[import-not-found]

            fcntl.flock(fd, fcntl.LOCK_EX)
        except ImportError:
            # Windows fallback.
            import msvcrt  # type: ignore[import-not-found]

            # LK_LOCK blocks (well, retries internally) until the byte
            # range becomes available. Locking 1 byte at offset 0 is
            # sufficient as an advisory sentinel.
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            try:
                import fcntl  # type: ignore[import-not-found]

                fcntl.flock(fd, fcntl.LOCK_UN)
            except ImportError:
                import msvcrt  # type: ignore[import-not-found]

                # Seek back to 0 before unlock; msvcrt.locking tracks
                # file position.
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                except OSError:
                    pass
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)


@dataclass(frozen=True)
class WitnessRecord:
    """One signed checkpoint of a Merkle index head.

    Attributes:
        checkpoint_index: Monotonic 0-based position in the log.
        tree_size: The Merkle tree size at the moment the checkpoint
            was issued (the same number a verifier would read from
            :meth:`MerkleSQLiteProvenanceIndex.tree_size`).
        tree_root: ``sha256:<hex>`` of the tree at that size.
        issued_at: ISO-8601 UTC timestamp of when the checkpoint was
            written. Drift between this and the operator's wall clock
            is on the operator; the gossip pattern detects rewrites
            either way because the signature covers it.
        previous_checkpoint_hash: ``sha256:<hex>`` over the canonical
            JSON of the previous record, or ``None`` for
            ``checkpoint_index == 0``. This is what makes the log a
            hash chain.
        signature: ``{"algorithm": "...", "value": "..."}`` over the
            canonical JSON of the record (signature field removed).
    """

    checkpoint_index: int
    tree_size: int
    tree_root: str
    issued_at: str
    previous_checkpoint_hash: Optional[str]
    signature: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "checkpoint_index": self.checkpoint_index,
            "tree_size": self.tree_size,
            "tree_root": self.tree_root,
            "issued_at": self.issued_at,
            "previous_checkpoint_hash": self.previous_checkpoint_hash,
        }
        if self.signature is not None:
            d["signature"] = dict(self.signature)
        return d

    def canonical_payload(self) -> bytes:
        """Canonical JSON the signature covers (signature block excluded)."""
        d = self.to_dict()
        d.pop("signature", None)
        return json.dumps(
            d,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def record_hash(self) -> str:
        """SHA-256 over the canonical JSON INCLUDING the signature.

        The next record's ``previous_checkpoint_hash`` is this value;
        chaining the signature in means an attacker who reforges an
        old record must also reforge every record after it.
        """
        d = self.to_dict()
        payload = json.dumps(
            d,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()


def _now_utc_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class WitnessLog:
    """Append-only signed checkpoint log over a Provenex Merkle index.

    Typical wiring: a periodic job (cron, scheduler, k8s CronJob) opens
    the index, reads the current tree head, calls :meth:`append`, and
    then publishes the new line to an external append-only store the
    operator cannot retroactively edit. The local file is the producer
    record; the external store is what closes the
    non-repudiation-against-operator property. Provenex does the
    crypto and chaining; you do the publication.

    Args:
        path: Filesystem path to the JSONL log. Created if missing;
            appended to otherwise. The class itself never deletes or
            rewrites records.
        signer: A :class:`ReceiptSigner` (HMAC or Ed25519). Ed25519 is
            the recommended choice for any deployment that hands the
            log to an external verifier, since the verifier needs only
            the public key.
    """

    def __init__(self, path: str, signer: ReceiptSigner) -> None:
        self._path = path
        self._signer = signer

    # ----------------------------------------------------------- write

    def append(self, tree_size: int, tree_root: str) -> WitnessRecord:
        """Issue a new signed checkpoint and append it to the log.

        Thread-safe and multi-process-safe via an advisory file lock
        on a sidecar ``<path>.lock`` file. Concurrent ``append`` calls
        from different threads OR different processes are serialised
        so the chain's ``previous_checkpoint_hash`` link stays intact
        and ``checkpoint_index`` stays monotonic. See
        :func:`_exclusive_file_lock` for the platform-specific details
        and the NFS caveat.

        Args:
            tree_size: Current Merkle tree size from the index.
            tree_root: Current tree-root string from the index
                (``sha256:<hex>``).

        Returns:
            The :class:`WitnessRecord` that was written. Its
            ``checkpoint_index`` is the position in the chain.
        """
        with _exclusive_file_lock(self._path):
            # latest() must be called INSIDE the lock so two concurrent
            # appends don't both observe the same predecessor and
            # produce duplicate checkpoint_index values.
            prev = self.latest()
            record = WitnessRecord(
                checkpoint_index=0 if prev is None else prev.checkpoint_index + 1,
                tree_size=tree_size,
                tree_root=tree_root,
                issued_at=_now_utc_iso(),
                previous_checkpoint_hash=(
                    prev.record_hash() if prev is not None else None
                ),
                signature=None,
            )
            sig_value = self._signer.sign(record.canonical_payload())
            signed = WitnessRecord(
                checkpoint_index=record.checkpoint_index,
                tree_size=record.tree_size,
                tree_root=record.tree_root,
                issued_at=record.issued_at,
                previous_checkpoint_hash=record.previous_checkpoint_hash,
                signature={
                    "algorithm": self._signer.algorithm,
                    "value": sig_value,
                },
            )
            line = json.dumps(
                signed.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            # O_APPEND open is the minimum guarantee against accidental
            # rewrites; operators chasing the strong property pair this
            # with WORM external publication. The flock above
            # additionally serialises concurrent writers.
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return signed

    # ----------------------------------------------------------- read

    def __iter__(self) -> Iterator[WitnessRecord]:
        return self.iter()

    def iter(self) -> Iterator[WitnessRecord]:
        if not os.path.exists(self._path):
            return
        with open(self._path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError as exc:
                    # Surface the file + line so a caller iterating a
                    # damaged log can pinpoint the bad record. The bare
                    # JSONDecodeError carries the column but not the
                    # source path.
                    raise ValueError(
                        f"malformed JSON in witness log {self._path} at "
                        f"line {line_no}: {exc}"
                    ) from exc
                try:
                    yield WitnessRecord(
                        checkpoint_index=int(d["checkpoint_index"]),
                        tree_size=int(d["tree_size"]),
                        tree_root=str(d["tree_root"]),
                        issued_at=str(d["issued_at"]),
                        previous_checkpoint_hash=d.get(
                            "previous_checkpoint_hash"
                        ),
                        signature=d.get("signature"),
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError(
                        f"malformed witness record in {self._path} at "
                        f"line {line_no}: {exc}"
                    ) from exc

    def latest(self) -> Optional[WitnessRecord]:
        last: Optional[WitnessRecord] = None
        for r in self.iter():
            last = r
        return last

    # --------------------------------------------------------- verify

    def verify(self) -> bool:
        """Verify the chain integrity of the local log.

        Returns True if every record's signature verifies AND every
        record's previous_checkpoint_hash matches the actual hash of
        the prior record AND checkpoint_index runs 0, 1, 2, ...

        Returns False if any of those fail. Verifying tree_root /
        tree_size against the actual Merkle index is the caller's
        responsibility (the log alone cannot recompute the tree).
        """
        prev: Optional[WitnessRecord] = None
        expected_index = 0
        for record in self.iter():
            if record.checkpoint_index != expected_index:
                return False
            if prev is None:
                if record.previous_checkpoint_hash is not None:
                    return False
            else:
                if record.previous_checkpoint_hash != prev.record_hash():
                    return False
            # Re-derive: verify_receipt_signature uses the same
            # canonical-JSON-minus-signature rule. Reuse it so the
            # canonicalisation discipline stays consistent across
            # receipt and witness records.
            if not verify_receipt_signature(record.to_dict(), self._signer):
                return False
            prev = record
            expected_index += 1
        return True

    def records(self) -> List[WitnessRecord]:
        return list(self.iter())
