"""SQLite provenance index augmented with an RFC 6962 transparency log.

This index keeps every property of :class:`SQLiteProvenanceIndex` — the
HMAC row signatures, the five verification outcomes, the same canonical
payload — and adds an append-only Merkle log over those exact rows.

Why two layers
--------------
The HMAC row signatures detect tampering with any single row. The Merkle
log adds a stronger property: an attacker cannot insert or remove rows
without changing a publicly-observable tree head. Auditors recognize this
pattern from Certificate Transparency and Sigstore Rekor.

The Merkle leaf for a row is the same canonical payload that the HMAC
signs::

    leaf = fingerprint \\n document_id \\n document_version \\n ingested_at
           \\n chunk_offset \\n chunk_length

So a verified inclusion proof shows that an authentic row was committed to
the log at the proven position. The two layers compose: HMAC for per-row
integrity, Merkle for whole-log integrity.

The full log (in-memory ``MerkleTree`` plus a persistent ``merkle_leaves``
table) is rebuilt from disk on construction; appending is O(log N) thanks
to the subtree-hash cache in :class:`provenex.core.merkle.MerkleTree`.
"""

from __future__ import annotations

from typing import Optional

from ..core.merkle import MerkleTree
from .sqlite_index import SQLiteProvenanceIndex, _canonical_payload


_MERKLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS merkle_leaves (
    leaf_index INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    leaf_bytes BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_merkle_fingerprint
    ON merkle_leaves(fingerprint);
"""


def _hex(b: bytes) -> str:
    """Encode bytes as the ``sha256:<hex>`` form the rest of Provenex uses."""
    return "sha256:" + b.hex()


class MerkleSQLiteProvenanceIndex(SQLiteProvenanceIndex):
    """SQLite provenance index with a transparency log.

    Adds three operations beyond the base interface:

        * :meth:`tree_size` — number of leaves committed to the log
        * :meth:`tree_root` — current tree head as ``sha256:<hex>``
        * :meth:`inclusion_proof` — produce an RFC 6962 audit path for a
          fingerprint, suitable for offline verification with
          :func:`provenex.core.merkle.verify_inclusion_proof`
    """

    def __init__(
        self,
        db_path: str,
        signing_secret: Optional[bytes] = None,
    ) -> None:
        super().__init__(db_path, signing_secret=signing_secret)
        with self._lock:
            self._conn.executescript(_MERKLE_SCHEMA)
            self._conn.commit()

        self._tree = MerkleTree()
        # Maps fingerprint -> most recent leaf_index. A given fingerprint
        # can occur more than once if the same chunk text appears under a
        # new document_version; lookup-style API returns the freshest.
        self._leaf_index_by_fp: dict[str, int] = {}
        self._rebuild_tree_from_disk()

    # ------------------------------------------------------------- helpers

    def _rebuild_tree_from_disk(self) -> None:
        """Replay persisted leaves into the in-memory tree in index order."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT leaf_index, fingerprint, leaf_bytes "
                "FROM merkle_leaves ORDER BY leaf_index ASC"
            ).fetchall()
        for row in rows:
            self._tree.append(row["leaf_bytes"])
            self._leaf_index_by_fp[row["fingerprint"]] = row["leaf_index"]

    # ----------------------------------------------------------- write

    def add(
        self,
        fingerprint: str,
        document_id: str,
        document_version: str,
        chunk_offset: int,
        chunk_length: int,
        authorized: bool = True,
    ) -> None:
        # Re-entrant lock so parent's add() can acquire it again without
        # deadlock. We check whether the row already exists *before*
        # delegating, so we know after the parent call whether a brand
        # new row was actually written and therefore needs a log entry.
        with self._lock:
            existed = (
                self._conn.execute(
                    "SELECT 1 FROM fingerprints "
                    "WHERE fingerprint = ? AND document_id = ? "
                    "AND document_version = ? LIMIT 1",
                    (fingerprint, document_id, document_version),
                ).fetchone()
                is not None
            )

            super().add(
                fingerprint=fingerprint,
                document_id=document_id,
                document_version=document_version,
                chunk_offset=chunk_offset,
                chunk_length=chunk_length,
                authorized=authorized,
            )

            if existed:
                return

            # Read back the row to get the ingested_at that the parent set,
            # then build the canonical payload — the same bytes the HMAC
            # signed. That payload is the Merkle leaf.
            row = self._conn.execute(
                "SELECT fingerprint, document_id, document_version, "
                "       ingested_at, chunk_offset, chunk_length "
                "FROM fingerprints "
                "WHERE fingerprint = ? AND document_id = ? "
                "AND document_version = ?",
                (fingerprint, document_id, document_version),
            ).fetchone()
            leaf_bytes = _canonical_payload(
                fingerprint=row["fingerprint"],
                document_id=row["document_id"],
                document_version=row["document_version"],
                ingested_at=row["ingested_at"],
                chunk_offset=row["chunk_offset"],
                chunk_length=row["chunk_length"],
            )
            leaf_index = self._tree.size()
            self._conn.execute(
                "INSERT INTO merkle_leaves "
                "(leaf_index, fingerprint, leaf_bytes) VALUES (?, ?, ?)",
                (leaf_index, fingerprint, leaf_bytes),
            )
            self._conn.commit()
            self._tree.append(leaf_bytes)
            self._leaf_index_by_fp[fingerprint] = leaf_index

    # ----------------------------------------------------------- read

    def tree_size(self) -> int:
        """Number of leaves currently in the transparency log."""
        with self._lock:
            return self._tree.size()

    def tree_root(self) -> str:
        """Current tree head as ``sha256:<hex>``."""
        with self._lock:
            return _hex(self._tree.root())

    def inclusion_proof(self, fingerprint: str) -> tuple[bytes, int, list[str]]:
        """Audit path for a fingerprint's most recent leaf.

        Args:
            fingerprint: The fingerprint to prove inclusion of.

        Returns:
            A 3-tuple ``(leaf_bytes, leaf_index, proof)`` where ``proof``
            is the audit path as a list of ``sha256:<hex>`` strings.
            ``leaf_bytes`` is the canonical row payload the HMAC signed —
            the same bytes that were hashed into the Merkle leaf.

        Raises:
            KeyError: If the fingerprint has never been added.
        """
        with self._lock:
            leaf_index = self._leaf_index_by_fp.get(fingerprint)
            if leaf_index is None:
                raise KeyError(f"fingerprint not in log: {fingerprint!r}")
            row = self._conn.execute(
                "SELECT leaf_bytes FROM merkle_leaves WHERE leaf_index = ?",
                (leaf_index,),
            ).fetchone()
            proof_bytes = self._tree.inclusion_proof(leaf_index)
        return row["leaf_bytes"], leaf_index, [_hex(p) for p in proof_bytes]
