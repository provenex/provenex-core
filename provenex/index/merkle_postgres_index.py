"""Postgres provenance index with an RFC 6962 transparency log.

The Postgres analog of :class:`MerkleSQLiteProvenanceIndex`. Keeps every
property of :class:`PostgresProvenanceIndex` — HMAC row signatures, the
five verification outcomes, identical canonical payload — and adds an
append-only Merkle log over those exact rows.

Multi-writer caveat (open source)
---------------------------------
``leaf_index`` assignment is serialized with ``pg_advisory_xact_lock`` so
multiple writers do not race on the tail of the log. That keeps the log
*correct* under concurrent ingest, but the in-memory ``MerkleTree`` that
each process holds reflects only leaves *that process* has appended (plus
the snapshot it loaded at construction). For the open-source build the
**recommended deployment is one ingester pod and many verify pods**, with
verify pods talking only to :class:`PostgresProvenanceIndex` (not the
Merkle variant). Multi-writer Merkle with cross-process tree
synchronization is on the commercial roadmap.

If you only need ``verify()`` and not ``tree_root()`` / inclusion proofs
on a given pod, use :class:`PostgresProvenanceIndex` directly — the
underlying tables are the same.
"""

from __future__ import annotations

from ..core.merkle import MerkleTree
from .postgres_index import PostgresProvenanceIndex
from .sqlite_index import _canonical_payload

_MERKLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS provenex_merkle_leaves (
    leaf_index BIGINT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    leaf_bytes BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_provenex_merkle_fingerprint
    ON provenex_merkle_leaves(fingerprint);
"""


# Advisory-lock key for leaf_index assignment. Any constant works; the
# value is shared by all writers against the same database.
_LEAF_LOCK_KEY = 0x70726F76656E6578  # ASCII 'provenex'


def _hex(b: bytes) -> str:
    """Encode bytes as the ``sha256:<hex>`` form the rest of Provenex uses."""
    return "sha256:" + b.hex()


class MerklePostgresProvenanceIndex(PostgresProvenanceIndex):
    """Postgres provenance index with a transparency log.

    Adds three operations beyond the base interface:

        * :meth:`tree_size` — number of leaves committed by *this* process
        * :meth:`tree_root` — tree head as ``sha256:<hex>`` for *this*
          process's view
        * :meth:`inclusion_proof` — RFC 6962 audit path for a fingerprint

    See module docstring for the multi-writer caveat.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        pool=None,
        signing_secret: bytes | None = None,
        min_size: int = 1,
        max_size: int = 10,
    ) -> None:
        super().__init__(
            dsn=dsn,
            pool=pool,
            signing_secret=signing_secret,
            min_size=min_size,
            max_size=max_size,
        )
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(_MERKLE_SCHEMA)
            conn.commit()

        self._tree = MerkleTree()
        self._leaf_index_by_fp: dict[str, int] = {}
        self._rebuild_tree_from_disk()

    # ------------------------------------------------------------- helpers

    def _rebuild_tree_from_disk(self) -> None:
        """Replay persisted leaves into the in-memory tree in index order."""
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT leaf_index, fingerprint, leaf_bytes "
                    "FROM provenex_merkle_leaves ORDER BY leaf_index ASC"
                )
                rows = cur.fetchall()
        for leaf_index, fingerprint, leaf_bytes in rows:
            self._tree.append(bytes(leaf_bytes))
            self._leaf_index_by_fp[fingerprint] = leaf_index

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
        # Did this exact (fp, doc, version) row already exist? If so the
        # base add() is an authorization-refresh only and we must NOT append
        # a new Merkle leaf.
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM provenex_fingerprints "
                    "WHERE fingerprint = %s AND document_id = %s "
                    "AND document_version = %s LIMIT 1",
                    (fingerprint, document_id, document_version),
                )
                existed = cur.fetchone() is not None

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

        # Read back the canonical row to build the leaf (identical bytes to
        # the HMAC payload). leaf_index assignment is serialized with an
        # advisory xact lock so concurrent writers don't collide on the tail.
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (_LEAF_LOCK_KEY,))
                cur.execute(
                    "SELECT fingerprint, document_id, document_version, "
                    "       ingested_at, chunk_offset, chunk_length "
                    "FROM provenex_fingerprints "
                    "WHERE fingerprint = %s AND document_id = %s "
                    "AND document_version = %s",
                    (fingerprint, document_id, document_version),
                )
                row = cur.fetchone()
                leaf_bytes = _canonical_payload(
                    fingerprint=row[0],
                    document_id=row[1],
                    document_version=row[2],
                    ingested_at=row[3],
                    chunk_offset=row[4],
                    chunk_length=row[5],
                )
                cur.execute(
                    "SELECT COALESCE(MAX(leaf_index), -1) + 1 "
                    "FROM provenex_merkle_leaves"
                )
                leaf_index = cur.fetchone()[0]
                cur.execute(
                    "INSERT INTO provenex_merkle_leaves "
                    "(leaf_index, fingerprint, leaf_bytes) VALUES (%s, %s, %s)",
                    (leaf_index, fingerprint, leaf_bytes),
                )
            conn.commit()

        self._tree.append(leaf_bytes)
        self._leaf_index_by_fp[fingerprint] = leaf_index

    # ----------------------------------------------------------- read

    def tree_size(self) -> int:
        """Number of leaves currently in this process's view of the log."""
        return self._tree.size()

    def tree_root(self) -> str:
        """Tree head as ``sha256:<hex>`` for this process's view."""
        return _hex(self._tree.root())

    def inclusion_proof(self, fingerprint: str) -> tuple[bytes, int, list[str]]:
        """Audit path for a fingerprint's most recent leaf.

        Returns:
            ``(leaf_bytes, leaf_index, proof)`` where ``proof`` is the audit
            path as ``sha256:<hex>`` strings and ``leaf_bytes`` is the
            canonical row payload the HMAC signed.

        Raises:
            KeyError: If the fingerprint has never been added (in this
                process's view of the log).
        """
        leaf_index = self._leaf_index_by_fp.get(fingerprint)
        if leaf_index is None:
            raise KeyError(f"fingerprint not in log: {fingerprint!r}")
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT leaf_bytes FROM provenex_merkle_leaves "
                    "WHERE leaf_index = %s",
                    (leaf_index,),
                )
                row = cur.fetchone()
        proof_bytes = self._tree.inclusion_proof(leaf_index)
        return bytes(row[0]), leaf_index, [_hex(p) for p in proof_bytes]
