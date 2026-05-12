"""RFC 6962 Merkle transparency log over fingerprint rows.

Why this exists
---------------
The HMAC-signed rows in the provenance index detect tampering with any
*single* row. A transparency log adds a stronger property: an attacker
cannot insert or remove rows without changing a publicly-observable tree
head. Given a published tree head, anyone holding a single row can produce
a logarithmic-sized inclusion proof showing the row was in the log without
revealing the rest of the log. Auditors recognize this pattern from
Certificate Transparency, Sigstore Rekor, and Go module checksum logs.

Algorithm
---------
This is RFC 6962 (the Certificate Transparency MTH) with two domain
separators::

    leaf_hash = SHA256(0x00 || leaf_bytes)
    node_hash = SHA256(0x01 || left_hash || right_hash)

For an n-leaf subtree where n > 1, the recursion splits at k = the largest
power of two strictly less than n. This split rule is what makes RFC 6962
trees deterministic for non-power-of-two sizes — there is no implicit leaf
duplication, no padding.

Reference: https://www.rfc-editor.org/rfc/rfc6962#section-2

Notes
-----
The recursive ``MTH`` calls share many subtree boundaries; we memoize on a
``(lo, hi)`` cache that is cleared on append. With the cache, building the
root is O(N) once, and an inclusion proof is O(log N) afterward. For the
million-leaf scale targeted by the OSS reference implementation this is
adequate. Production deployments maintain the tree incrementally — see the
hosted Provenex transparency log for that.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence


# --------------------------------------------------------------------------- #
# Hashing primitives                                                          #
# --------------------------------------------------------------------------- #


def _hash_leaf(leaf: bytes) -> bytes:
    """RFC 6962 leaf hash: ``SHA256(0x00 || leaf)``."""
    return hashlib.sha256(b"\x00" + leaf).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal node hash: ``SHA256(0x01 || left || right)``."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest power of two strictly less than ``n``. Requires ``n > 1``."""
    return 1 << ((n - 1).bit_length() - 1)


# --------------------------------------------------------------------------- #
# Tree                                                                        #
# --------------------------------------------------------------------------- #


class MerkleTree:
    """An append-only RFC 6962 Merkle tree.

    Leaves are stored as their hashes (not the original bytes). The tree
    root and inclusion proofs are computed lazily; appending invalidates
    the cache.
    """

    def __init__(self) -> None:
        self._leaf_hashes: list[bytes] = []
        # Memoized subtree hashes keyed by (lo, hi) half-open ranges into
        # _leaf_hashes. Cleared on every append.
        self._mth_cache: dict[tuple[int, int], bytes] = {}

    # ------------------------------------------------------------------ basic

    def size(self) -> int:
        """Number of leaves in the tree."""
        return len(self._leaf_hashes)

    def append(self, leaf: bytes) -> int:
        """Append a leaf and return its 0-based index.

        Args:
            leaf: Raw leaf bytes. The tree stores ``SHA256(0x00 || leaf)``.

        Returns:
            The leaf's position in the log.
        """
        idx = len(self._leaf_hashes)
        self._leaf_hashes.append(_hash_leaf(leaf))
        self._mth_cache.clear()
        return idx

    # ------------------------------------------------------------------ root

    def root(self) -> bytes:
        """The current tree head (32 bytes).

        Returns ``SHA256(b"")`` for an empty tree, per RFC 6962 §2.1.
        """
        if not self._leaf_hashes:
            return hashlib.sha256(b"").digest()
        return self._mth(0, len(self._leaf_hashes))

    def _mth(self, lo: int, hi: int) -> bytes:
        """Merkle tree hash of ``_leaf_hashes[lo:hi]`` (half-open)."""
        key = (lo, hi)
        cached = self._mth_cache.get(key)
        if cached is not None:
            return cached
        n = hi - lo
        if n == 1:
            r = self._leaf_hashes[lo]
        else:
            k = _largest_pow2_lt(n)
            r = _hash_node(self._mth(lo, lo + k), self._mth(lo + k, hi))
        self._mth_cache[key] = r
        return r

    # ------------------------------------------------------------- proofs

    def inclusion_proof(self, leaf_index: int) -> list[bytes]:
        """Audit path for the leaf at ``leaf_index``.

        Returns a list of sibling hashes ordered bottom-up. For a leaf in a
        size-1 tree the proof is empty. Use :func:`verify_inclusion_proof`
        to check a proof against a known root.

        Raises:
            IndexError: if ``leaf_index`` is outside the tree.
        """
        n = len(self._leaf_hashes)
        if leaf_index < 0 or leaf_index >= n:
            raise IndexError(
                f"leaf_index {leaf_index} out of range [0, {n})"
            )
        return self._proof(leaf_index, 0, n)

    def _proof(self, m: int, lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        k = _largest_pow2_lt(n)
        if m < lo + k:
            return self._proof(m, lo, lo + k) + [self._mth(lo + k, hi)]
        return self._proof(m, lo + k, hi) + [self._mth(lo, lo + k)]


# --------------------------------------------------------------------------- #
# Stateless verifier                                                          #
# --------------------------------------------------------------------------- #


def verify_inclusion_proof(
    leaf: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Verify an RFC 6962 inclusion proof.

    Args:
        leaf: The raw leaf bytes (not the leaf hash).
        leaf_index: 0-based position of the leaf in the log.
        tree_size: Total number of leaves the proof was produced against.
        proof: Audit path from :meth:`MerkleTree.inclusion_proof`.
        root: The tree head the proof should verify against.

    Returns:
        True iff the proof is valid for ``(leaf, leaf_index, tree_size, root)``.
        False on any mismatch, including out-of-range index or empty tree.
    """
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False

    fn = _hash_leaf(leaf)
    sn = tree_size - 1
    r = leaf_index

    for sibling in proof:
        if sn == 0:
            return False
        if (r & 1) == 1 or r == sn:
            fn = _hash_node(sibling, fn)
            # When we came here via r == sn (r even), unwind even levels
            # until r is odd or zero. This mirrors RFC 6962 §2.1.2.
            while (r & 1) == 0 and r != 0:
                r >>= 1
                sn >>= 1
        else:
            fn = _hash_node(fn, sibling)
        r >>= 1
        sn >>= 1

    return fn == root and sn == 0
