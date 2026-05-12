"""Tests for the RFC 6962 Merkle transparency log primitive.

The format matches RFC 6962 (Certificate Transparency) so receipts can be
verified by any RFC 6962-compatible auditor tool. Domain separators:

    leaf_hash = SHA256(0x00 || leaf_bytes)
    node_hash = SHA256(0x01 || left || right)

For unbalanced trees the recursion splits at the largest power of two
strictly less than the subtree size.
"""

from __future__ import annotations

import hashlib

import pytest

from provenex.core.merkle import MerkleTree, verify_inclusion_proof


def _h_leaf(s: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + s).digest()


def _h_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


# --------------------------------------------------------------------------- #
# Construction and root                                                       #
# --------------------------------------------------------------------------- #


def test_empty_tree_has_empty_string_root():
    """RFC 6962 §2.1: the root of an empty tree is SHA-256 of the empty string."""
    tree = MerkleTree()
    assert tree.size() == 0
    assert tree.root() == hashlib.sha256(b"").digest()


def test_single_leaf_root_equals_leaf_hash():
    tree = MerkleTree()
    tree.append(b"a")
    assert tree.size() == 1
    assert tree.root() == _h_leaf(b"a")


def test_two_leaf_root():
    tree = MerkleTree()
    tree.append(b"a")
    tree.append(b"b")
    assert tree.root() == _h_node(_h_leaf(b"a"), _h_leaf(b"b"))


def test_three_leaf_root_uses_pow2_split():
    """For n=3 the split is at k=2: root = H(H(a,b), leaf_c)."""
    tree = MerkleTree()
    tree.append(b"a")
    tree.append(b"b")
    tree.append(b"c")
    ab = _h_node(_h_leaf(b"a"), _h_leaf(b"b"))
    expected = _h_node(ab, _h_leaf(b"c"))
    assert tree.root() == expected


def test_append_returns_sequential_indices():
    tree = MerkleTree()
    assert tree.append(b"a") == 0
    assert tree.append(b"b") == 1
    assert tree.append(b"c") == 2
    assert tree.size() == 3


def test_root_changes_on_append():
    tree = MerkleTree()
    tree.append(b"a")
    r1 = tree.root()
    tree.append(b"b")
    r2 = tree.root()
    assert r1 != r2


def test_root_deterministic():
    """Two trees built with the same leaves in the same order produce the same root."""
    a = MerkleTree()
    b = MerkleTree()
    for leaf in [b"x", b"y", b"z", b"w", b"v"]:
        a.append(leaf)
        b.append(leaf)
    assert a.root() == b.root()


# --------------------------------------------------------------------------- #
# Inclusion proofs                                                            #
# --------------------------------------------------------------------------- #


def test_single_leaf_proof_is_empty():
    tree = MerkleTree()
    tree.append(b"a")
    assert tree.inclusion_proof(0) == []


def test_inclusion_proof_balanced_tree():
    """For a 2^k tree every proof has exactly k hashes."""
    tree = MerkleTree()
    leaves = [str(i).encode() for i in range(8)]
    for leaf in leaves:
        tree.append(leaf)
    for i in range(8):
        proof = tree.inclusion_proof(i)
        assert len(proof) == 3, f"proof for index {i} should have 3 hashes"


def test_inclusion_proof_roundtrip_all_balanced_sizes():
    """Verify proves and verifies for every leaf at every power-of-2 size."""
    for k in range(0, 8):
        n = 1 << k
        tree = MerkleTree()
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        for leaf in leaves:
            tree.append(leaf)
        root = tree.root()
        size = tree.size()
        for i in range(n):
            proof = tree.inclusion_proof(i)
            assert verify_inclusion_proof(leaves[i], i, size, proof, root), (
                f"failed at n={n}, i={i}"
            )


def test_inclusion_proof_roundtrip_unbalanced_sizes():
    """Sizes that aren't powers of 2 must also roundtrip for every leaf."""
    for n in [1, 2, 3, 5, 7, 9, 11, 13, 17, 23, 100, 257]:
        tree = MerkleTree()
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        for leaf in leaves:
            tree.append(leaf)
        root = tree.root()
        for i in range(n):
            proof = tree.inclusion_proof(i)
            ok = verify_inclusion_proof(leaves[i], i, n, proof, root)
            assert ok, f"failed at n={n}, i={i}"


def test_inclusion_proof_wrong_leaf_fails():
    tree = MerkleTree()
    for i in range(5):
        tree.append(str(i).encode())
    proof = tree.inclusion_proof(2)
    assert verify_inclusion_proof(b"99", 2, 5, proof, tree.root()) is False


def test_inclusion_proof_wrong_index_fails():
    tree = MerkleTree()
    for i in range(5):
        tree.append(str(i).encode())
    proof = tree.inclusion_proof(2)
    assert verify_inclusion_proof(b"2", 3, 5, proof, tree.root()) is False


def test_inclusion_proof_wrong_root_fails():
    tree = MerkleTree()
    for i in range(5):
        tree.append(str(i).encode())
    proof = tree.inclusion_proof(2)
    wrong_root = b"\x00" * 32
    assert verify_inclusion_proof(b"2", 2, 5, proof, wrong_root) is False


def test_inclusion_proof_against_different_tree_fails():
    """A proof from one tree must not verify against a different tree's root."""
    tree5 = MerkleTree()
    for i in range(5):
        tree5.append(str(i).encode())
    tree6 = MerkleTree()
    for i in range(6):
        tree6.append(str(i).encode())
    proof = tree5.inclusion_proof(2)
    # Same leaf and index, but the root is from a different log — must fail.
    assert verify_inclusion_proof(b"2", 2, 6, proof, tree6.root()) is False


def test_inclusion_proof_tampered_proof_fails():
    tree = MerkleTree()
    for i in range(8):
        tree.append(str(i).encode())
    proof = tree.inclusion_proof(3)
    # Flip a bit in one of the proof hashes.
    bad = list(proof)
    bad[0] = bytes(b ^ 0x01 for b in bad[0])
    assert verify_inclusion_proof(b"3", 3, 8, bad, tree.root()) is False


def test_inclusion_proof_out_of_range_raises():
    tree = MerkleTree()
    tree.append(b"a")
    with pytest.raises(IndexError):
        tree.inclusion_proof(5)
    with pytest.raises(IndexError):
        tree.inclusion_proof(-1)


def test_verify_rejects_index_outside_tree():
    """verify_inclusion_proof must return False if leaf_index >= tree_size."""
    assert verify_inclusion_proof(b"x", 5, 5, [], b"\x00" * 32) is False
    assert verify_inclusion_proof(b"x", 0, 0, [], b"\x00" * 32) is False


# --------------------------------------------------------------------------- #
# Scale sanity                                                                #
# --------------------------------------------------------------------------- #


def test_proof_size_is_logarithmic():
    """Proof size for n leaves is at most ceil(log2(n))."""
    import math

    tree = MerkleTree()
    n = 1000
    for i in range(n):
        tree.append(i.to_bytes(4, "big"))
    proof = tree.inclusion_proof(n // 2)
    assert len(proof) <= math.ceil(math.log2(n))


def test_proofs_are_consistent_across_appends():
    """After appending more leaves, old leaves still produce valid proofs against the new root."""
    tree = MerkleTree()
    leaves = [f"L{i}".encode() for i in range(20)]
    for leaf in leaves[:10]:
        tree.append(leaf)
    # Snapshot the root at size 10
    root_at_10 = tree.root()
    proof_5_at_10 = tree.inclusion_proof(5)
    assert verify_inclusion_proof(leaves[5], 5, 10, proof_5_at_10, root_at_10)

    # Grow to 20
    for leaf in leaves[10:]:
        tree.append(leaf)
    root_at_20 = tree.root()
    # The old proof should NOT verify against the new root (it's a different tree)
    assert not verify_inclusion_proof(leaves[5], 5, 20, proof_5_at_10, root_at_20)
    # But a fresh proof for leaf 5 at size 20 should verify.
    proof_5_at_20 = tree.inclusion_proof(5)
    assert verify_inclusion_proof(leaves[5], 5, 20, proof_5_at_20, root_at_20)
