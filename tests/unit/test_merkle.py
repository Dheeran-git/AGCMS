"""Unit tests for the Merkle-tree anchor utilities."""
from __future__ import annotations

import hashlib

import pytest

from agcms.audit.merkle import (
    compute_root,
    inclusion_proof,
    leaf_hash,
    node_hash,
    verify_inclusion,
)


def _sig(i: int) -> str:
    """Deterministic fake signature hex for test inputs."""
    return hashlib.sha256(f"sig-{i}".encode()).hexdigest()


class TestRoot:
    def test_empty_root_is_zero(self):
        assert compute_root([]) == b"\x00" * 32

    def test_single_leaf_root_equals_leaf(self):
        sig = _sig(0)
        assert compute_root([sig]) == leaf_hash(sig)

    def test_two_leaves(self):
        sigs = [_sig(0), _sig(1)]
        expected = node_hash(leaf_hash(sigs[0]), leaf_hash(sigs[1]))
        assert compute_root(sigs) == expected

    def test_three_leaves_duplicates_last(self):
        sigs = [_sig(0), _sig(1), _sig(2)]
        l0, l1, l2 = (leaf_hash(s) for s in sigs)
        left = node_hash(l0, l1)
        right = node_hash(l2, l2)  # duplicate-odd
        expected = node_hash(left, right)
        assert compute_root(sigs) == expected

    def test_root_is_32_bytes(self):
        sigs = [_sig(i) for i in range(17)]
        assert len(compute_root(sigs)) == 32

    def test_root_changes_on_tamper(self):
        sigs = [_sig(i) for i in range(10)]
        original = compute_root(sigs)
        sigs[5] = _sig(999)
        assert compute_root(sigs) != original

    def test_root_changes_on_reorder(self):
        sigs = [_sig(i) for i in range(10)]
        original = compute_root(sigs)
        sigs[3], sigs[4] = sigs[4], sigs[3]
        assert compute_root(sigs) != original


class TestInclusionProof:
    @pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 100])
    def test_every_leaf_verifies_under_root(self, n):
        sigs = [_sig(i) for i in range(n)]
        root_hex = compute_root(sigs).hex()
        for i, sig in enumerate(sigs):
            proof = inclusion_proof(sigs, i)
            assert verify_inclusion(sig, proof, root_hex), (
                f"leaf {i} failed under tree size {n}: proof={proof}"
            )

    def test_wrong_signature_fails(self):
        sigs = [_sig(i) for i in range(8)]
        root_hex = compute_root(sigs).hex()
        proof = inclusion_proof(sigs, 3)
        assert not verify_inclusion(_sig(999), proof, root_hex)

    def test_wrong_root_fails(self):
        sigs = [_sig(i) for i in range(8)]
        proof = inclusion_proof(sigs, 3)
        wrong_root = "a" * 64
        assert not verify_inclusion(sigs[3], proof, wrong_root)

    def test_tampered_sibling_fails(self):
        sigs = [_sig(i) for i in range(8)]
        root_hex = compute_root(sigs).hex()
        proof = inclusion_proof(sigs, 3)
        # Corrupt first sibling in the proof
        position, _ = proof[0]
        proof[0] = (position, "f" * 64)
        assert not verify_inclusion(sigs[3], proof, root_hex)

    def test_index_out_of_range_raises(self):
        with pytest.raises(IndexError):
            inclusion_proof([_sig(0), _sig(1)], 5)
