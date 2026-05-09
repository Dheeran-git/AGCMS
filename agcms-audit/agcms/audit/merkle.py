"""Merkle-tree utilities for audit-root anchoring.

Hash scheme:
  leaf_h(s)      = SHA256(0x00 || bytes.fromhex(s))
  node_h(l, r)   = SHA256(0x01 || l || r)

Odd layer handling: the last node at the layer is duplicated to pair with
itself (Bitcoin convention). This keeps the tree shape predictable and
avoids Certificate-Transparency-style mixed-arity pairings, at the cost
of one trivial ambiguity that does not affect security of per-root
anchoring.

Leaves are the audit row's ``log_signature`` (lowercase hex, 64 chars).
Root is 32 bytes. Sign the root with HMAC-SHA256 using the anchor key,
not the row key — anchor material is rotated independently.
"""
from __future__ import annotations

import hashlib
from typing import List, Sequence, Tuple

LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(signature_hex: str) -> bytes:
    return _h(LEAF_TAG + bytes.fromhex(signature_hex))


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(NODE_TAG + left + right)


def compute_root(signatures: Sequence[str]) -> bytes:
    """Return the 32-byte Merkle root over the ordered signatures.

    Empty input returns 32 zero bytes so that "no activity" periods still
    produce a signable artifact.
    """
    if not signatures:
        return b"\x00" * 32

    level: List[bytes] = [leaf_hash(s) for s in signatures]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def inclusion_proof(signatures: Sequence[str], index: int) -> List[Tuple[str, str]]:
    """Sibling path for leaf at ``index``.

    Returned as a list of ``(position, sibling_hex)`` where ``position``
    is ``"L"`` (sibling is left of the running hash) or ``"R"`` (right).
    """
    if index < 0 or index >= len(signatures):
        raise IndexError(f"index {index} out of range for {len(signatures)} leaves")

    level: List[bytes] = [leaf_hash(s) for s in signatures]
    proof: List[Tuple[str, str]] = []
    i = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if i % 2 == 0:
            proof.append(("R", level[i + 1].hex()))
        else:
            proof.append(("L", level[i - 1].hex()))
        i //= 2
        level = [node_hash(level[j], level[j + 1]) for j in range(0, len(level), 2)]
    return proof


def verify_inclusion(
    signature_hex: str,
    proof: Sequence[Tuple[str, str]],
    root_hex: str,
) -> bool:
    """Return True iff ``signature_hex`` is in the tree rooted at ``root_hex``."""
    running = leaf_hash(signature_hex)
    for position, sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if position == "L":
            running = node_hash(sibling, running)
        elif position == "R":
            running = node_hash(running, sibling)
        else:
            return False
    return running == bytes.fromhex(root_hex)


__all__ = [
    "compute_root",
    "inclusion_proof",
    "leaf_hash",
    "node_hash",
    "verify_inclusion",
]
