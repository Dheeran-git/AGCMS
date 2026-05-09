"""Signing-key rotation state machine.

Pure functions — no DB or HTTP — so the transition rules are unit-testable
in isolation. The gateway's ``management_api.py`` layers DB persistence
and RBAC on top of these.

State diagram
-------------
    [propose] ──► proposed ──[approve]──► approved ──[execute]──► executed
                     │                        │
                     └────[cancel]────────────┘
                              ▼
                          cancelled

Invariants enforced by this module
----------------------------------
* The approver must differ from the proposer (two-person rule).
* A rotation can only be executed from the ``approved`` state.
* A rotation can only be cancelled from ``proposed`` or ``approved``.
* The new kid must not collide with any existing kid.
* ``new_key_hash`` is SHA-256(new_key_material). Material itself is never
  stored — verification that the env secret store has the right bytes is
  the operator's responsibility at execute-time.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional


class RotationState(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    EXECUTED = "executed"
    CANCELLED = "cancelled"


class RotationError(Exception):
    """Raised when a state transition is invalid."""


@dataclass(frozen=True)
class Rotation:
    purpose: str              # "row" | "anchor"
    new_kid: str
    new_key_hash: str         # SHA-256 hex of new key material
    old_kid: str
    state: RotationState
    proposed_by: str
    approved_by: Optional[str] = None
    executed_by: Optional[str] = None
    cancelled_by: Optional[str] = None


def hash_key_material(material: bytes | str) -> str:
    """Return SHA-256 hex of the key material (for later fingerprint checks)."""
    if isinstance(material, str):
        material = material.encode("utf-8")
    if not material:
        raise RotationError("key material must not be empty")
    return hashlib.sha256(material).hexdigest()


def propose(
    *,
    purpose: str,
    new_kid: str,
    new_key_material: bytes | str,
    old_kid: str,
    proposed_by: str,
    reason: str,
    existing_kids: Iterable[str],
) -> Rotation:
    """Validate + build a new Rotation in the ``proposed`` state.

    ``existing_kids`` is every kid already in the signing_keys table — the
    new kid must be unique (collisions would corrupt historical verification).
    """
    if purpose not in ("row", "anchor"):
        raise RotationError(f"purpose must be 'row' or 'anchor', got {purpose!r}")
    if not new_kid or not new_kid.strip():
        raise RotationError("new_kid is required")
    if new_kid == old_kid:
        raise RotationError("new_kid must differ from old_kid")
    if new_kid in set(existing_kids):
        raise RotationError(
            f"new_kid {new_kid!r} already exists — choose a fresh identifier"
        )
    if not proposed_by or not proposed_by.strip():
        raise RotationError("proposed_by is required")
    if not reason or not reason.strip():
        raise RotationError("reason is required (audit trail)")

    return Rotation(
        purpose=purpose,
        new_kid=new_kid,
        new_key_hash=hash_key_material(new_key_material),
        old_kid=old_kid,
        state=RotationState.PROPOSED,
        proposed_by=proposed_by,
    )


def approve(rotation: Rotation, *, approver: str) -> Rotation:
    """Move a ``proposed`` rotation to ``approved``.

    Enforces the two-person rule: approver != proposer.
    """
    if rotation.state is not RotationState.PROPOSED:
        raise RotationError(
            f"cannot approve rotation in state {rotation.state.value!r}"
        )
    if not approver or not approver.strip():
        raise RotationError("approver is required")
    if approver == rotation.proposed_by:
        raise RotationError(
            "approver must differ from proposer (two-person rule)"
        )
    return Rotation(
        purpose=rotation.purpose,
        new_kid=rotation.new_kid,
        new_key_hash=rotation.new_key_hash,
        old_kid=rotation.old_kid,
        state=RotationState.APPROVED,
        proposed_by=rotation.proposed_by,
        approved_by=approver,
    )


def execute(rotation: Rotation, *, executor: str) -> Rotation:
    """Move an ``approved`` rotation to ``executed``.

    Executor can be either approver or proposer — typically the operator
    who just updated the secret store with the new key material.
    """
    if rotation.state is not RotationState.APPROVED:
        raise RotationError(
            f"cannot execute rotation in state {rotation.state.value!r}"
        )
    if not executor or not executor.strip():
        raise RotationError("executor is required")
    return Rotation(
        purpose=rotation.purpose,
        new_kid=rotation.new_kid,
        new_key_hash=rotation.new_key_hash,
        old_kid=rotation.old_kid,
        state=RotationState.EXECUTED,
        proposed_by=rotation.proposed_by,
        approved_by=rotation.approved_by,
        executed_by=executor,
    )


def cancel(rotation: Rotation, *, canceller: str) -> Rotation:
    """Cancel a rotation that has not yet been executed."""
    if rotation.state not in (RotationState.PROPOSED, RotationState.APPROVED):
        raise RotationError(
            f"cannot cancel rotation in state {rotation.state.value!r}"
        )
    if not canceller or not canceller.strip():
        raise RotationError("canceller is required")
    return Rotation(
        purpose=rotation.purpose,
        new_kid=rotation.new_kid,
        new_key_hash=rotation.new_key_hash,
        old_kid=rotation.old_kid,
        state=RotationState.CANCELLED,
        proposed_by=rotation.proposed_by,
        approved_by=rotation.approved_by,
        cancelled_by=canceller,
    )


__all__ = [
    "Rotation",
    "RotationState",
    "RotationError",
    "hash_key_material",
    "propose",
    "approve",
    "execute",
    "cancel",
]
