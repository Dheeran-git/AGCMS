"""DB-backed repository for signing-key rotation records.

Thin persistence layer on top of ``agcms.audit.key_rotation`` — handles
loading/saving rotation state and the final ``signing_keys`` table mutation
when a rotation is executed. Invariants live in the pure-function module;
this one just talks to Postgres.
"""
from __future__ import annotations

import uuid
from typing import Optional

import sqlalchemy

from agcms.audit.key_rotation import (
    Rotation,
    RotationError,
    RotationState,
    approve as _approve,
    cancel as _cancel,
    execute as _execute,
    propose as _propose,
)
from agcms.db import database


async def list_signing_keys() -> list[dict]:
    rows = await database.fetch_all(
        sqlalchemy.text(
            "SELECT kid, purpose, key_hash, is_active, created_at, retired_at, notes "
            "FROM signing_keys ORDER BY purpose, created_at"
        )
    )
    return [dict(r) for r in rows]


async def _existing_kids() -> list[str]:
    rows = await database.fetch_all(sqlalchemy.text("SELECT kid FROM signing_keys"))
    return [r["kid"] for r in rows]


async def _active_kid(purpose: str) -> Optional[str]:
    row = await database.fetch_one(
        sqlalchemy.text(
            "SELECT kid FROM signing_keys "
            "WHERE purpose = :purpose AND is_active = TRUE LIMIT 1"
        ).bindparams(purpose=purpose),
    )
    return None if row is None else row["kid"]


async def propose_rotation(
    *,
    purpose: str,
    new_kid: str,
    new_key_material: str,
    proposed_by: str,
    reason: str,
) -> dict:
    old_kid = await _active_kid(purpose)
    if old_kid is None:
        raise RotationError(f"no active {purpose!r} key on file — nothing to rotate")

    existing = await _existing_kids()
    rotation = _propose(
        purpose=purpose,
        new_kid=new_kid,
        new_key_material=new_key_material,
        old_kid=old_kid,
        proposed_by=proposed_by,
        reason=reason,
        existing_kids=existing,
    )

    row_id = uuid.uuid4()
    async with database.transaction():
        await database.execute(
            sqlalchemy.text(
                "INSERT INTO signing_key_rotations "
                "(id, purpose, new_kid, new_key_hash, old_kid, state, "
                " proposed_by, reason) "
                "VALUES (:id, :purpose, :new_kid, :new_key_hash, :old_kid, :state, "
                "        :proposed_by, :reason)"
            ).bindparams(
                id=row_id,
                purpose=rotation.purpose,
                new_kid=rotation.new_kid,
                new_key_hash=rotation.new_key_hash,
                old_kid=rotation.old_kid,
                state=rotation.state.value,
                proposed_by=rotation.proposed_by,
                reason=reason,
            ),
        )
    return await fetch_rotation(row_id)


async def approve_rotation(rotation_id: str, *, approver: str) -> dict:
    rec = await fetch_rotation(rotation_id)
    rotation = _to_domain(rec)
    approved = _approve(rotation, approver=approver)
    await database.execute(
        sqlalchemy.text(
            "UPDATE signing_key_rotations "
            "SET state = :state, approved_by = :approved_by, approved_at = NOW() "
            "WHERE id = :id AND state = 'proposed'"
        ).bindparams(
            state=approved.state.value,
            approved_by=approver,
            id=uuid.UUID(rotation_id),
        ),
    )
    return await fetch_rotation(rotation_id)


async def execute_rotation(rotation_id: str, *, executor: str) -> dict:
    rec = await fetch_rotation(rotation_id)
    rotation = _to_domain(rec)
    executed = _execute(rotation, executor=executor)

    async with database.transaction():
        # Flip the signing_keys rows: retire the old kid, activate the new kid.
        # new_kid may not exist yet — insert it.
        await database.execute(
            sqlalchemy.text(
                "UPDATE signing_keys "
                "SET is_active = FALSE, retired_at = NOW() "
                "WHERE kid = :old_kid"
            ).bindparams(old_kid=rotation.old_kid),
        )
        await database.execute(
            sqlalchemy.text(
                "INSERT INTO signing_keys (kid, purpose, key_hash, is_active, notes) "
                "VALUES (:kid, :purpose, :key_hash, TRUE, :notes) "
                "ON CONFLICT (kid) DO UPDATE "
                "SET is_active = TRUE, retired_at = NULL, "
                "    key_hash = EXCLUDED.key_hash, notes = EXCLUDED.notes"
            ).bindparams(
                kid=rotation.new_kid,
                purpose=rotation.purpose,
                key_hash=rotation.new_key_hash,
                notes=f"Rotated in via {rotation_id} by {executor}.",
            ),
        )
        await database.execute(
            sqlalchemy.text(
                "UPDATE signing_key_rotations "
                "SET state = :state, executed_by = :executed_by, executed_at = NOW() "
                "WHERE id = :id AND state = 'approved'"
            ).bindparams(
                state=executed.state.value,
                executed_by=executor,
                id=uuid.UUID(rotation_id),
            ),
        )
    return await fetch_rotation(rotation_id)


async def cancel_rotation(rotation_id: str, *, canceller: str) -> dict:
    rec = await fetch_rotation(rotation_id)
    rotation = _to_domain(rec)
    cancelled = _cancel(rotation, canceller=canceller)
    await database.execute(
        sqlalchemy.text(
            "UPDATE signing_key_rotations "
            "SET state = :state, cancelled_by = :cancelled_by, cancelled_at = NOW() "
            "WHERE id = :id AND state IN ('proposed', 'approved')"
        ).bindparams(
            state=cancelled.state.value,
            cancelled_by=canceller,
            id=uuid.UUID(rotation_id),
        ),
    )
    return await fetch_rotation(rotation_id)


async def fetch_rotation(rotation_id: str | uuid.UUID) -> dict:
    if isinstance(rotation_id, str):
        try:
            rid = uuid.UUID(rotation_id)
        except ValueError as exc:
            raise RotationError(f"invalid rotation id: {rotation_id}") from exc
    else:
        rid = rotation_id
    row = await database.fetch_one(
        sqlalchemy.text("SELECT * FROM signing_key_rotations WHERE id = :id").bindparams(id=rid),
    )
    if row is None:
        raise RotationError(f"rotation {rotation_id} not found")
    return dict(row)


async def list_rotations(*, limit: int = 50) -> list[dict]:
    rows = await database.fetch_all(
        sqlalchemy.text(
            "SELECT * FROM signing_key_rotations "
            "ORDER BY proposed_at DESC LIMIT :lim"
        ).bindparams(lim=limit),
    )
    return [dict(r) for r in rows]


def _to_domain(rec: dict) -> Rotation:
    return Rotation(
        purpose=rec["purpose"],
        new_kid=rec["new_kid"],
        new_key_hash=rec["new_key_hash"],
        old_kid=rec["old_kid"],
        state=RotationState(rec["state"]),
        proposed_by=rec["proposed_by"],
        approved_by=rec.get("approved_by"),
        executed_by=rec.get("executed_by"),
        cancelled_by=rec.get("cancelled_by"),
    )
