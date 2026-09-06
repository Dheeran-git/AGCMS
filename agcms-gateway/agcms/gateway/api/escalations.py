"""Escalation review workflow (compliance+)."""

import uuid
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_compliance
from agcms.gateway.api.common import db_dsn

router = APIRouter()


class EscalationUpdate(BaseModel):
    status: str = Field(..., pattern="^(PENDING|REVIEWED|DISMISSED|ACTIONED)$")
    notes: Optional[str] = None


class EscalationAcknowledge(BaseModel):
    notes: Optional[str] = None


class EscalationAssign(BaseModel):
    assignee_user_id: Optional[str] = None  # null clears assignment


class EscalationResolve(BaseModel):
    resolution_notes: str = Field(..., min_length=1)


# SLA targets in minutes — info: 24h, warning: 4h, critical: 30m.
# Used to compute time-to-acknowledge/resolve targets for the Alerts UI.
_SLA_MINUTES = {"info": 1440, "warning": 240, "critical": 30}

_ESC_COLS = (
    "id, interaction_id, tenant_id, created_at, reason, status, severity, "
    "reviewed_by, reviewed_at, notes, "
    "assignee_user_id, acknowledged_at, acknowledged_by, "
    "resolved_at, resolved_by, resolution_notes, sla_breached"
)


@router.get("/escalations")
async def list_escalations(
    ctx: AuthContext = Depends(require_compliance),
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """List escalations for the tenant, optionally filtered by status."""
    conn = await asyncpg.connect(db_dsn())
    try:
        if status_filter:
            rows = await conn.fetch(
                f"SELECT {_ESC_COLS} FROM escalations "
                "WHERE tenant_id = $1 AND status = $2 ORDER BY created_at DESC",
                ctx.tenant_id, status_filter,
            )
        else:
            rows = await conn.fetch(
                f"SELECT {_ESC_COLS} FROM escalations "
                "WHERE tenant_id = $1 ORDER BY created_at DESC",
                ctx.tenant_id,
            )
        # Lazily mark SLA-breached items so the index reflects current state.
        breached_ids = [r["id"] for r in rows if _is_sla_breached(r)]
        if breached_ids:
            await conn.execute(
                "UPDATE escalations SET sla_breached = TRUE "
                "WHERE id = ANY($1::uuid[]) AND sla_breached = FALSE",
                breached_ids,
            )
    finally:
        await conn.close()

    return {"escalations": [_serialize_escalation(r) for r in rows]}


@router.put("/escalations/{escalation_id}")
async def update_escalation(
    escalation_id: str,
    body: EscalationUpdate,
    ctx: AuthContext = Depends(require_compliance),
):
    """Update an escalation's status and notes."""
    eid = _parse_uuid(escalation_id, "escalation_id")
    conn = await asyncpg.connect(db_dsn())
    try:
        row = await conn.fetchrow(
            "UPDATE escalations SET status = $1, notes = $2, reviewed_at = NOW() "
            f"WHERE id = $3 AND tenant_id = $4 RETURNING {_ESC_COLS}",
            body.status, body.notes, eid, ctx.tenant_id,
        )
    finally:
        await conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    return _serialize_escalation(row)


@router.post("/escalations/{escalation_id}/acknowledge")
async def acknowledge_escalation(
    escalation_id: str,
    body: EscalationAcknowledge,
    ctx: AuthContext = Depends(require_compliance),
):
    """Mark an escalation acknowledged by the current user. Idempotent."""
    eid = _parse_uuid(escalation_id, "escalation_id")
    user_uuid = _user_uuid(ctx)
    conn = await asyncpg.connect(db_dsn())
    try:
        row = await conn.fetchrow(
            "UPDATE escalations SET "
            "  acknowledged_at = COALESCE(acknowledged_at, NOW()), "
            "  acknowledged_by = COALESCE(acknowledged_by, $1), "
            "  notes = COALESCE($2, notes) "
            f"WHERE id = $3 AND tenant_id = $4 RETURNING {_ESC_COLS}",
            user_uuid, body.notes, eid, ctx.tenant_id,
        )
    finally:
        await conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    return _serialize_escalation(row)


@router.post("/escalations/{escalation_id}/assign")
async def assign_escalation(
    escalation_id: str,
    body: EscalationAssign,
    ctx: AuthContext = Depends(require_compliance),
):
    """Assign (or unassign) an escalation to a tenant user."""
    eid = _parse_uuid(escalation_id, "escalation_id")
    assignee = _parse_uuid(body.assignee_user_id, "assignee_user_id") if body.assignee_user_id else None
    conn = await asyncpg.connect(db_dsn())
    try:
        if assignee is not None:
            exists = await conn.fetchval(
                "SELECT 1 FROM tenant_users WHERE id = $1 AND tenant_id = $2",
                assignee, ctx.tenant_id,
            )
            if not exists:
                raise HTTPException(status_code=404, detail="Assignee not in tenant")
        row = await conn.fetchrow(
            "UPDATE escalations SET assignee_user_id = $1 "
            f"WHERE id = $2 AND tenant_id = $3 RETURNING {_ESC_COLS}",
            assignee, eid, ctx.tenant_id,
        )
    finally:
        await conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    return _serialize_escalation(row)


@router.post("/escalations/{escalation_id}/resolve")
async def resolve_escalation(
    escalation_id: str,
    body: EscalationResolve,
    ctx: AuthContext = Depends(require_compliance),
):
    """Mark an escalation resolved with mandatory resolution notes."""
    eid = _parse_uuid(escalation_id, "escalation_id")
    user_uuid = _user_uuid(ctx)
    conn = await asyncpg.connect(db_dsn())
    try:
        row = await conn.fetchrow(
            "UPDATE escalations SET "
            "  resolved_at = NOW(), resolved_by = $1, "
            "  resolution_notes = $2, status = 'ACTIONED', "
            "  acknowledged_at = COALESCE(acknowledged_at, NOW()), "
            "  acknowledged_by = COALESCE(acknowledged_by, $1) "
            f"WHERE id = $3 AND tenant_id = $4 RETURNING {_ESC_COLS}",
            user_uuid, body.resolution_notes, eid, ctx.tenant_id,
        )
    finally:
        await conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    return _serialize_escalation(row)


def _parse_uuid(raw: str, label: str) -> uuid.UUID:
    try:
        return uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail=f"Invalid {label} (must be UUID)")


def _user_uuid(ctx: AuthContext) -> Optional[uuid.UUID]:
    """ctx.user_id is a UUID for JWT auth, sentinel otherwise."""
    if not ctx.user_id:
        return None
    try:
        return uuid.UUID(ctx.user_id)
    except (ValueError, AttributeError, TypeError):
        return None


def _is_sla_breached(row) -> bool:
    """An open escalation breaches SLA if it's older than the per-severity
    target without having been resolved (or, for unack'd ones, acknowledged)."""
    if row["resolved_at"] is not None:
        return False
    if row["sla_breached"]:
        return True
    target_minutes = _SLA_MINUTES.get(row["severity"], 240)
    age_seconds = (datetime.now(timezone.utc) - row["created_at"]).total_seconds()
    return age_seconds > target_minutes * 60


def _serialize_escalation(r) -> dict:
    target_minutes = _SLA_MINUTES.get(r["severity"], 240)
    return {
        "id": str(r["id"]),
        "interaction_id": str(r["interaction_id"]) if r["interaction_id"] else None,
        "tenant_id": r["tenant_id"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "reason": r["reason"],
        "status": r["status"],
        "severity": r["severity"],
        "reviewed_by": str(r["reviewed_by"]) if r["reviewed_by"] else None,
        "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
        "notes": r["notes"],
        "assignee_user_id": str(r["assignee_user_id"]) if r["assignee_user_id"] else None,
        "acknowledged_at": r["acknowledged_at"].isoformat() if r["acknowledged_at"] else None,
        "acknowledged_by": str(r["acknowledged_by"]) if r["acknowledged_by"] else None,
        "resolved_at": r["resolved_at"].isoformat() if r["resolved_at"] else None,
        "resolved_by": str(r["resolved_by"]) if r["resolved_by"] else None,
        "resolution_notes": r["resolution_notes"],
        "sla_breached": bool(r["sla_breached"]) or _is_sla_breached(r),
        "sla_target_minutes": target_minutes,
    }
