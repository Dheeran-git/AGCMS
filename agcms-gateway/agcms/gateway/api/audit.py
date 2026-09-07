"""Audit log list / get / export / per-row verify."""

import csv
import io
import uuid
from typing import Any, Optional

import asyncpg
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_compliance
from agcms.gateway.api.common import AUDIT_URL, db_dsn, passthrough, csv_safe, parse_ts

router = APIRouter()


@router.get("/audit/logs")
async def list_audit_logs(
    ctx: AuthContext = Depends(require_compliance),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    """List audit logs for the caller's tenant, newest first."""
    clauses = ["tenant_id = $1"]
    args: list[Any] = [ctx.tenant_id]

    if action:
        args.append(action)
        clauses.append(f"enforcement_action = ${len(args)}")
    if start:
        args.append(parse_ts(start))
        clauses.append(f"created_at >= ${len(args)}")
    if end:
        args.append(parse_ts(end))
        clauses.append(f"created_at <= ${len(args)}")

    where = " AND ".join(clauses)
    args.extend([limit, offset])

    query = (
        f"SELECT interaction_id, tenant_id, user_id, department, created_at, "
        f"enforcement_action, enforcement_reason, pii_detected, pii_entity_types, "
        f"pii_risk_level, injection_score, injection_type, response_violated, "
        f"total_latency_ms "
        f"FROM audit_logs WHERE {where} "
        f"ORDER BY created_at DESC LIMIT ${len(args) - 1} OFFSET ${len(args)}"
    )

    conn = await asyncpg.connect(db_dsn())
    try:
        rows = await conn.fetch(query, *args)
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM audit_logs WHERE {where}", *args[:-2]
        )
    finally:
        await conn.close()

    return {
        "logs": [_serialize_audit_row(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/audit/logs/{interaction_id}")
async def get_audit_log(
    interaction_id: str,
    ctx: AuthContext = Depends(require_compliance),
):
    """Fetch a single audit log entry by interaction_id."""
    try:
        iid = uuid.UUID(interaction_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid interaction_id (must be UUID)")

    conn = await asyncpg.connect(db_dsn())
    try:
        row = await conn.fetchrow(
            "SELECT * FROM audit_logs WHERE interaction_id = $1 AND tenant_id = $2 "
            "ORDER BY created_at DESC LIMIT 1",
            iid, ctx.tenant_id,
        )
    finally:
        await conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Audit log not found")
    return _serialize_audit_row(row)


@router.get("/audit/export")
async def export_audit_logs(
    ctx: AuthContext = Depends(require_compliance),
    format: str = Query("json", pattern="^(json|csv)$"),
    limit: int = Query(1000, ge=1, le=10000),
):
    """Export audit logs for the tenant as JSON or CSV."""
    conn = await asyncpg.connect(db_dsn())
    try:
        rows = await conn.fetch(
            "SELECT interaction_id, tenant_id, user_id, department, created_at, "
            "enforcement_action, enforcement_reason, pii_detected, pii_entity_types, "
            "pii_risk_level, injection_score, injection_type, response_violated, "
            "total_latency_ms "
            "FROM audit_logs WHERE tenant_id = $1 "
            "ORDER BY created_at DESC LIMIT $2",
            ctx.tenant_id, limit,
        )
    finally:
        await conn.close()

    serialized = [_serialize_audit_row(r) for r in rows]

    if format == "json":
        return {"tenant_id": ctx.tenant_id, "count": len(serialized), "logs": serialized}

    # CSV
    buf = io.StringIO()
    if serialized:
        writer = csv.DictWriter(buf, fieldnames=list(serialized[0].keys()))
        writer.writeheader()
        for row in serialized:
            writer.writerow({k: csv_safe(v) for k, v in row.items()})
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="audit_{ctx.tenant_id}.csv"'
        },
    )


@router.post("/audit/verify/{interaction_id}")
async def verify_audit_log(
    interaction_id: str,
    ctx: AuthContext = Depends(require_compliance),
):
    """Verify the HMAC signature of an audit log entry (via audit service)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{AUDIT_URL}/verify/{interaction_id}")
    return passthrough(resp)


def _serialize_audit_row(r) -> dict:
    """Convert an asyncpg Record from audit_logs into JSON-safe dict."""
    return {
        "interaction_id": str(r["interaction_id"]) if r["interaction_id"] else None,
        "tenant_id": r["tenant_id"],
        "user_id": r["user_id"],
        "department": r["department"] if "department" in r else None,
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "enforcement_action": r["enforcement_action"],
        "enforcement_reason": r["enforcement_reason"],
        "pii_detected": r["pii_detected"],
        "pii_entity_types": list(r["pii_entity_types"]) if r.get("pii_entity_types") else [],
        "pii_risk_level": r["pii_risk_level"] if "pii_risk_level" in r else None,
        "injection_score": float(r["injection_score"]) if r["injection_score"] is not None else None,
        "injection_type": r["injection_type"] if "injection_type" in r else None,
        "response_violated": r["response_violated"] if "response_violated" in r else None,
        "total_latency_ms": r["total_latency_ms"],
    }
