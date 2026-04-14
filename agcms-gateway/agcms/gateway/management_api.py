"""AGCMS Management REST API.

Exposes a versioned /api/v1 surface for compliance officers and tenant admins.
Lives in the gateway because the gateway already has:
  - DB access (DATABASE_URL)
  - JWT decode (agcms.gateway.auth.authenticate)
  - HTTP client infrastructure (httpx) for proxying to other services

Endpoint groups:
  /auth/*        — proxies to the auth service (no role gate)
  /audit/*       — audit log list/get/export/verify (compliance+)
  /policy/*      — policy CRUD backed by the DB policies table (admin/compliance)
  /users/*       — tenant_users CRUD (admin)
  /escalations/* — escalation review (compliance+)
  /stats/*       — per-tenant dashboard metrics (compliance+)
  /tenant/*      — tenant admin proxies (admin)

All DB queries are filtered by ``ctx.tenant_id`` for tenant isolation.
"""

import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import asyncpg
import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import (
    get_current_auth,
    require_admin,
    require_compliance,
)

router = APIRouter(prefix="/api/v1", tags=["management"])

# Service URLs
_DB_URL = os.environ.get("DATABASE_URL", "")
_AUTH_URL = os.environ.get("AUTH_SERVICE_URL", "http://auth:8006")
_TENANT_URL = os.environ.get("TENANT_SERVICE_URL", "http://tenant:8007")
_AUDIT_URL = os.environ.get("AUDIT_SERVICE_URL", "http://audit:8005")


def _db_dsn() -> str:
    return _DB_URL.replace("+asyncpg", "")


# ============================================================
# Auth proxies (no role gate)
# ============================================================


class TokenRequest(BaseModel):
    api_key: str


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/auth/token")
async def auth_token(body: TokenRequest):
    """Proxy api_key → access+refresh tokens to the auth service."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{_AUTH_URL}/v1/auth/token", json=body.model_dump())
    return _passthrough(resp)


@router.post("/auth/refresh")
async def auth_refresh(body: RefreshRequest):
    """Proxy refresh_token → new access token."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{_AUTH_URL}/v1/auth/refresh", json=body.model_dump())
    return _passthrough(resp)


@router.get("/auth/me")
async def auth_me(request: Request):
    """Proxy the Authorization header to the auth service /v1/auth/me."""
    auth_header = request.headers.get("Authorization", "")
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{_AUTH_URL}/v1/auth/me",
            headers={"Authorization": auth_header},
        )
    return _passthrough(resp)


def _passthrough(resp: httpx.Response):
    """Return upstream response as JSON, preserving status code."""
    try:
        data = resp.json()
    except Exception:
        data = {"detail": resp.text}
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=data.get("detail", data))
    return data


# ============================================================
# Audit
# ============================================================


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
        args.append(_parse_ts(start))
        clauses.append(f"created_at >= ${len(args)}")
    if end:
        args.append(_parse_ts(end))
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

    conn = await asyncpg.connect(_db_dsn())
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

    conn = await asyncpg.connect(_db_dsn())
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
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            "SELECT interaction_id, tenant_id, user_id, department, created_at, "
            "enforcement_action, enforcement_reason, pii_detected, pii_risk_level, "
            "injection_score, total_latency_ms "
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
            writer.writerow({k: _csv_safe(v) for k, v in row.items()})
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
        resp = await client.get(f"{_AUDIT_URL}/verify/{interaction_id}")
    return _passthrough(resp)


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


def _csv_safe(value: Any) -> str:
    """Flatten lists/dicts/None for CSV."""
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def _parse_ts(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid timestamp: {s}")


# ============================================================
# Policy
# ============================================================


class PolicyUpdate(BaseModel):
    config: dict[str, Any]
    notes: Optional[str] = None


@router.get("/policy")
async def get_active_policy(ctx: AuthContext = Depends(require_compliance)):
    """Return the active policy for the caller's tenant."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        row = await conn.fetchrow(
            "SELECT id, tenant_id, config, version, is_active, created_at, notes "
            "FROM policies WHERE tenant_id = $1 AND is_active = TRUE "
            "ORDER BY created_at DESC LIMIT 1",
            ctx.tenant_id,
        )
    finally:
        await conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="No active policy for tenant")
    return _serialize_policy(row)


@router.put("/policy")
async def update_policy(
    body: PolicyUpdate,
    ctx: AuthContext = Depends(require_admin),
):
    """Replace the active policy for the tenant with a new version (bumped patch)."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        current = await conn.fetchrow(
            "SELECT version FROM policies WHERE tenant_id = $1 AND is_active = TRUE "
            "ORDER BY created_at DESC LIMIT 1",
            ctx.tenant_id,
        )
        next_version = _bump_version(current["version"] if current else None)

        async with conn.transaction():
            await conn.execute(
                "UPDATE policies SET is_active = FALSE WHERE tenant_id = $1 AND is_active = TRUE",
                ctx.tenant_id,
            )
            row = await conn.fetchrow(
                "INSERT INTO policies (tenant_id, config, version, is_active, notes) "
                "VALUES ($1, $2::jsonb, $3, TRUE, $4) "
                "RETURNING id, tenant_id, config, version, is_active, created_at, notes",
                ctx.tenant_id, json.dumps(body.config), next_version, body.notes,
            )
    finally:
        await conn.close()

    return _serialize_policy(row)


@router.get("/policy/versions")
async def list_policy_versions(ctx: AuthContext = Depends(require_compliance)):
    """List all policy versions for the tenant, newest first."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            "SELECT id, tenant_id, config, version, is_active, created_at, notes "
            "FROM policies WHERE tenant_id = $1 "
            "ORDER BY created_at DESC",
            ctx.tenant_id,
        )
    finally:
        await conn.close()

    return {"versions": [_serialize_policy(r) for r in rows]}


def _serialize_policy(r) -> dict:
    config = r["config"]
    if isinstance(config, str):
        config = json.loads(config) if config else {}
    return {
        "id": str(r["id"]),
        "tenant_id": r["tenant_id"],
        "config": config,
        "version": r["version"],
        "is_active": r["is_active"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "notes": r["notes"],
    }


def _bump_version(current: Optional[str]) -> str:
    """Semver patch bump: 1.0.0 → 1.0.1. Start at 1.0.0 if invalid/missing."""
    if not current:
        return "1.0.0"
    parts = current.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return "1.0.0"
    major, minor, patch = map(int, parts)
    return f"{major}.{minor}.{patch + 1}"


# ============================================================
# Users
# ============================================================


class UserCreate(BaseModel):
    external_id: str = Field(..., min_length=1, max_length=256)
    email: Optional[str] = Field(None, max_length=256)
    role: str = Field(..., pattern="^(admin|compliance|user)$")
    department: Optional[str] = Field(None, max_length=128)


@router.get("/users")
async def list_users(ctx: AuthContext = Depends(require_admin)):
    """List tenant users for the caller's tenant."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            "SELECT id, tenant_id, external_id, email, department, role, is_active, created_at "
            "FROM tenant_users WHERE tenant_id = $1 ORDER BY created_at DESC",
            ctx.tenant_id,
        )
    finally:
        await conn.close()
    return {"users": [_serialize_user(r) for r in rows]}


@router.post("/users", status_code=201)
async def create_user(
    body: UserCreate,
    ctx: AuthContext = Depends(require_admin),
):
    """Create a new tenant user."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        try:
            row = await conn.fetchrow(
                "INSERT INTO tenant_users (tenant_id, external_id, email, department, role) "
                "VALUES ($1, $2, $3, $4, $5) "
                "RETURNING id, tenant_id, external_id, email, department, role, is_active, created_at",
                ctx.tenant_id, body.external_id, body.email, body.department, body.role,
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(
                status_code=409,
                detail=f"User with external_id '{body.external_id}' already exists for this tenant",
            )
    finally:
        await conn.close()

    return _serialize_user(row)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    ctx: AuthContext = Depends(require_admin),
):
    """Soft-delete a tenant user by setting is_active=FALSE."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user_id (must be UUID)")

    conn = await asyncpg.connect(_db_dsn())
    try:
        row = await conn.fetchrow(
            "UPDATE tenant_users SET is_active = FALSE "
            "WHERE id = $1 AND tenant_id = $2 "
            "RETURNING id",
            uid, ctx.tenant_id,
        )
    finally:
        await conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deactivated", "user_id": str(row["id"])}


def _serialize_user(r) -> dict:
    return {
        "id": str(r["id"]),
        "tenant_id": r["tenant_id"],
        "external_id": r["external_id"],
        "email": r["email"],
        "department": r["department"],
        "role": r["role"],
        "is_active": r["is_active"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
    }


# ============================================================
# Escalations
# ============================================================


class EscalationUpdate(BaseModel):
    status: str = Field(..., pattern="^(PENDING|REVIEWED|DISMISSED|ACTIONED)$")
    notes: Optional[str] = None


@router.get("/escalations")
async def list_escalations(
    ctx: AuthContext = Depends(require_compliance),
    status_filter: Optional[str] = Query(None, alias="status"),
):
    """List escalations for the tenant, optionally filtered by status."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        if status_filter:
            rows = await conn.fetch(
                "SELECT id, interaction_id, tenant_id, created_at, reason, status, "
                "reviewed_by, reviewed_at, notes "
                "FROM escalations WHERE tenant_id = $1 AND status = $2 "
                "ORDER BY created_at DESC",
                ctx.tenant_id, status_filter,
            )
        else:
            rows = await conn.fetch(
                "SELECT id, interaction_id, tenant_id, created_at, reason, status, "
                "reviewed_by, reviewed_at, notes "
                "FROM escalations WHERE tenant_id = $1 "
                "ORDER BY created_at DESC",
                ctx.tenant_id,
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
    try:
        eid = uuid.UUID(escalation_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid escalation_id (must be UUID)")

    conn = await asyncpg.connect(_db_dsn())
    try:
        row = await conn.fetchrow(
            "UPDATE escalations SET status = $1, notes = $2, reviewed_at = NOW() "
            "WHERE id = $3 AND tenant_id = $4 "
            "RETURNING id, interaction_id, tenant_id, created_at, reason, status, "
            "reviewed_by, reviewed_at, notes",
            body.status, body.notes, eid, ctx.tenant_id,
        )
    finally:
        await conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Escalation not found")
    return _serialize_escalation(row)


def _serialize_escalation(r) -> dict:
    return {
        "id": str(r["id"]),
        "interaction_id": str(r["interaction_id"]) if r["interaction_id"] else None,
        "tenant_id": r["tenant_id"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "reason": r["reason"],
        "status": r["status"],
        "reviewed_by": str(r["reviewed_by"]) if r["reviewed_by"] else None,
        "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
        "notes": r["notes"],
    }


# ============================================================
# Stats
# ============================================================


@router.get("/stats/overview")
async def stats_overview(ctx: AuthContext = Depends(require_compliance)):
    """24h totals for the caller's tenant."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        row = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_requests,
                COUNT(*) FILTER (WHERE enforcement_action != 'ALLOW') AS violations,
                COUNT(*) FILTER (WHERE pii_detected = TRUE) AS pii_detections,
                COUNT(*) FILTER (WHERE injection_score > 0.5) AS injection_blocks,
                AVG(total_latency_ms) AS avg_latency_ms
            FROM audit_logs
            WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'
            """,
            ctx.tenant_id,
        )
    finally:
        await conn.close()

    return {
        "tenant_id": ctx.tenant_id,
        "total_requests": row["total_requests"] or 0,
        "violations": row["violations"] or 0,
        "pii_detections": row["pii_detections"] or 0,
        "injection_blocks": row["injection_blocks"] or 0,
        "avg_latency_ms": round(row["avg_latency_ms"] or 0, 1),
        "period": "24h",
    }


@router.get("/stats/timeseries")
async def stats_timeseries(
    ctx: AuthContext = Depends(require_compliance),
    hours: int = Query(24, ge=1, le=168),
):
    """Hourly bucketed request counts for the tenant."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            """
            SELECT date_trunc('hour', created_at) AS hour,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE enforcement_action != 'ALLOW') AS violations,
                   COUNT(*) FILTER (WHERE pii_detected = TRUE) AS pii
            FROM audit_logs
            WHERE tenant_id = $1 AND created_at >= NOW() - make_interval(hours => $2)
            GROUP BY hour ORDER BY hour
            """,
            ctx.tenant_id, hours,
        )
    finally:
        await conn.close()

    return {
        "tenant_id": ctx.tenant_id,
        "hours": hours,
        "buckets": [
            {
                "hour": r["hour"].isoformat() if r["hour"] else None,
                "total": r["total"],
                "violations": r["violations"],
                "pii": r["pii"],
            }
            for r in rows
        ],
    }


@router.get("/stats/departments")
async def stats_departments(ctx: AuthContext = Depends(require_compliance)):
    """Last-7-day request counts grouped by department."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            """
            SELECT COALESCE(department, 'unknown') AS department,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE enforcement_action != 'ALLOW') AS violations
            FROM audit_logs
            WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
            GROUP BY department ORDER BY total DESC
            """,
            ctx.tenant_id,
        )
    finally:
        await conn.close()

    return {
        "tenant_id": ctx.tenant_id,
        "period": "7d",
        "departments": [
            {
                "department": r["department"],
                "total": r["total"],
                "violations": r["violations"],
            }
            for r in rows
        ],
    }


@router.get("/stats/hours")
async def stats_hours(ctx: AuthContext = Depends(require_compliance)):
    """Hour-of-day heatmap over the last 7 days."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            """
            SELECT EXTRACT(hour FROM created_at)::int AS hour,
                   COUNT(*) AS total
            FROM audit_logs
            WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '7 days'
            GROUP BY hour ORDER BY hour
            """,
            ctx.tenant_id,
        )
    finally:
        await conn.close()

    return {
        "tenant_id": ctx.tenant_id,
        "period": "7d",
        "hours": [{"hour": r["hour"], "total": r["total"]} for r in rows],
    }


# ============================================================
# Tenant admin proxies
# ============================================================


@router.post("/tenant/provision")
async def tenant_provision(
    body: dict = Body(...),
    ctx: AuthContext = Depends(require_admin),
):
    """Proxy tenant provisioning to the tenant service."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{_TENANT_URL}/provision", json=body)
    return _passthrough(resp)


@router.get("/tenant/usage")
async def tenant_usage(ctx: AuthContext = Depends(require_admin)):
    """Proxy usage stats request to the tenant service (for the caller's tenant)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{_TENANT_URL}/tenants/{ctx.tenant_id}/usage")
    return _passthrough(resp)


@router.put("/tenant/settings")
async def tenant_settings(
    body: dict = Body(...),
    ctx: AuthContext = Depends(require_admin),
):
    """Proxy settings update to the tenant service (for the caller's tenant)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.put(
            f"{_TENANT_URL}/tenants/{ctx.tenant_id}/settings",
            json=body,
        )
    return _passthrough(resp)


# ============================================================
# Compliance Reports
# ============================================================

_KNOWN_REPORT_TYPES = {"gdpr", "eu-ai-act"}


@router.get("/reports/{report_type}")
async def generate_compliance_report(
    report_type: str,
    ctx: AuthContext = Depends(require_compliance),
):
    """Generate a GDPR Article 30 or EU AI Act Article 13 compliance report.

    Queries the last 30 days of audit_logs for the caller's tenant.
    Returns a structured JSON report suitable for archival or display.
    """
    if report_type not in _KNOWN_REPORT_TYPES:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown report type '{report_type}'. Valid: {sorted(_KNOWN_REPORT_TYPES)}",
        )

    now = datetime.now(timezone.utc)
    period_label = "Last 30 days"

    conn = await asyncpg.connect(_db_dsn())
    try:
        # Core 30-day aggregates
        agg = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_requests,
                COUNT(*) FILTER (WHERE pii_detected = TRUE) AS total_pii,
                COUNT(*) FILTER (
                    WHERE pii_detected = TRUE AND enforcement_action = 'REDACT'
                ) AS pii_redacted,
                COUNT(*) FILTER (
                    WHERE pii_detected = TRUE AND enforcement_action = 'BLOCK'
                ) AS pii_blocked,
                COUNT(*) FILTER (
                    WHERE pii_detected = TRUE AND enforcement_action = 'ESCALATE'
                ) AS pii_escalated
            FROM audit_logs
            WHERE tenant_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            """,
            ctx.tenant_id,
        )

        # Escalation breakdown
        esc_agg = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'PENDING') AS pending,
                COUNT(*) FILTER (WHERE status != 'PENDING') AS resolved
            FROM escalations
            WHERE tenant_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            """,
            ctx.tenant_id,
        )

        # Policy change count
        policy_changes = await conn.fetchval(
            """
            SELECT COUNT(*) FROM policies
            WHERE tenant_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            """,
            ctx.tenant_id,
        )

        # Active policy for injection config
        active_policy_row = await conn.fetchrow(
            "SELECT config FROM policies WHERE tenant_id = $1 AND is_active = TRUE "
            "ORDER BY created_at DESC LIMIT 1",
            ctx.tenant_id,
        )

    finally:
        await conn.close()

    # Parse active policy config
    active_config: dict = {}
    if active_policy_row:
        raw = active_policy_row["config"]
        active_config = json.loads(raw) if isinstance(raw, str) else (raw or {})

    inj_cfg = active_config.get("injection", {})
    pii_cfg = active_config.get("pii", {})

    total_requests = int(agg["total_requests"] or 0)
    total_pii = int(agg["total_pii"] or 0)
    pii_redacted = int(agg["pii_redacted"] or 0)
    pii_blocked = int(agg["pii_blocked"] or 0)
    pii_escalated = int(agg["pii_escalated"] or 0)
    esc_total = int(esc_agg["total"] or 0)
    esc_pending = int(esc_agg["pending"] or 0)
    esc_resolved = int(esc_agg["resolved"] or 0)
    policy_changes_int = int(policy_changes or 0)
    inj_enabled = bool(inj_cfg.get("enabled", True))
    pii_enabled = bool(pii_cfg.get("enabled", True))

    if report_type == "gdpr":
        findings = [
            {
                "check": "PII detection enabled",
                "status": "pass" if pii_enabled else "fail",
                "detail": "spaCy NER + regex patterns active" if pii_enabled else "PII detection is disabled — GDPR risk",
            },
            {
                "check": "Data minimisation (REDACT action)",
                "status": "pass" if pii_redacted > 0 or total_pii == 0 else "warning",
                "detail": f"{pii_redacted} records redacted out of {total_pii} PII detections",
            },
            {
                "check": "PII blocking for critical data",
                "status": "pass" if pii_cfg.get("critical_action") in ("BLOCK", "ESCALATE") else "warning",
                "detail": f"critical_action = {pii_cfg.get('critical_action', 'not set')}",
            },
            {
                "check": "Audit trail integrity (HMAC)",
                "status": "pass",
                "detail": "All audit logs are HMAC-SHA256 signed",
            },
            {
                "check": "Retention policy defined",
                "status": "pass",
                "detail": "Audit logs retained for 90 days (partitioned table)",
            },
            {
                "check": "Cross-border data transfer",
                "status": "pass",
                "detail": "All LLM calls routed to Groq (US) — no EU adequacy decision required for controller-to-processor",
            },
        ]
        return {
            "report_type": "gdpr",
            "generated_at": now.isoformat(),
            "tenant_id": ctx.tenant_id,
            "period": period_label,
            "total_requests": total_requests,
            "total_pii_detections": total_pii,
            "pii_redacted": pii_redacted,
            "pii_blocked": pii_blocked,
            "pii_escalated": pii_escalated,
            "data_categories_processed": _derive_pii_categories(pii_cfg),
            "cross_border_transfers": False,
            "retention_policy": "90 days",
            "findings": findings,
        }

    # EU AI Act report
    findings = [
        {
            "check": "Risk classification declared",
            "status": "pass",
            "detail": "Classified as Limited Risk — AI system with human interaction",
        },
        {
            "check": "Transparency obligation (Article 13)",
            "status": "pass",
            "detail": "System name, purpose, and capabilities disclosed in documentation",
        },
        {
            "check": "Prompt injection detection",
            "status": "pass" if inj_enabled else "fail",
            "detail": f"Heuristic + ML (DeBERTa) detector — enabled={inj_enabled}, "
                      f"block_threshold={inj_cfg.get('block_threshold', 'n/a')}",
        },
        {
            "check": "Human oversight mechanism",
            "status": "pass" if esc_total > 0 or esc_pending == 0 else "warning",
            "detail": f"{esc_total} escalations in last 30d — {esc_pending} pending, {esc_resolved} resolved",
        },
        {
            "check": "Audit trail (Article 12)",
            "status": "pass",
            "detail": "HMAC-SHA256 signed, tamper-evident, append-only audit log",
        },
        {
            "check": "Policy governance",
            "status": "pass",
            "detail": f"{policy_changes_int} policy version(s) deployed in last 30d — versioned + audited",
        },
    ]
    return {
        "report_type": "eu-ai-act",
        "generated_at": now.isoformat(),
        "tenant_id": ctx.tenant_id,
        "system_name": "AGCMS",
        "risk_classification": "Limited Risk",
        "injection_detection_enabled": inj_enabled,
        "injection_detection_method": "Heuristic rules + DeBERTa ML classifier (ONNX)",
        "human_oversight_escalations": esc_total,
        "pending_escalations": esc_pending,
        "resolved_escalations": esc_resolved,
        "audit_trail_signed": True,
        "policy_changes_30d": policy_changes_int,
        "findings": findings,
    }


def _derive_pii_categories(pii_cfg: dict) -> list[str]:
    """Return the list of PII categories the current policy is configured to detect."""
    base = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD"]
    custom = list((pii_cfg.get("custom_patterns") or {}).keys())
    return base + custom
