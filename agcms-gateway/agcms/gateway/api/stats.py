"""Per-tenant dashboard metrics."""

import asyncpg
from fastapi import APIRouter, Depends, Query

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_compliance
from agcms.gateway.api.common import db_dsn

router = APIRouter()


@router.get("/stats/overview")
async def stats_overview(ctx: AuthContext = Depends(require_compliance)):
    """24h totals for the caller's tenant."""
    conn = await asyncpg.connect(db_dsn())
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
    conn = await asyncpg.connect(db_dsn())
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
    conn = await asyncpg.connect(db_dsn())
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
    conn = await asyncpg.connect(db_dsn())
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
