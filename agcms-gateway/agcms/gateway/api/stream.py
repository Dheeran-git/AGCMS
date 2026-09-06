"""Server-Sent Events feed of new violations."""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import asyncpg
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_compliance
from agcms.gateway.api.common import db_dsn

router = APIRouter()


_SSE_POLL_INTERVAL_SECONDS = 2.0
_SSE_HEARTBEAT_SECONDS = 15.0


def _serialize_violation_row(r: Any) -> dict:
    return {
        "interaction_id": str(r["interaction_id"]),
        "tenant_id": r["tenant_id"],
        "user_id": r["user_id"],
        "department": r["department"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        "action": r["enforcement_action"],
        "reason": r["enforcement_reason"],
        "pii_detected": r["pii_detected"],
        "pii_entity_types": r["pii_entity_types"] or [],
        "pii_risk_level": r["pii_risk_level"],
        "injection_score": float(r["injection_score"]) if r["injection_score"] is not None else None,
        "injection_type": r["injection_type"],
        "response_violated": r["response_violated"],
        "latency_ms": r["total_latency_ms"],
    }


_VIOLATION_COLS = (
    "interaction_id, tenant_id, user_id, department, created_at, "
    "enforcement_action, enforcement_reason, pii_detected, pii_entity_types, "
    "pii_risk_level, injection_score, injection_type, response_violated, "
    "total_latency_ms"
)


@router.get("/stream/violations")
async def stream_violations(
    request: Request,
    ctx: AuthContext = Depends(require_compliance),
):
    """Push new violations as Server-Sent Events scoped to the caller's tenant.

    Each event is ``data: <json>\\n\\n`` where ``<json>`` is the same shape
    as a row from ``GET /api/dashboard/violations``. The feed:
      • emits a single ``snapshot`` event with the most recent 20 rows on
        connect so the dashboard renders immediately without a separate
        REST call;
      • then emits ``violation`` events for each new row as it lands;
      • emits ``: keepalive`` comments every 15s so proxies don't drop
        the connection during quiet periods.
    """

    async def event_gen():
        conn = await asyncpg.connect(db_dsn())
        try:
            # Snapshot — recent violations on initial connect.
            snapshot_rows = await conn.fetch(
                f"SELECT {_VIOLATION_COLS} FROM audit_logs "
                "WHERE tenant_id = $1 AND enforcement_action != 'ALLOW' "
                "ORDER BY created_at DESC LIMIT 20",
                ctx.tenant_id,
            )
            payload = json.dumps(
                [_serialize_violation_row(r) for r in snapshot_rows]
            )
            yield f"event: snapshot\ndata: {payload}\n\n"

            # Anchor on the newest row's timestamp (or now()) so the live
            # tail picks up every violation that lands after this point.
            since = (
                snapshot_rows[0]["created_at"]
                if snapshot_rows
                else datetime.now(timezone.utc)
            )

            last_heartbeat = datetime.now(timezone.utc)
            while True:
                if await request.is_disconnected():
                    break
                new_rows = await conn.fetch(
                    f"SELECT {_VIOLATION_COLS} FROM audit_logs "
                    "WHERE tenant_id = $1 AND enforcement_action != 'ALLOW' "
                    "AND created_at > $2 ORDER BY created_at ASC LIMIT 50",
                    ctx.tenant_id,
                    since,
                )
                for r in new_rows:
                    since = r["created_at"]
                    yield (
                        "event: violation\n"
                        f"data: {json.dumps(_serialize_violation_row(r))}\n\n"
                    )

                now = datetime.now(timezone.utc)
                if (now - last_heartbeat).total_seconds() >= _SSE_HEARTBEAT_SECONDS:
                    yield ": keepalive\n\n"
                    last_heartbeat = now

                await asyncio.sleep(_SSE_POLL_INTERVAL_SECONDS)
        finally:
            await conn.close()

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Disable buffering at any reverse proxy in the path (nginx).
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
