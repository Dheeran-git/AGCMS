"""GDPR Article 17 — purge workflow REST API.

Implements the two-admin approval flow and execution entrypoints:

* ``POST /api/v1/gdpr/purge-requests``               (admin) — file a request
* ``GET  /api/v1/gdpr/purge-requests``               (admin) — list all
* ``GET  /api/v1/gdpr/purge-requests/{id}``          (admin) — detail
* ``POST /api/v1/gdpr/purge-requests/{id}/approve``  (admin, different from requester)
* ``POST /api/v1/gdpr/purge-requests/{id}/reject``   (admin, different from requester)
* ``POST /api/v1/gdpr/purge-requests/{id}/execute``  (admin) — tombstone rows

Design constraints (see database/migrations/009_gdpr_purge.sql for full rationale):
  - Pending requests auto-expire 24h after filing.
  - Approver MUST differ from requester (enforced in code AND via a CHECK
    constraint on the column combination).
  - Executor does not delete rows. It overwrites subject-PII columns on each
    matching audit row with ``[REDACTED]`` and binds the redaction to the
    approval chain via ``redaction_records`` rows that are themselves
    HMAC-signed with the active audit row key.
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import asyncpg
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_admin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/gdpr", tags=["gdpr"])

_DB_URL = os.environ.get("DATABASE_URL", "")
_APPROVAL_WINDOW_HOURS = 24


def _dsn() -> str:
    return _DB_URL.replace("+asyncpg", "")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class PurgeRequestCreate(BaseModel):
    subject_user_id: str = Field(..., min_length=1, max_length=256)
    reason: str = Field(..., min_length=10, max_length=2000)


class PurgeDecision(BaseModel):
    note: Optional[str] = Field(default=None, max_length=2000)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _resolve_admin_uuid(conn: asyncpg.Connection, ctx: AuthContext) -> uuid.UUID:
    """Map the caller's JWT identity to a ``tenant_users.id`` UUID.

    The JWT claim ``user_id`` is ``tenant_users.external_id``; we need the
    UUID for foreign-key fields on ``gdpr_purge_requests``.
    """
    row = await conn.fetchrow(
        "SELECT id FROM tenant_users "
        "WHERE tenant_id = $1 AND external_id = $2 AND is_active = TRUE",
        ctx.tenant_id,
        ctx.user_id,
    )
    if row is None:
        raise HTTPException(
            status_code=403,
            detail="Caller has no active tenant_user record; cannot file GDPR action",
        )
    return row["id"]


async def _expire_stale_requests(conn: asyncpg.Connection, tenant_id: str) -> None:
    """Flip any ``pending`` request past its 24h window to ``expired``.

    Runs on every list/get/approve call so stale state does not linger.
    """
    now = datetime.now(timezone.utc)
    await conn.execute(
        "UPDATE gdpr_purge_requests "
        "SET state = 'expired' "
        "WHERE tenant_id = $1 AND state = 'pending' AND approval_expires_at < $2",
        tenant_id, now,
    )


def _serialize(r) -> dict:
    return {
        "id": str(r["id"]),
        "tenant_id": r["tenant_id"],
        "subject_user_id": r["subject_user_id"],
        "subject_tenant_user_id": str(r["subject_tenant_user_id"]) if r["subject_tenant_user_id"] else None,
        "requested_by": str(r["requested_by"]),
        "requested_at": r["requested_at"].isoformat() if r["requested_at"] else None,
        "approval_expires_at": r["approval_expires_at"].isoformat() if r["approval_expires_at"] else None,
        "approved_by": str(r["approved_by"]) if r["approved_by"] else None,
        "approved_at": r["approved_at"].isoformat() if r["approved_at"] else None,
        "rejected_by": str(r["rejected_by"]) if r["rejected_by"] else None,
        "rejected_at": r["rejected_at"].isoformat() if r["rejected_at"] else None,
        "executed_at": r["executed_at"].isoformat() if r["executed_at"] else None,
        "rows_redacted": r["rows_redacted"],
        "state": r["state"],
        "reason": r["reason"],
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/purge-requests", status_code=201)
async def create_purge_request(
    body: PurgeRequestCreate,
    ctx: AuthContext = Depends(require_admin),
):
    """Admin files a GDPR Art. 17 purge request for a data subject."""
    conn = await asyncpg.connect(_dsn())
    try:
        requester_uuid = await _resolve_admin_uuid(conn, ctx)

        # Try to resolve the subject to a tenant_users row for reference.
        subject_row = await conn.fetchrow(
            "SELECT id FROM tenant_users "
            "WHERE tenant_id = $1 AND external_id = $2",
            ctx.tenant_id, body.subject_user_id,
        )
        subject_uuid = subject_row["id"] if subject_row else None

        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=_APPROVAL_WINDOW_HOURS)

        row = await conn.fetchrow(
            "INSERT INTO gdpr_purge_requests ("
            "  tenant_id, subject_user_id, subject_tenant_user_id, "
            "  requested_by, requested_at, approval_expires_at, reason"
            ") VALUES ($1, $2, $3, $4, $5, $6, $7) "
            "RETURNING *",
            ctx.tenant_id, body.subject_user_id, subject_uuid,
            requester_uuid, now, expires, body.reason,
        )
        log.info(
            "gdpr.purge_request.created tenant=%s subject=%s requester=%s id=%s",
            ctx.tenant_id, body.subject_user_id, requester_uuid, row["id"],
        )
        return _serialize(row)
    finally:
        await conn.close()


@router.get("/purge-requests")
async def list_purge_requests(
    ctx: AuthContext = Depends(require_admin),
):
    conn = await asyncpg.connect(_dsn())
    try:
        await _expire_stale_requests(conn, ctx.tenant_id)
        rows = await conn.fetch(
            "SELECT * FROM gdpr_purge_requests "
            "WHERE tenant_id = $1 "
            "ORDER BY requested_at DESC LIMIT 200",
            ctx.tenant_id,
        )
        return {"requests": [_serialize(r) for r in rows]}
    finally:
        await conn.close()


@router.get("/purge-requests/{request_id}")
async def get_purge_request(
    request_id: str,
    ctx: AuthContext = Depends(require_admin),
):
    try:
        rid = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request_id")

    conn = await asyncpg.connect(_dsn())
    try:
        await _expire_stale_requests(conn, ctx.tenant_id)
        row = await conn.fetchrow(
            "SELECT * FROM gdpr_purge_requests WHERE id = $1 AND tenant_id = $2",
            rid, ctx.tenant_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Purge request not found")
        return _serialize(row)
    finally:
        await conn.close()


@router.post("/purge-requests/{request_id}/approve")
async def approve_purge_request(
    request_id: str,
    body: PurgeDecision = Body(default=PurgeDecision()),
    ctx: AuthContext = Depends(require_admin),
):
    try:
        rid = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request_id")

    conn = await asyncpg.connect(_dsn())
    try:
        await _expire_stale_requests(conn, ctx.tenant_id)
        approver_uuid = await _resolve_admin_uuid(conn, ctx)

        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT * FROM gdpr_purge_requests "
                "WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
                rid, ctx.tenant_id,
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Purge request not found")
            if row["state"] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail=f"Cannot approve a request in state '{row['state']}'",
                )
            if row["requested_by"] == approver_uuid:
                raise HTTPException(
                    status_code=403,
                    detail="Approver must differ from requester (two-admin rule)",
                )
            if row["approval_expires_at"] < datetime.now(timezone.utc):
                await conn.execute(
                    "UPDATE gdpr_purge_requests SET state = 'expired' WHERE id = $1",
                    rid,
                )
                raise HTTPException(
                    status_code=409,
                    detail="Approval window has expired (24h)",
                )

            now = datetime.now(timezone.utc)
            updated = await conn.fetchrow(
                "UPDATE gdpr_purge_requests "
                "SET state = 'approved', approved_by = $1, approved_at = $2 "
                "WHERE id = $3 "
                "RETURNING *",
                approver_uuid, now, rid,
            )

            # Stamp the approval signature using the audit key. We import
            # here to keep the gdpr module importable without the audit
            # keys registry being loaded (useful for tests).
            try:
                from agcms.audit.redaction import sign_purge_approval

                sig = sign_purge_approval(dict(updated))
                await conn.execute(
                    "UPDATE gdpr_purge_requests SET approval_signature = $1 WHERE id = $2",
                    sig, rid,
                )
                updated = await conn.fetchrow(
                    "SELECT * FROM gdpr_purge_requests WHERE id = $1", rid,
                )
            except Exception as exc:  # pragma: no cover - keys unavailable in some envs
                log.warning(
                    "gdpr.approval.sign_failed id=%s err=%s",
                    rid, exc,
                )

        log.info(
            "gdpr.purge_request.approved tenant=%s id=%s approver=%s",
            ctx.tenant_id, rid, approver_uuid,
        )
        return _serialize(updated)
    finally:
        await conn.close()


@router.post("/purge-requests/{request_id}/reject")
async def reject_purge_request(
    request_id: str,
    body: PurgeDecision = Body(default=PurgeDecision()),
    ctx: AuthContext = Depends(require_admin),
):
    try:
        rid = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request_id")

    conn = await asyncpg.connect(_dsn())
    try:
        rejecter_uuid = await _resolve_admin_uuid(conn, ctx)

        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT state, requested_by FROM gdpr_purge_requests "
                "WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
                rid, ctx.tenant_id,
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Purge request not found")
            if row["state"] != "pending":
                raise HTTPException(
                    status_code=409,
                    detail=f"Cannot reject a request in state '{row['state']}'",
                )
            if row["requested_by"] == rejecter_uuid:
                raise HTTPException(
                    status_code=403,
                    detail="Rejecter must differ from requester",
                )

            updated = await conn.fetchrow(
                "UPDATE gdpr_purge_requests "
                "SET state = 'rejected', rejected_by = $1, rejected_at = $2 "
                "WHERE id = $3 "
                "RETURNING *",
                rejecter_uuid, datetime.now(timezone.utc), rid,
            )

        log.info(
            "gdpr.purge_request.rejected tenant=%s id=%s rejecter=%s",
            ctx.tenant_id, rid, rejecter_uuid,
        )
        return _serialize(updated)
    finally:
        await conn.close()


@router.post("/purge-requests/{request_id}/execute")
async def execute_purge_request(
    request_id: str,
    ctx: AuthContext = Depends(require_admin),
):
    """Tombstone audit-log PII for an approved request.

    Delegates the cryptographic work to ``agcms.audit.redaction``. State
    transitions to ``executed`` on success; ``rows_redacted`` is written
    with the count from the executor.
    """
    try:
        rid = uuid.UUID(request_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request_id")

    conn = await asyncpg.connect(_dsn())
    try:
        row = await conn.fetchrow(
            "SELECT state FROM gdpr_purge_requests "
            "WHERE id = $1 AND tenant_id = $2",
            rid, ctx.tenant_id,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Purge request not found")
        if row["state"] != "approved":
            raise HTTPException(
                status_code=409,
                detail=f"Cannot execute a request in state '{row['state']}' (must be 'approved')",
            )

        # Run the redaction executor. It lives in agcms-audit and opens
        # its own connection/transaction.
        from agcms.audit.redaction import execute_purge

        try:
            result = await execute_purge(str(rid))
        except (LookupError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc))

        now = datetime.now(timezone.utc)
        updated = await conn.fetchrow(
            "UPDATE gdpr_purge_requests "
            "SET state = 'executed', executed_at = $1, rows_redacted = $2 "
            "WHERE id = $3 "
            "RETURNING *",
            now, result.rows_redacted, rid,
        )
        log.info(
            "gdpr.purge_request.executed tenant=%s id=%s rows=%d",
            ctx.tenant_id, rid, result.rows_redacted,
        )
        return {
            **_serialize(updated),
            "redaction_record_ids": result.redaction_record_ids,
        }
    finally:
        await conn.close()
