"""Tenant policy read / update / version history."""

import json
from typing import Any, Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_admin, require_compliance
from agcms.gateway.api.common import db_dsn

router = APIRouter()


class PolicyUpdate(BaseModel):
    config: dict[str, Any]
    notes: Optional[str] = None


@router.get("/policy")
async def get_active_policy(ctx: AuthContext = Depends(require_compliance)):
    """Return the active policy for the caller's tenant."""
    conn = await asyncpg.connect(db_dsn())
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
    conn = await asyncpg.connect(db_dsn())
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
    conn = await asyncpg.connect(db_dsn())
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
    """Semver patch bump: 1.0.0 -> 1.0.1. Start at 1.0.0 if invalid/missing."""
    if not current:
        return "1.0.0"
    parts = current.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return "1.0.0"
    major, minor, patch = map(int, parts)
    return f"{major}.{minor}.{patch + 1}"
