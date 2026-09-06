"""Tenant user CRUD (admin)."""

import uuid
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_admin
from agcms.gateway.api.common import db_dsn

router = APIRouter()


class UserCreate(BaseModel):
    external_id: str = Field(..., min_length=1, max_length=256)
    email: Optional[str] = Field(None, max_length=256)
    role: str = Field(..., pattern="^(admin|compliance|user)$")
    department: Optional[str] = Field(None, max_length=128)


@router.get("/users")
async def list_users(ctx: AuthContext = Depends(require_admin)):
    """List tenant users for the caller's tenant."""
    conn = await asyncpg.connect(db_dsn())
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
    conn = await asyncpg.connect(db_dsn())
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

    conn = await asyncpg.connect(db_dsn())
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
