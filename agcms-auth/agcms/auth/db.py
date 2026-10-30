"""Database helpers for the auth service.

Looks up a tenant by SHA-256 hash of the provided API key,
then fetches the admin user for that tenant.
Uses asyncpg for async PostgreSQL access.
"""

import hashlib
import os
from typing import Optional

import asyncpg

_DATABASE_URL = os.environ.get("DATABASE_URL", "")


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


async def get_tenant_by_api_key(api_key: str) -> Optional[dict]:
    """Return tenant row dict if the API key matches, else None."""
    key_hash = _hash_key(api_key)
    conn = await asyncpg.connect(_DATABASE_URL)
    try:
        row = await conn.fetchrow(
            "SELECT id, name, plan, admin_email, is_active "
            "FROM tenants WHERE api_key_hash = $1",
            key_hash,
        )
    finally:
        await conn.close()

    if row is None or not row["is_active"]:
        return None
    return dict(row)


async def get_admin_user(tenant_id: str) -> Optional[dict]:
    """Return the active admin tenant_user row, or None if it or the tenant is inactive."""
    conn = await asyncpg.connect(_DATABASE_URL)
    try:
        row = await conn.fetchrow(
            "SELECT u.id, u.external_id, u.email, u.role "
            "FROM tenant_users u JOIN tenants t ON t.id = u.tenant_id "
            "WHERE u.tenant_id = $1 AND u.role = 'admin' AND u.is_active = TRUE "
            "AND t.is_active = TRUE "
            "LIMIT 1",
            tenant_id,
        )
    finally:
        await conn.close()

    return dict(row) if row else None
