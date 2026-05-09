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
    """Return the admin tenant_user row for the given tenant."""
    conn = await asyncpg.connect(_DATABASE_URL)
    try:
        row = await conn.fetchrow(
            "SELECT id, external_id, email, role "
            "FROM tenant_users "
            "WHERE tenant_id = $1 AND role = 'admin' AND is_active = TRUE "
            "LIMIT 1",
            tenant_id,
        )
    finally:
        await conn.close()

    return dict(row) if row else None


async def get_tenant_by_workos_org(workos_org_id: str) -> Optional[dict]:
    """Return the tenant row that owns this WorkOS organization, if any."""
    conn = await asyncpg.connect(_DATABASE_URL)
    try:
        row = await conn.fetchrow(
            "SELECT id, name, plan, admin_email, is_active, workos_org_id, sso_enforced "
            "FROM tenants WHERE workos_org_id = $1",
            workos_org_id,
        )
    finally:
        await conn.close()
    return dict(row) if row and row["is_active"] else None


async def provision_or_fetch_sso_user(
    tenant_id: str,
    *,
    sso_subject: str,
    email: str,
    display_name: Optional[str],
) -> dict:
    """Upsert a tenant_user row keyed by (tenant_id, sso_subject).

    First-login provisioning creates a ``user`` role row; admin promotion
    must be done explicitly by an existing admin. Returns the user dict.
    """
    conn = await asyncpg.connect(_DATABASE_URL)
    try:
        row = await conn.fetchrow(
            "SELECT id, external_id, email, role, is_active "
            "FROM tenant_users "
            "WHERE tenant_id = $1 AND sso_subject = $2",
            tenant_id,
            sso_subject,
        )
        if row is not None:
            if not row["is_active"]:
                return None  # caller surfaces as 403
            if email and row["email"] != email:
                await conn.execute(
                    "UPDATE tenant_users SET email = $1 WHERE id = $2",
                    email,
                    row["id"],
                )
            return dict(row)

        # No row — provision one. external_id defaults to the email or sso_subject.
        external_id = email or sso_subject
        row = await conn.fetchrow(
            "INSERT INTO tenant_users "
            "(tenant_id, external_id, email, role, sso_subject, auth_provider) "
            "VALUES ($1, $2, $3, 'user', $4, 'workos') "
            "ON CONFLICT (tenant_id, external_id) DO UPDATE "
            "SET sso_subject = EXCLUDED.sso_subject, "
            "    auth_provider = EXCLUDED.auth_provider, "
            "    email = EXCLUDED.email "
            "RETURNING id, external_id, email, role, is_active",
            tenant_id,
            external_id,
            email,
            sso_subject,
        )
    finally:
        await conn.close()
    return dict(row)
