"""Database helpers for the MFA enrollment / verification flow.

The shape of the `user_mfa` row is:

    id              UUID  PK
    tenant_user_id  UUID  FK → tenant_users.id (unique)
    totp_secret     str   base32 TOTP secret (plaintext in Phase 6.2;
                          envelope-encrypted in Phase 6.3)
    recovery_codes  list[str]  SHA-256 hex hashes of plaintext recovery codes
    enabled         bool
    enrolled_at     ts
    verified_at     ts
    last_used_at    ts
    disabled_at     ts
"""
from __future__ import annotations

import json
import os
from typing import Optional

import asyncpg

_DATABASE_URL = os.environ.get("DATABASE_URL", "")


async def _connect() -> asyncpg.Connection:
    return await asyncpg.connect(_DATABASE_URL)


async def fetch_user_by_external_id(
    tenant_id: str, external_id: str
) -> Optional[dict]:
    """Return the tenant_users row for (tenant_id, external_id), or None."""
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            "SELECT id, tenant_id, external_id, email, role, is_active "
            "FROM tenant_users WHERE tenant_id = $1 AND external_id = $2",
            tenant_id,
            external_id,
        )
    finally:
        await conn.close()
    return dict(row) if row else None


async def fetch_mfa(tenant_user_id) -> Optional[dict]:
    """Return the user_mfa row for this tenant_user, or None."""
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            "SELECT id, tenant_user_id, totp_secret, recovery_codes, enabled, "
            "enrolled_at, verified_at, last_used_at, disabled_at "
            "FROM user_mfa WHERE tenant_user_id = $1",
            tenant_user_id,
        )
    finally:
        await conn.close()
    if not row:
        return None
    data = dict(row)
    # asyncpg returns JSONB as str; decode to list.
    codes = data.get("recovery_codes")
    if isinstance(codes, str):
        data["recovery_codes"] = json.loads(codes) if codes else []
    elif codes is None:
        data["recovery_codes"] = []
    return data


async def upsert_pending_enrollment(
    tenant_user_id,
    *,
    totp_secret: str,
    recovery_hashes: list[str],
) -> None:
    """Create or replace a pending (enabled=FALSE) enrollment row.

    Overwriting an existing row is intentional: if the user loses their
    device mid-enrollment and restarts, the older pending secret is
    discarded rather than orphaned. An *enabled* row is replaced too,
    but only after the caller has confirmed via MFA — otherwise anyone
    with an access token could silently rotate another user's MFA.
    """
    conn = await _connect()
    try:
        await conn.execute(
            "INSERT INTO user_mfa (tenant_user_id, totp_secret, recovery_codes, enabled) "
            "VALUES ($1, $2, $3::jsonb, FALSE) "
            "ON CONFLICT (tenant_user_id) DO UPDATE SET "
            "  totp_secret = EXCLUDED.totp_secret, "
            "  recovery_codes = EXCLUDED.recovery_codes, "
            "  enabled = FALSE, "
            "  enrolled_at = NOW(), "
            "  verified_at = NULL, "
            "  disabled_at = NULL",
            tenant_user_id,
            totp_secret,
            json.dumps(recovery_hashes),
        )
    finally:
        await conn.close()


async def mark_verified(tenant_user_id) -> None:
    conn = await _connect()
    try:
        await conn.execute(
            "UPDATE user_mfa SET enabled = TRUE, verified_at = NOW() "
            "WHERE tenant_user_id = $1",
            tenant_user_id,
        )
    finally:
        await conn.close()


async def record_use(tenant_user_id) -> None:
    conn = await _connect()
    try:
        await conn.execute(
            "UPDATE user_mfa SET last_used_at = NOW() WHERE tenant_user_id = $1",
            tenant_user_id,
        )
    finally:
        await conn.close()


async def replace_recovery_codes(
    tenant_user_id, hashes: list[str]
) -> None:
    conn = await _connect()
    try:
        await conn.execute(
            "UPDATE user_mfa SET recovery_codes = $2::jsonb WHERE tenant_user_id = $1",
            tenant_user_id,
            json.dumps(hashes),
        )
    finally:
        await conn.close()


async def disable_mfa(tenant_user_id) -> bool:
    """Mark a user's MFA as disabled. Returns True if a row was updated."""
    conn = await _connect()
    try:
        result = await conn.execute(
            "UPDATE user_mfa SET enabled = FALSE, disabled_at = NOW() "
            "WHERE tenant_user_id = $1 AND enabled = TRUE",
            tenant_user_id,
        )
    finally:
        await conn.close()
    # asyncpg returns 'UPDATE <count>'
    return result.endswith(" 1")
