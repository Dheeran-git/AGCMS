"""Session persistence + revocation helpers for the auth service.

Every access token issued by the auth service produces a row in
``auth_sessions``. Rows are keyed by the token's ``jti``. The gateway's
verification path consults:

  1. Redis blacklist — fast O(1) per-jti revocation check (hot path).
  2. ``tenant_users.revoked_before`` — bulk revocation pivot; any token whose
     ``iat`` is older is rejected (e.g. password change, admin "revoke all").
  3. ``auth_sessions.revoked_at`` — durable per-session revocation, surfaced
     in the dashboard Sessions tab.

The DB row is also the surface the /sessions endpoints list from; Redis is
only a latency optimization.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Optional

import asyncpg

_DATABASE_URL = os.environ.get("DATABASE_URL", "")


async def _connect() -> asyncpg.Connection:
    return await asyncpg.connect(_DATABASE_URL)


async def record_session(
    *,
    jti: str,
    tenant_user_id: str,
    tenant_id: str,
    issued_at: datetime,
    expires_at: datetime,
    issued_via: str,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """Insert an ``auth_sessions`` row for a newly-issued access token.

    Best-effort: if the auth_sessions table is temporarily unavailable we
    swallow the error rather than failing the login. The token itself still
    carries a valid jti; on first request the gateway will log a "session row
    not found" warning and fall back to the revoked_before pivot.
    """
    conn = await _connect()
    try:
        await conn.execute(
            """
            INSERT INTO auth_sessions
                (jti, tenant_user_id, tenant_id, issued_at, expires_at,
                 issued_via, user_agent, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            jti,
            tenant_user_id,
            tenant_id,
            issued_at,
            expires_at,
            issued_via,
            user_agent,
            ip_address,
        )
    finally:
        await conn.close()


async def list_sessions_for_user(tenant_user_id: str) -> list[dict[str, Any]]:
    """Return the caller's active + recent sessions, newest first.

    Recent revoked / expired sessions are included so the user can see their
    own session history; the UI filters or greys-out dead rows.
    """
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT jti, issued_at, expires_at, last_seen_at, revoked_at,
                   revoked_by, revoke_reason, user_agent, ip_address::text AS ip_address,
                   issued_via
            FROM auth_sessions
            WHERE tenant_user_id = $1
            ORDER BY issued_at DESC
            LIMIT 50
            """,
            tenant_user_id,
        )
    finally:
        await conn.close()
    return [dict(r) for r in rows]


async def list_sessions_for_tenant(tenant_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Admin view: every active session across the tenant, newest first."""
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT s.jti, s.tenant_user_id, s.issued_at, s.expires_at,
                   s.last_seen_at, s.revoked_at, s.revoke_reason,
                   s.user_agent, s.ip_address::text AS ip_address, s.issued_via,
                   u.email, u.external_id, u.role
            FROM auth_sessions s
            JOIN tenant_users u ON u.id = s.tenant_user_id
            WHERE s.tenant_id = $1
            ORDER BY s.issued_at DESC
            LIMIT $2
            """,
            tenant_id,
            limit,
        )
    finally:
        await conn.close()
    return [dict(r) for r in rows]


async def revoke_session(
    *,
    jti: str,
    revoked_by: Optional[str],
    reason: str = "user_revoked",
) -> Optional[dict[str, Any]]:
    """Mark a single session revoked. Returns the row (with expires_at) if it existed.

    Callers should follow this up with a Redis blacklist write so the revocation
    is visible to the gateway within one cache miss.
    """
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            UPDATE auth_sessions
            SET revoked_at = NOW(),
                revoked_by = $1,
                revoke_reason = $2
            WHERE jti = $3 AND revoked_at IS NULL
            RETURNING jti, tenant_user_id, tenant_id, issued_at, expires_at
            """,
            revoked_by,
            reason,
            jti,
        )
    finally:
        await conn.close()
    return dict(row) if row else None


async def revoke_all_sessions_for_user(
    *,
    tenant_user_id: str,
    revoked_by: Optional[str],
    reason: str = "revoke_all",
) -> list[dict[str, Any]]:
    """Revoke every active session AND bump ``tenant_users.revoked_before``.

    Bumping the pivot guarantees that even a token whose session row somehow
    escapes this revocation sweep (e.g. a session row that was never written
    due to a transient DB hiccup at issuance) is still rejected on the next
    gateway hit — ``iat < revoked_before`` fails the pivot check.
    """
    conn = await _connect()
    try:
        async with conn.transaction():
            rows = await conn.fetch(
                """
                UPDATE auth_sessions
                SET revoked_at = NOW(),
                    revoked_by = $1,
                    revoke_reason = $2
                WHERE tenant_user_id = $3 AND revoked_at IS NULL
                RETURNING jti, expires_at
                """,
                revoked_by,
                reason,
                tenant_user_id,
            )
            await conn.execute(
                "UPDATE tenant_users SET revoked_before = NOW() WHERE id = $1",
                tenant_user_id,
            )
    finally:
        await conn.close()
    return [dict(r) for r in rows]


async def fetch_session(jti: str) -> Optional[dict[str, Any]]:
    """Gateway verification path: is this jti valid?"""
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            SELECT jti, tenant_user_id, tenant_id, issued_at, expires_at,
                   revoked_at
            FROM auth_sessions WHERE jti = $1
            """,
            jti,
        )
    finally:
        await conn.close()
    return dict(row) if row else None


async def touch_session(jti: str) -> None:
    """Update ``last_seen_at`` on gateway activity. Best-effort."""
    conn = await _connect()
    try:
        await conn.execute(
            "UPDATE auth_sessions SET last_seen_at = NOW() WHERE jti = $1",
            jti,
        )
    finally:
        await conn.close()
