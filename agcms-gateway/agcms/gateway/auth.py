"""Dual-mode authentication for the AGCMS gateway.

Accepts either of the following in the ``Authorization: Bearer <token>`` header:

1. **JWT access tokens** issued by the auth service (type="access"). Decoded
   locally with the shared ``JWT_SECRET_KEY`` — no HTTP hop on the hot path.
2. **Raw API keys** looked up via SHA-256 hash against the ``tenants`` table.
   Enables direct LLM access without a login roundtrip.

The Phase-1 dev key ``agcms_test_key_for_development`` still works via a
fast-path hash comparison (used by existing tests, the dashboard, and demos).

Detection heuristic:
    token with exactly 2 dots   → JWT path
    otherwise                   → API key path

Returns an ``AuthContext`` dataclass carrying ``tenant_id``, ``user_id``,
``role``, and ``auth_method`` — consumed by the gateway's 13-step lifecycle
and (later) the management-API RBAC layer.
"""

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import FrozenSet, Optional, Tuple

import asyncpg
import redis.asyncio as aioredis
from jose import JWTError, jwt

from agcms.common import scopes as scope_vocab

_log = logging.getLogger("agcms.gateway.auth")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# SHA-256 of the Phase-1 development API key.
_DEV_KEY_HASH = hashlib.sha256(b"agcms_test_key_for_development").hexdigest()
_DEV_TENANT_ID = "default"

_JWT_ALGORITHM = "HS256"


def _jwt_secret() -> str:
    """Read JWT_SECRET_KEY at call time so env overrides work after import."""
    return os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret-change-me")


def _database_url() -> str:
    return os.environ.get("DATABASE_URL", "")


# ---------------------------------------------------------------------------
# Revocation cache (Phase 6.5)
# ---------------------------------------------------------------------------
#
# Two Redis-backed revocation surfaces, both optional — on Redis failure we
# fail open so the LLM hot path keeps working (revocation then degrades to
# eventual-consistency via the access token's own 15-minute TTL):
#
#   agcms:at:blacklist:<jti>              explicit per-session revocation
#   agcms:at:revoked_before:<tenant_user> bulk pivot; values are unix seconds
#
# The auth service writes both; the gateway only reads.
#
_redis_client: Optional[aioredis.Redis] = None


def _get_redis() -> Optional[aioredis.Redis]:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    url = os.environ.get("REDIS_URL")
    if not url:
        return None
    try:
        _redis_client = aioredis.from_url(url, decode_responses=True)
    except Exception as exc:  # noqa: BLE001 — fail open, don't block auth on Redis outage
        _log.warning("gateway auth Redis init failed: %s", exc)
        return None
    return _redis_client


async def _is_jwt_revoked(jti: Optional[str], tenant_user_id: Optional[str], iat: Optional[int]) -> bool:
    """Return True if this access token has been revoked.

    Checks both the per-jti blacklist and the per-user ``revoked_before`` pivot.
    If Redis is unreachable, returns False (fail open — better to keep the
    proxy live during an ops incident than to deny every request).
    """
    r = _get_redis()
    if r is None:
        return False
    try:
        if jti:
            if await r.exists(f"agcms:at:blacklist:{jti}") == 1:
                return True
        if tenant_user_id and iat:
            pivot = await r.get(f"agcms:at:revoked_before:{tenant_user_id}")
            if pivot and iat < int(pivot):
                return True
    except Exception as exc:  # noqa: BLE001 — fail open
        _log.warning("gateway auth Redis check failed: %s", exc)
        return False
    return False


# ---------------------------------------------------------------------------
# AuthContext
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthContext:
    """Caller identity passed through the request lifecycle."""
    tenant_id: str
    user_id: str       # JWT claim, or "api_key" for raw API-key auth
    role: str          # JWT claim, or "user" default for raw API-key auth
    auth_method: str   # "jwt" | "api_key" | "dev_key"
    scopes: FrozenSet[str] = field(default_factory=frozenset)
    api_key_id: Optional[str] = None  # api_keys.id when auth_method == "api_key"

    def has_scope(self, required: str) -> bool:
        return scope_vocab.has_scope(self.scopes, required)


# ---------------------------------------------------------------------------
# Token path: JWT
# ---------------------------------------------------------------------------


def _try_jwt(token: str) -> Tuple[Optional[AuthContext], Optional[dict]]:
    """Decode a JWT access token. Returns (ctx, payload) or (None, None)."""
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=[_JWT_ALGORITHM])
    except JWTError:
        return None, None

    if payload.get("type") != "access":
        return None, None

    tenant_id = payload.get("sub")
    user_id = payload.get("user_id")
    role = payload.get("role")
    if not (tenant_id and user_id and role):
        return None, None

    ctx = AuthContext(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        auth_method="jwt",
        scopes=scope_vocab.scopes_for_role(role),
    )
    return ctx, payload


# ---------------------------------------------------------------------------
# Token path: API key (DB lookup)
# ---------------------------------------------------------------------------


async def _try_api_key_db(api_key: str) -> Optional[AuthContext]:
    """Look up an API key via its SHA-256 hash.

    Prefers the scoped ``api_keys`` table. Falls back to the legacy
    ``tenants.api_key_hash`` column so pre-migration deployments keep
    working; legacy keys get the full scope set (behavior preserved).
    Updates ``last_used_at`` on every successful lookup.
    """
    key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    db_url = _database_url()
    if not db_url:
        return None

    try:
        conn = await asyncpg.connect(db_url)
    except Exception:
        return None

    try:
        row = await conn.fetchrow(
            "SELECT ak.id, ak.tenant_id, ak.scopes "
            "FROM api_keys ak "
            "JOIN tenants t ON t.id = ak.tenant_id "
            "WHERE ak.key_hash = $1 "
            "  AND ak.revoked_at IS NULL "
            "  AND t.is_active = TRUE",
            key_hash,
        )
        if row is not None:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                row["id"],
            )
            return AuthContext(
                tenant_id=row["tenant_id"],
                user_id="api_key",
                role="user",
                auth_method="api_key",
                scopes=frozenset(row["scopes"] or []),
                api_key_id=str(row["id"]),
            )

        # Legacy path (pre-Phase-6.4 tenants still on tenants.api_key_hash)
        legacy = await conn.fetchrow(
            "SELECT id FROM tenants "
            "WHERE api_key_hash = $1 AND is_active = TRUE",
            key_hash,
        )
    finally:
        await conn.close()

    if legacy is None:
        return None

    return AuthContext(
        tenant_id=legacy["id"],
        user_id="api_key",
        role="user",
        auth_method="api_key",
        scopes=scope_vocab.ALL_SCOPES,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def authenticate(
    auth_header: Optional[str],
) -> Tuple[Optional[AuthContext], Optional[str]]:
    """Validate an Authorization header and return ``(ctx, error_message)``.

    Returns ``(AuthContext, None)`` on success, or ``(None, error_message)``
    on failure. Tries JWT first when the token looks like a JWT, otherwise
    falls through to API-key paths (dev fast-path, then DB lookup).
    """
    if not auth_header:
        return None, "Missing API key. Provide Authorization: Bearer <key>"

    token = auth_header[7:] if auth_header.startswith("Bearer ") else auth_header
    token = token.strip()
    if not token:
        return None, "Empty authorization token"

    # JWT shape: header.payload.signature (exactly two dots)
    if token.count(".") == 2:
        ctx, payload = _try_jwt(token)
        if ctx is None or payload is None:
            return None, "Invalid or expired JWT"

        # Phase 6.5: reject if this jti (or all of this user's sessions) was revoked.
        # The auth service looks up tenant_user_id server-side, but here we only
        # have the JWT user_id (external_id). The pivot key is keyed by the
        # tenant_user_id UUID, which the auth service sets in the claim as
        # ``tuid`` when the session was recorded. Fall back to external_id for
        # older tokens that don't carry it.
        tuid = payload.get("tuid") or payload.get("user_id")
        if await _is_jwt_revoked(payload.get("jti"), tuid, payload.get("iat")):
            return None, "Session has been revoked"

        return ctx, None

    # API-key path — dev key fast-path first
    key_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if key_hash == _DEV_KEY_HASH:
        return (
            AuthContext(
                tenant_id=_DEV_TENANT_ID,
                user_id="admin",
                role="admin",
                auth_method="dev_key",
                scopes=scope_vocab.ALL_SCOPES,
            ),
            None,
        )

    # Real API key — DB lookup
    ctx = await _try_api_key_db(token)
    if ctx is not None:
        return ctx, None

    return None, "Invalid API key"
