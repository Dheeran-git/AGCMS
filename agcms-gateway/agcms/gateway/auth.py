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
import os
from dataclasses import dataclass
from typing import Optional, Tuple

import asyncpg
from jose import JWTError, jwt

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
# AuthContext
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthContext:
    """Caller identity passed through the request lifecycle."""
    tenant_id: str
    user_id: str       # JWT claim, or "api_key" for raw API-key auth
    role: str          # JWT claim, or "user" default for raw API-key auth
    auth_method: str   # "jwt" | "api_key" | "dev_key"


# ---------------------------------------------------------------------------
# Token path: JWT
# ---------------------------------------------------------------------------


def _try_jwt(token: str) -> Optional[AuthContext]:
    """Decode a JWT access token. Returns AuthContext or None on any failure."""
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=[_JWT_ALGORITHM])
    except JWTError:
        return None

    if payload.get("type") != "access":
        return None

    tenant_id = payload.get("sub")
    user_id = payload.get("user_id")
    role = payload.get("role")
    if not (tenant_id and user_id and role):
        return None

    return AuthContext(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        auth_method="jwt",
    )


# ---------------------------------------------------------------------------
# Token path: API key (DB lookup)
# ---------------------------------------------------------------------------


async def _try_api_key_db(api_key: str) -> Optional[AuthContext]:
    """Look up an API key via its SHA-256 hash in the tenants table."""
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
            "SELECT id FROM tenants "
            "WHERE api_key_hash = $1 AND is_active = TRUE",
            key_hash,
        )
    finally:
        await conn.close()

    if row is None:
        return None

    return AuthContext(
        tenant_id=row["id"],
        user_id="api_key",
        role="user",
        auth_method="api_key",
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
        ctx = _try_jwt(token)
        if ctx is not None:
            return ctx, None
        return None, "Invalid or expired JWT"

    # API-key path — dev key fast-path first
    key_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if key_hash == _DEV_KEY_HASH:
        return (
            AuthContext(
                tenant_id=_DEV_TENANT_ID,
                user_id="admin",
                role="admin",
                auth_method="dev_key",
            ),
            None,
        )

    # Real API key — DB lookup
    ctx = await _try_api_key_db(token)
    if ctx is not None:
        return ctx, None

    return None, "Invalid API key"
