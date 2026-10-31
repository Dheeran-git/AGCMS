"""Dual-mode authentication for the AGCMS gateway.

Accepts either of the following in the ``Authorization: Bearer <token>`` header:

1. **JWT access tokens** issued by the auth service (type="access"). Decoded
   locally with the shared ``JWT_SECRET_KEY`` — no HTTP hop on the hot path.
2. **Raw API keys** looked up via SHA-256 hash against the ``tenants`` table.
   Enables direct LLM access without a login roundtrip.

The Phase-1 dev key ``agcms_test_key_for_development`` is seeded for the
``default`` tenant in ``database/init.sql`` and so works through the normal
API-key lookup. A database-free fast path for it exists for tests and is only
honoured when ``AGCMS_ALLOW_DEV_KEY=true``. ``JWT_SECRET_KEY`` has no default.

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
from typing import FrozenSet, Optional, Tuple

import asyncpg
from jose import JWTError, jwt

from agcms.common import scopes as scope_vocab
from agcms.gateway import clients

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
    secret = os.environ.get("JWT_SECRET_KEY", "")
    if not secret:
        raise RuntimeError("JWT_SECRET_KEY is not set; refusing to accept or verify tokens")
    return secret


def _dev_key_allowed() -> bool:
    """The built-in dev key bypasses the database; only honour it when explicitly enabled."""
    return os.environ.get("AGCMS_ALLOW_DEV_KEY", "false").lower() == "true"


# ---------------------------------------------------------------------------
# AuthContext
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthContext:
    """Caller identity passed through the request lifecycle."""
    tenant_id: str
    user_id: str       # JWT claim, or "api_key" for raw API-key auth
    role: str          # JWT claim; for API keys "admin" if the key holds the admin scope, else "user"
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
        payload = jwt.decode(
            token, _jwt_secret(), algorithms=[_JWT_ALGORITHM], options={"require_exp": True},
        )
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

    if clients.pool is None:
        return None
    try:
        async with clients.pool.acquire() as conn:
            return await _lookup_key(conn, key_hash)
    except (OSError, asyncpg.PostgresError, asyncpg.InterfaceError):
        return None  # database unreachable: the key cannot be verified


async def _lookup_key(conn, key_hash: str) -> Optional[AuthContext]:
    """Resolve a key hash against ``api_keys``, then the legacy tenant column."""
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
        await conn.execute("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1", row["id"])
        scopes = frozenset(row["scopes"] or [])
        return AuthContext(
            tenant_id=row["tenant_id"],
            user_id="api_key",
            # The admin scope grants tenant management, so it carries the admin role.
            role="admin" if scope_vocab.ADMIN in scopes else "user",
            auth_method="api_key",
            scopes=scopes,
            api_key_id=str(row["id"]),
        )

    # Legacy path (pre-Phase-6.4 tenants still on tenants.api_key_hash)
    legacy = await conn.fetchrow(
        "SELECT id FROM tenants WHERE api_key_hash = $1 AND is_active = TRUE",
        key_hash,
    )
    if legacy is None:
        return None

    # The tenant master key: /v1/auth/token already exchanges it for an admin
    # JWT, so it carries the admin role here too. Scoped api_keys stay "user".
    return AuthContext(
        tenant_id=legacy["id"],
        user_id="api_key",
        role="admin",
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

        return ctx, None

    # API-key path — dev key fast-path first
    key_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if key_hash == _DEV_KEY_HASH and _dev_key_allowed():
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
