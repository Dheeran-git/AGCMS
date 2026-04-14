"""JWT token creation and verification for AGCMS auth service.

Access tokens: short-lived (15 min), carry tenant_id + user role.
Refresh tokens: long-lived (7 days), carry only tenant_id + token type + jti.

Both are signed HS256 JWTs using JWT_SECRET_KEY env var.

Refresh token single-use enforcement:
  - Each refresh token carries a unique ``jti`` (JWT ID, UUID4).
  - On use the jti is written to a Redis blacklist with TTL = token expiry.
  - Subsequent calls with the same token are rejected (replay protection).
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis.asyncio as aioredis
from jose import JWTError, jwt

_SECRET = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret-change-me")
_ALGORITHM = "HS256"
_ACCESS_EXPIRE_MINUTES = 15
_REFRESH_EXPIRE_DAYS = 7

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
_redis: Optional[aioredis.Redis] = None


def _get_blacklist_redis() -> aioredis.Redis:
    """Return (and lazily create) the shared Redis client."""
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(_REDIS_URL, decode_responses=True)
    return _redis


async def blacklist_jti(jti: str, exp_timestamp: int) -> None:
    """Mark a refresh token jti as used. TTL matches the token's own expiry."""
    r = _get_blacklist_redis()
    ttl = max(exp_timestamp - int(datetime.now(timezone.utc).timestamp()), 1)
    await r.set(f"agcms:rt:blacklist:{jti}", "1", ex=ttl)


async def is_jti_blacklisted(jti: str) -> bool:
    """Return True if this jti has already been used (or is otherwise invalid)."""
    r = _get_blacklist_redis()
    return await r.exists(f"agcms:rt:blacklist:{jti}") == 1


def create_access_token(tenant_id: str, role: str, user_id: str) -> str:
    """Issue a short-lived access JWT."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": tenant_id,
        "user_id": user_id,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=_ACCESS_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def create_refresh_token(tenant_id: str) -> str:
    """Issue a long-lived refresh JWT with a unique jti for single-use enforcement."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": tenant_id,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(days=_REFRESH_EXPIRE_DAYS),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT. Returns payload dict or None on failure."""
    try:
        return jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    except JWTError:
        return None


def verify_access_token(token: str) -> Optional[dict]:
    """Decode and validate an access token. Returns payload or None."""
    payload = decode_token(token)
    if payload is None or payload.get("type") != "access":
        return None
    return payload


def verify_refresh_token(token: str) -> Optional[dict]:
    """Decode and validate a refresh token. Returns payload or None."""
    payload = decode_token(token)
    if payload is None or payload.get("type") != "refresh":
        return None
    return payload
