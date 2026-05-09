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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import redis.asyncio as aioredis
from jose import JWTError, jwt

_SECRET = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret-change-me")
_ALGORITHM = "HS256"
_ACCESS_EXPIRE_MINUTES = 15
_REFRESH_EXPIRE_DAYS = 7
_MFA_CHALLENGE_EXPIRE_MINUTES = 5


@dataclass(frozen=True)
class IssuedAccessToken:
    """The encoded JWT plus the claim metadata callers need for session recording."""

    token: str
    jti: str
    issued_at: datetime
    expires_at: datetime

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


def create_access_token(
    tenant_id: str,
    role: str,
    user_id: str,
    tenant_user_id: Optional[str] = None,
) -> str:
    """Issue a short-lived access JWT. Thin wrapper returning only the string."""
    return issue_access_token(
        tenant_id=tenant_id,
        role=role,
        user_id=user_id,
        tenant_user_id=tenant_user_id,
    ).token


def issue_access_token(
    *,
    tenant_id: str,
    role: str,
    user_id: str,
    tenant_user_id: Optional[str] = None,
) -> IssuedAccessToken:
    """Issue an access JWT and return the metadata needed for session recording.

    Every access token carries a unique ``jti`` so that individual sessions can
    be revoked by the owning user or by an admin (Phase 6.5). The gateway
    verifies ``jti`` against both a Redis blacklist (fast path) and the
    ``auth_sessions`` table (source of truth).

    ``tenant_user_id`` — when supplied, is embedded as the ``tuid`` claim so
    the gateway can key its per-user revoked_before pivot against the same
    UUID the auth service writes.
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=_ACCESS_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": tenant_id,
        "user_id": user_id,
        "role": role,
        "type": "access",
        "jti": jti,
        "iat": now,
        "exp": exp,
    }
    if tenant_user_id is not None:
        payload["tuid"] = tenant_user_id
    token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)
    return IssuedAccessToken(token=token, jti=jti, issued_at=now, expires_at=exp)


async def blacklist_access_jti(jti: str, exp_timestamp: int) -> None:
    """Revoke an access-token jti. Gateway short-circuits on hit."""
    r = _get_blacklist_redis()
    ttl = max(exp_timestamp - int(datetime.now(timezone.utc).timestamp()), 1)
    await r.set(f"agcms:at:blacklist:{jti}", "1", ex=ttl)


async def is_access_jti_blacklisted(jti: str) -> bool:
    """Check a short-TTL Redis cache for per-jti revocation of an access token."""
    r = _get_blacklist_redis()
    return await r.exists(f"agcms:at:blacklist:{jti}") == 1


async def set_user_revoked_before(tenant_user_id: str, pivot_ts: int) -> None:
    """Publish a bulk-revocation pivot for a tenant_user.

    The gateway rejects any access token whose ``iat < pivot_ts``. TTL is set
    to the access-token lifetime: after that window, every token issued before
    the pivot has naturally expired and the pivot is no longer needed.
    """
    r = _get_blacklist_redis()
    ttl = _ACCESS_EXPIRE_MINUTES * 60 + 60  # small safety margin
    await r.set(
        f"agcms:at:revoked_before:{tenant_user_id}",
        str(pivot_ts),
        ex=ttl,
    )


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


def create_mfa_challenge_token(
    tenant_id: str, user_id: str, tenant_user_id: str, role: str
) -> str:
    """Issue a short-lived ticket that `/v1/auth/mfa/login` exchanges for real tokens.

    Issued after API-key login when the user has MFA enabled. The
    challenge token carries just enough to mint the final access /
    refresh pair without a second DB round-trip.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": tenant_id,
        "user_id": user_id,
        "tenant_user_id": tenant_user_id,
        "role": role,
        "type": "mfa_challenge",
        "iat": now,
        "exp": now + timedelta(minutes=_MFA_CHALLENGE_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def verify_mfa_challenge_token(token: str) -> Optional[dict]:
    """Decode a challenge token. Returns payload or None."""
    payload = decode_token(token)
    if payload is None or payload.get("type") != "mfa_challenge":
        return None
    return payload
