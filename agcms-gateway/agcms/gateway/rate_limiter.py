"""Redis-based rate limiters for the AGCMS gateway.

Two layers of protection:
1. Per-tenant rate limit  — keyed by tenant_id, configurable RPM.
   Applies after authentication; can be bypassed by API key rotation.
2. Global IP rate limit   — keyed by client IP, hardcoded ceiling.
   Applied before authentication; prevents brute-force and API key rotation bypass.
"""

import os
from typing import Optional, Tuple

import redis.asyncio as aioredis

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
_DEFAULT_RPM = 60         # per-tenant default
_GLOBAL_IP_RPM = 200      # per-IP ceiling (across all tenants)

_redis: Optional[aioredis.Redis] = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(_REDIS_URL, decode_responses=True)
    return _redis


async def _sliding_window_check(key: str, limit: int) -> Tuple[bool, int]:
    """Increment a Redis counter with 60s TTL; return (allowed, count)."""
    r = await _get_redis()
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.ttl(key)
    results = await pipe.execute()

    current_count = results[0]
    ttl = results[1]

    if ttl == -1:
        await r.expire(key, 60)

    return current_count <= limit, current_count


async def check_rate_limit(
    tenant_id: str,
    rpm_limit: int = _DEFAULT_RPM,
) -> Tuple[bool, int]:
    """Check and increment the per-tenant rate limit.

    Args:
        tenant_id: The tenant identifier.
        rpm_limit: Max requests per minute for this tenant.

    Returns:
        (allowed, current_count) — allowed is True if under limit.
    """
    return await _sliding_window_check(f"agcms:rate:{tenant_id}:rpm", rpm_limit)


async def check_global_ip_rate_limit(client_ip: str) -> Tuple[bool, int]:
    """Check and increment the global per-IP rate limit.

    Applied regardless of tenant identity — prevents rate limit bypass
    via API key rotation and protects unauthenticated endpoints.

    Args:
        client_ip: The client's IP address (from X-Forwarded-For or direct).

    Returns:
        (allowed, current_count) — allowed is True if under limit.
    """
    return await _sliding_window_check(
        f"agcms:rate:global:ip:{client_ip}:rpm",
        _GLOBAL_IP_RPM,
    )
