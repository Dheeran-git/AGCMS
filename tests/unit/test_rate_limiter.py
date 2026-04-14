"""Unit tests for the AGCMS gateway rate limiter.

Covers:
  - Per-tenant rate limit: allowed under limit, blocked at limit
  - Per-tenant: TTL is set on first request
  - Global IP rate limit: allowed under limit, blocked at limit
  - Global IP: uses a separate Redis key namespace from per-tenant
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("REDIS_URL", "redis://localhost:6379")

from agcms.gateway.rate_limiter import (  # noqa: E402
    check_global_ip_rate_limit,
    check_rate_limit,
)


def _make_redis(incr_val: int, ttl_val: int) -> MagicMock:
    """Return a mock Redis client whose pipeline returns (incr_val, ttl_val)."""
    pipe = MagicMock()
    pipe.incr = MagicMock()
    pipe.ttl = MagicMock()
    pipe.execute = AsyncMock(return_value=[incr_val, ttl_val])

    r = MagicMock()
    r.pipeline = MagicMock(return_value=pipe)
    r.expire = AsyncMock()
    return r


# ===========================================================================
# Per-tenant rate limit
# ===========================================================================


class TestPerTenantRateLimit:
    @pytest.mark.asyncio
    async def test_first_request_is_allowed(self):
        r = _make_redis(incr_val=1, ttl_val=-1)  # first ever request, no TTL yet
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=r):
            allowed, count = await check_rate_limit("tenant1", rpm_limit=60)
        assert allowed is True
        assert count == 1

    @pytest.mark.asyncio
    async def test_request_at_limit_is_allowed(self):
        r = _make_redis(incr_val=60, ttl_val=30)
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=r):
            allowed, count = await check_rate_limit("tenant1", rpm_limit=60)
        assert allowed is True
        assert count == 60

    @pytest.mark.asyncio
    async def test_request_over_limit_is_blocked(self):
        r = _make_redis(incr_val=61, ttl_val=30)
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=r):
            allowed, count = await check_rate_limit("tenant1", rpm_limit=60)
        assert allowed is False
        assert count == 61

    @pytest.mark.asyncio
    async def test_ttl_set_on_first_request(self):
        r = _make_redis(incr_val=1, ttl_val=-1)  # -1 means no TTL set yet
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=r):
            await check_rate_limit("tenant1", rpm_limit=60)
        r.expire.assert_called_once_with("agcms:rate:tenant1:rpm", 60)

    @pytest.mark.asyncio
    async def test_ttl_not_reset_on_subsequent_requests(self):
        r = _make_redis(incr_val=5, ttl_val=45)  # TTL already set
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=r):
            await check_rate_limit("tenant1", rpm_limit=60)
        r.expire.assert_not_called()


# ===========================================================================
# Global IP rate limit
# ===========================================================================


class TestGlobalIPRateLimit:
    @pytest.mark.asyncio
    async def test_first_request_from_ip_is_allowed(self):
        r = _make_redis(incr_val=1, ttl_val=-1)
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=r):
            allowed, count = await check_global_ip_rate_limit("1.2.3.4")
        assert allowed is True
        assert count == 1

    @pytest.mark.asyncio
    async def test_ip_over_global_limit_is_blocked(self):
        r = _make_redis(incr_val=201, ttl_val=30)
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=r):
            allowed, count = await check_global_ip_rate_limit("1.2.3.4")
        assert allowed is False

    @pytest.mark.asyncio
    async def test_global_ip_uses_separate_key_namespace(self):
        """Global IP keys must not collide with per-tenant keys."""
        keys_used: list[str] = []
        original = _make_redis(incr_val=1, ttl_val=-1)

        def capturing_pipeline():
            pipe = MagicMock()

            async def execute():
                return [1, -1]

            pipe.incr = lambda key: keys_used.append(key)
            pipe.ttl = MagicMock()
            pipe.execute = execute
            return pipe

        original.pipeline = capturing_pipeline
        with patch("agcms.gateway.rate_limiter._get_redis", new_callable=AsyncMock, return_value=original):
            await check_global_ip_rate_limit("10.0.0.1")

        assert any("global:ip" in k for k in keys_used), f"Expected 'global:ip' in key, got: {keys_used}"
        assert not any(k.startswith("agcms:rate:") and "global" not in k for k in keys_used)
