"""Unit tests for the gateway's active-tenant-policy lookup and cache."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from agcms.gateway import tenant_policy


def _conn(row):
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=row)
    conn.close = AsyncMock()
    return conn


@pytest.fixture(autouse=True)
def _clear_cache():
    tenant_policy._cache.clear()
    yield
    tenant_policy._cache.clear()


@pytest.mark.asyncio
async def test_returns_config_and_parses_jsonb_string():
    cfg = {"injection": {"block_threshold": 0.65, "escalate_threshold": 0.85}}
    conn = _conn({"config": json.dumps(cfg)})
    with patch("agcms.gateway.tenant_policy.asyncpg.connect", AsyncMock(return_value=conn)):
        assert await tenant_policy.active_policy("default") == cfg
    assert conn.fetchrow.call_args[0][1] == "default"


@pytest.mark.asyncio
async def test_missing_policy_returns_none():
    conn = _conn(None)
    with patch("agcms.gateway.tenant_policy.asyncpg.connect", AsyncMock(return_value=conn)):
        assert await tenant_policy.active_policy("t-none") is None


@pytest.mark.asyncio
async def test_cache_hit_skips_db_until_invalidated():
    conn = _conn({"config": {"pii": {"enabled": True}}})
    connect = AsyncMock(return_value=conn)
    with patch("agcms.gateway.tenant_policy.asyncpg.connect", connect):
        await tenant_policy.active_policy("default")
        await tenant_policy.active_policy("default")
        assert connect.await_count == 1
        tenant_policy.invalidate("default")
        await tenant_policy.active_policy("default")
        assert connect.await_count == 2


@pytest.mark.asyncio
async def test_db_error_propagates():
    """The gateway's fail-closed handler decides what to do; we do not swallow it."""
    with patch("agcms.gateway.tenant_policy.asyncpg.connect", AsyncMock(side_effect=OSError("db down"))):
        with pytest.raises(OSError):
            await tenant_policy.active_policy("default")
