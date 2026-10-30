"""Gateway rate-limit inputs: the trusted client IP, a Redis outage, and audit-sized headers."""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from agcms.gateway import main

_BODY = {"messages": [{"role": "user", "content": "hello"}]}


def _post(headers=None, ip_limit=None, tenant_limit=None):
    ctx = MagicMock(tenant_id="t1", auth_method="api_key")
    ctx.has_scope.return_value = True
    ip_limit = ip_limit or AsyncMock(return_value=(True, 1))
    audit = AsyncMock()
    with patch.object(main, "check_global_ip_rate_limit", ip_limit), \
         patch.object(main, "authenticate", AsyncMock(return_value=(ctx, None))), \
         patch.object(main, "active_policy", AsyncMock(return_value={})), \
         patch.object(main, "check_rate_limit", tenant_limit or AsyncMock(return_value=(False, 99))), \
         patch.object(main, "_audit_log", audit):
        resp = TestClient(main.app).post(
            "/v1/chat/completions", json=_BODY,
            headers={"Authorization": "Bearer key", **(headers or {})},
        )
    return resp, ip_limit


def test_forwarded_for_header_cannot_choose_the_rate_limit_ip():
    _, ip_limit = _post(headers={"X-Forwarded-For": "203.0.113.9"})
    assert ip_limit.await_args.args[0] != "203.0.113.9"


def test_redis_outage_on_ip_limit_is_503():
    resp, _ = _post(ip_limit=AsyncMock(side_effect=RedisConnectionError("down")))
    assert resp.status_code == 503
    assert resp.json()["error"] == "governance_unavailable"


def test_redis_outage_on_tenant_limit_is_503():
    resp, _ = _post(tenant_limit=AsyncMock(side_effect=RedisConnectionError("down")))
    assert resp.status_code == 503


def test_redis_outage_fail_open_lets_the_request_through(monkeypatch):
    monkeypatch.setattr(main, "_FAIL_MODE", "open")
    resp, _ = _post(ip_limit=AsyncMock(side_effect=RedisConnectionError("down")))
    assert resp.status_code == 429  # reached the tenant limiter, which is mocked as exceeded
