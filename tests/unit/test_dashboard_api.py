"""Dashboard API: every route needs a caller, and every query is scoped to the caller's tenant.

The Playground runs the governed lifecycle as the caller's tenant, sends that
tenant's policy to the scanners and the response checker, and fails closed.
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient
from jose import jwt

from agcms.gateway import dashboard_api
from agcms.gateway.main import app

POLICY = {"pii": {"custom_patterns": {"EMPLOYEE_ID": r"EMP-\d{4}"}}}


def _auth(role: str = "admin", tenant: str = "acme") -> dict:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": tenant, "user_id": "alice", "role": role, "type": "access",
         "iat": now, "exp": now + timedelta(minutes=5)},
        os.environ["JWT_SECRET_KEY"], algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


client = TestClient(app)


class TestReadRoutes:
    def test_routes_reject_anonymous_callers(self):
        for path in ("/stats", "/violations", "/timeline", "/playground/providers"):
            assert client.get(f"/api/dashboard{path}").status_code == 401

    def test_user_role_cannot_read_tenant_stats(self):
        assert client.get("/api/dashboard/stats", headers=_auth(role="user")).status_code == 403

    def test_stats_are_scoped_to_the_callers_tenant(self):
        row = {"total_requests": 3, "violations": 1, "pii_detections": 1,
               "injection_blocks": 0, "avg_latency_ms": 12.34}
        fetch = AsyncMock(return_value=row)
        with patch.object(dashboard_api, "_fetch", fetch):
            resp = client.get("/api/dashboard/stats", headers=_auth(tenant="acme"))
        assert resp.status_code == 200
        assert resp.json()["avg_latency_ms"] == 12.3
        assert fetch.await_args.args[1] == "acme"

    def test_database_down_is_503_not_empty_200(self):
        with patch.object(dashboard_api.asyncpg, "connect", AsyncMock(side_effect=OSError("refused"))):
            resp = client.get("/api/dashboard/timeline", headers=_auth())
        assert resp.status_code == 503


class FakeClient:
    """Stands in for httpx.AsyncClient; records posted bodies, fails listed services."""

    posted: dict[str, dict] = {}
    replies: dict[str, dict] = {}
    down: set[str] = set()

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json):
        service = url.split("//")[1].split(":")[0]
        FakeClient.posted[service] = json
        if service in FakeClient.down:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json=FakeClient.replies.get(service, {}))


def _chat(decision="ALLOW", down=()):
    FakeClient.posted = {}
    FakeClient.down = set(down)
    FakeClient.replies = {
        "pii": {"has_pii": False, "entities": [], "risk_level": "NONE", "masked_text": None},
        "injection": {"risk_score": 0.0, "triggered_rules": []},
        "policy": {"action": decision, "reason": None, "triggered_policies": []},
        "response": {"violated": False, "violations": []},
    }
    llm = AsyncMock(return_value={"choices": [{"message": {"content": "Hello."}}]})
    with patch.object(dashboard_api.httpx, "AsyncClient", FakeClient), \
         patch.object(dashboard_api, "active_policy", AsyncMock(return_value=POLICY)) as policy, \
         patch.object(dashboard_api, "check_rate_limit", AsyncMock(return_value=(True, 1))), \
         patch.object(dashboard_api, "forward_to_llm", llm):
        resp = client.post("/api/dashboard/playground/chat",
                           json={"message": "Hi there"}, headers=_auth(tenant="acme"))
    return resp, llm, policy


class TestPlayground:
    def test_runs_as_callers_tenant_with_its_policy(self):
        resp, llm, policy = _chat()
        assert resp.status_code == 200
        assert resp.json()["llm_response"] == "Hello."
        policy.assert_awaited_once_with("acme")
        assert FakeClient.posted["pii"]["policy"] == POLICY["pii"]
        assert FakeClient.posted["response"]["policy"] == POLICY

    def test_block_never_reaches_the_provider(self):
        resp, llm, _ = _chat(decision="BLOCK")
        assert resp.status_code == 200
        llm.assert_not_awaited()

    def test_scanner_outage_fails_closed(self):
        resp, llm, _ = _chat(down={"injection"})
        assert resp.status_code == 503
        llm.assert_not_awaited()

    def test_policy_outage_fails_closed(self):
        resp, llm, _ = _chat(down={"policy"})
        assert resp.status_code == 503
        llm.assert_not_awaited()

    def test_empty_message_is_rejected(self):
        resp = client.post("/api/dashboard/playground/chat",
                           json={"message": "   "}, headers=_auth())
        assert resp.status_code == 422
