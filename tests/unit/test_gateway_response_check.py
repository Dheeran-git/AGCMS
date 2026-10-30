"""The gateway sends the tenant's active policy to the response checker.

Without it, restricted topics and system-prompt keywords configured in the
tenant policy are never checked on the live request path.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi.testclient import TestClient

from agcms.gateway import main

POLICY = {"response_compliance": {"restricted_topics": ["project titan"]}}
REPLIES = {
    "/scan": {"entities": [], "risk_score": 0.0, "triggered_rules": []},
    "/resolve": {"action": "ALLOW", "reason": None, "triggered_policies": []},
    "/check": {"violations": []},
}


class FakeClient:
    """Stands in for httpx.AsyncClient and records every JSON body posted."""

    posted: dict[str, dict] = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json):
        path = "/" + url.rsplit("/", 1)[1]
        FakeClient.posted[path] = json
        return httpx.Response(200, json=REPLIES[path])


def test_response_check_receives_tenant_policy():
    ctx = MagicMock(tenant_id="t1", auth_method="api_key")
    ctx.has_scope.return_value = True
    llm_reply = {"choices": [{"message": {"role": "assistant", "content": "Project Titan ships in Q3."}}]}
    with patch.object(main.httpx, "AsyncClient", FakeClient), \
         patch.object(main, "check_global_ip_rate_limit", AsyncMock(return_value=(True, 1))), \
         patch.object(main, "authenticate", AsyncMock(return_value=(ctx, None))), \
         patch.object(main, "active_policy", AsyncMock(return_value=POLICY)), \
         patch.object(main, "check_rate_limit", AsyncMock(return_value=(True, 1))), \
         patch.object(main, "forward_to_llm", AsyncMock(return_value=llm_reply)), \
         patch.object(main, "_audit_log", AsyncMock()):
        resp = TestClient(main.app).post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "When does the launch ship?"}]},
            headers={"Authorization": "Bearer key"},
        )
    assert resp.status_code == 200
    assert FakeClient.posted["/check"]["policy"] == POLICY
