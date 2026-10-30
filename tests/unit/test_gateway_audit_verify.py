"""The gateway's audit verify routes only ever ask about the caller's own tenant."""

import os
from datetime import datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient
from jose import jwt

from agcms.gateway.api import audit
from agcms.gateway.main import app


def _auth(tenant: str) -> dict:
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": tenant, "user_id": "u", "role": "compliance", "type": "access",
         "iat": now, "exp": now + timedelta(minutes=5)},
        os.environ["JWT_SECRET_KEY"], algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


class FakeClient:
    calls: list[tuple[str, dict]] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, params=None):
        FakeClient.calls.append((url, params))
        return httpx.Response(200, json={"ok": True})


def _get(method, path, monkeypatch):
    FakeClient.calls = []
    monkeypatch.setattr(audit.httpx, "AsyncClient", FakeClient)
    return TestClient(app).request(method, path, headers=_auth("acme"))


def test_row_verify_is_scoped_to_callers_tenant(monkeypatch):
    resp = _get("POST", "/api/v1/audit/verify/00000000-0000-0000-0000-000000000001", monkeypatch)
    assert resp.status_code == 200
    assert FakeClient.calls[0][1] == {"tenant_id": "acme"}


def test_chain_verify_is_scoped_to_callers_tenant(monkeypatch):
    resp = _get("GET", "/api/v1/audit/chain/verify?tenant_id=other&start=2026-01-01", monkeypatch)
    assert resp.status_code == 200
    url, params = FakeClient.calls[0]
    assert url.endswith("/chain/verify")
    assert params == {"tenant_id": "acme", "start": "2026-01-01"}


def test_chain_verify_needs_a_caller():
    assert TestClient(app).get("/api/v1/audit/chain/verify").status_code == 401
