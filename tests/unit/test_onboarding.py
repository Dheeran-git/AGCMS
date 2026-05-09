"""Phase 7.1 — onboarding wizard endpoint tests."""
from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")
os.environ.setdefault("AGCMS_SIGNING_KEY", "test-row-signing-key-phase-5-fixture")
os.environ.setdefault("AGCMS_ANCHOR_KEY", "test-anchor-key-phase-5-fixture")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agcms.gateway.auth import AuthContext  # noqa: E402
from agcms.gateway.onboarding import (  # noqa: E402
    FRAMEWORKS,
    _mark_completed,
    _suggested_packs,
    router as onboarding_router,
)
from agcms.gateway.rbac import get_current_auth  # noqa: E402


TENANT = "t1"


class FakeConn:
    def __init__(self, initial_state: dict | None = None) -> None:
        self.state = initial_state or {}
        self.fetch = AsyncMock(return_value=[])
        self.fetchrow = AsyncMock(side_effect=self._fetchrow)
        self.execute = AsyncMock(side_effect=self._execute)
        self.close = AsyncMock(return_value=None)

    async def _fetchrow(self, query, *args):
        if "SELECT onboarding_state FROM tenants" in query:
            return {"onboarding_state": json.dumps(self.state)}
        return None

    async def _execute(self, query, *args):
        if "UPDATE tenants SET onboarding_state" in query:
            _tenant_id, payload = args
            self.state = json.loads(payload)
        return "OK"


def _patch_conn(conn: FakeConn):
    return patch(
        "agcms.gateway.onboarding.asyncpg.connect",
        new_callable=AsyncMock,
        return_value=conn,
    )


_ADMIN = AuthContext(tenant_id=TENANT, user_id="admin-a", role="admin", auth_method="jwt")
_USER = AuthContext(tenant_id=TENANT, user_id="alice", role="user", auth_method="jwt")


def _app(ctx: AuthContext) -> FastAPI:
    app = FastAPI()
    app.include_router(onboarding_router)
    app.dependency_overrides[get_current_auth] = lambda: ctx
    return app


class TestCatalog:
    def test_catalog_lists_every_framework(self):
        # The /catalog endpoint is unauthenticated — no ctx override needed.
        app = FastAPI()
        app.include_router(onboarding_router)
        body = TestClient(app).get("/api/v1/onboarding/catalog").json()
        framework_ids = {f["id"] for f in body["frameworks"]}
        assert framework_ids == set(FRAMEWORKS.keys())
        assert "healthcare" in body["industries"]
        assert "51-200" in body["company_sizes"]
        assert "eu" in body["regions"]


class TestState:
    def test_empty_state_is_not_completed(self):
        conn = FakeConn(initial_state={})
        with _patch_conn(conn):
            body = TestClient(_app(_ADMIN)).get("/api/v1/onboarding/state").json()
        assert body == {"state": {}, "completed": False}

    def test_state_requires_auth(self):
        conn = FakeConn(initial_state={})
        app = FastAPI()
        app.include_router(onboarding_router)
        # No dependency override: authenticate() will try to run and fail 401.
        with _patch_conn(conn):
            resp = TestClient(app).get("/api/v1/onboarding/state")
        assert resp.status_code == 401


class TestTenantProfile:
    def test_admin_sets_profile(self):
        conn = FakeConn(initial_state={})
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post(
                "/api/v1/onboarding/tenant-profile",
                json={
                    "industry": "healthcare",
                    "company_size": "51-200",
                    "region": "us",
                },
            )
        assert resp.status_code == 200, resp.text
        assert conn.state["tenant_profile"]["industry"] == "healthcare"
        assert conn.state["completed"] is False

    def test_invalid_industry_rejected(self):
        conn = FakeConn(initial_state={})
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post(
                "/api/v1/onboarding/tenant-profile",
                json={
                    "industry": "meatpacking",
                    "company_size": "51-200",
                    "region": "us",
                },
            )
        assert resp.status_code == 422

    def test_non_admin_rejected(self):
        conn = FakeConn(initial_state={})
        with _patch_conn(conn):
            resp = TestClient(_app(_USER)).post(
                "/api/v1/onboarding/tenant-profile",
                json={
                    "industry": "healthcare",
                    "company_size": "51-200",
                    "region": "us",
                },
            )
        assert resp.status_code == 403


class TestFrameworks:
    def test_frameworks_selection_populates_suggestions(self):
        conn = FakeConn(initial_state={"tenant_profile": {"industry": "healthcare"}})
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post(
                "/api/v1/onboarding/frameworks",
                json={"selected": ["HIPAA", "SOC_2"]},
            )
        assert resp.status_code == 200, resp.text
        assert conn.state["frameworks"] == ["HIPAA", "SOC_2"]
        assert conn.state["suggested_packs"] == ["hipaa", "soc2-cc"]

    def test_unknown_framework_rejected(self):
        conn = FakeConn(initial_state={})
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post(
                "/api/v1/onboarding/frameworks",
                json={"selected": ["HIPAA", "UNOBTAINIUM_COMPLIANCE"]},
            )
        assert resp.status_code == 422
        assert "UNOBTAINIUM_COMPLIANCE" in resp.json()["detail"]

    def test_empty_selection_rejected(self):
        conn = FakeConn(initial_state={})
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post(
                "/api/v1/onboarding/frameworks",
                json={"selected": []},
            )
        assert resp.status_code == 422


class TestPolicyPacks:
    def test_packs_recorded(self):
        conn = FakeConn(initial_state={})
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post(
                "/api/v1/onboarding/policy-packs",
                json={"packs": ["hipaa", "soc2-cc"]},
            )
        assert resp.status_code == 200
        assert conn.state["policy_packs"] == ["hipaa", "soc2-cc"]


class TestFirstCall:
    def test_first_call_marks_completion(self):
        initial = {
            "tenant_profile": {"industry": "healthcare", "company_size": "51-200", "region": "us"},
            "frameworks": ["HIPAA"],
            "policy_packs": ["hipaa"],
        }
        conn = FakeConn(initial_state=initial)
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post(
                "/api/v1/onboarding/first-call",
                json={"interaction_id": "abc-123"},
            )
        assert resp.status_code == 200
        assert conn.state["first_call"] == {"interaction_id": "abc-123"}
        assert conn.state["completed"] is True


class TestReset:
    def test_reset_clears_state(self):
        conn = FakeConn(initial_state={
            "tenant_profile": {"industry": "healthcare"},
            "frameworks": ["HIPAA"],
            "completed": False,
        })
        with _patch_conn(conn):
            resp = TestClient(_app(_ADMIN)).post("/api/v1/onboarding/reset")
        assert resp.status_code == 200
        assert conn.state == {}


class TestPureHelpers:
    def test_suggested_packs_dedupes(self):
        # If somehow two frameworks mapped to the same pack, the list
        # returned to the UI must be deduped — otherwise the pack loader
        # applies the same YAML twice.
        with patch.dict(FRAMEWORKS, {
            "FAKE_A": {"label": "a", "suggested_pack": "same-pack", "citation_root": ""},
            "FAKE_B": {"label": "b", "suggested_pack": "same-pack", "citation_root": ""},
        }):
            assert _suggested_packs(["FAKE_A", "FAKE_B"]) == ["same-pack"]

    def test_mark_completed_requires_all_four_steps(self):
        assert _mark_completed({"tenant_profile": {}})["completed"] is False
        assert _mark_completed({
            "tenant_profile": {},
            "frameworks": [],
            "policy_packs": [],
            "first_call": {},
        })["completed"] is True
