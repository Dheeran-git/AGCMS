"""Unit tests for the AGCMS Management REST API (gateway /api/v1/*).

Covers every endpoint group:
  - Auth proxies (token, refresh, me)
  - Audit logs (list, get, export CSV, verify)
  - Policy (get active, PUT with version bump, list versions)
  - Users (list, create, duplicate 409, soft delete)
  - Escalations (list, status filter, update)
  - Stats (overview, timeseries)
  - Tenant admin proxies (provision, usage, settings)
  - RBAC enforcement (role gating)

Mocking strategy:
  - ``asyncpg.connect`` → replaced with AsyncMock returning a FakeConn
  - ``httpx.AsyncClient`` → replaced with a FakeHttpxClient context manager
  - ``get_current_auth`` → injected via FastAPI ``dependency_overrides``
    with a synthetic ``AuthContext`` (no real JWT).
"""

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import asyncpg  # noqa: E402

from agcms.gateway.auth import AuthContext  # noqa: E402
from agcms.gateway.management_api import router  # noqa: E402
from agcms.gateway.rbac import get_current_auth  # noqa: E402


# ==================================================================
# Fake DB connection
# ==================================================================


class FakeTxn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeConn:
    """Minimal async stand-in for an asyncpg connection."""

    def __init__(self) -> None:
        self.fetch = AsyncMock(return_value=[])
        self.fetchrow = AsyncMock(return_value=None)
        self.fetchval = AsyncMock(return_value=0)
        self.execute = AsyncMock(return_value="OK")
        self.close = AsyncMock(return_value=None)

    def transaction(self) -> FakeTxn:
        return FakeTxn()


def _patch_asyncpg(fake_conn: FakeConn):
    """Build an AsyncMock suitable for patching ``asyncpg.connect``."""
    return patch(
        "agcms.gateway.management_api.asyncpg.connect",
        new_callable=AsyncMock,
        return_value=fake_conn,
    )


# ==================================================================
# Fake httpx client (async context manager)
# ==================================================================


class FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


class FakeHttpxClient:
    """Replaces ``httpx.AsyncClient(...)`` — supports context manager + verb methods."""

    def __init__(self, response: FakeResponse):
        self._response = response
        self.calls: list[tuple[str, str, dict]] = []

    # Constructor-call form: FakeHttpxClient(timeout=...) returns self
    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._response

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._response

    async def put(self, url, **kwargs):
        self.calls.append(("PUT", url, kwargs))
        return self._response


def _patch_httpx(fake_client: FakeHttpxClient):
    return patch(
        "agcms.gateway.management_api.httpx.AsyncClient",
        return_value=fake_client,
    )


# ==================================================================
# Test app builder + role contexts
# ==================================================================


_ADMIN = AuthContext(tenant_id="t1", user_id="admin-user", role="admin", auth_method="jwt")
_COMPLIANCE = AuthContext(tenant_id="t1", user_id="comp-user", role="compliance", auth_method="jwt")
_USER = AuthContext(tenant_id="t1", user_id="normal-user", role="user", auth_method="jwt")


def _make_app(ctx: AuthContext | None) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    if ctx is not None:
        app.dependency_overrides[get_current_auth] = lambda: ctx
    return app


# ==================================================================
# 1. Auth proxy endpoints (no role gate)
# ==================================================================


class TestAuthProxies:
    def test_auth_token_proxies_to_auth_service(self):
        fake_client = FakeHttpxClient(FakeResponse(200, {"access_token": "abc", "refresh_token": "r"}))
        app = _make_app(None)
        with _patch_httpx(fake_client):
            resp = TestClient(app).post(
                "/api/v1/auth/token",
                json={"api_key": "agcms_test_key_for_development"},
            )
        assert resp.status_code == 200
        assert resp.json()["access_token"] == "abc"
        assert any(c[0] == "POST" and c[1].endswith("/v1/auth/token") for c in fake_client.calls)

    def test_auth_refresh_proxies_to_auth_service(self):
        fake_client = FakeHttpxClient(FakeResponse(200, {"access_token": "new"}))
        app = _make_app(None)
        with _patch_httpx(fake_client):
            resp = TestClient(app).post(
                "/api/v1/auth/refresh",
                json={"refresh_token": "old-token"},
            )
        assert resp.status_code == 200
        assert resp.json()["access_token"] == "new"

    def test_auth_me_forwards_authorization_header(self):
        fake_client = FakeHttpxClient(FakeResponse(200, {"user_id": "u1", "role": "admin"}))
        app = _make_app(None)
        with _patch_httpx(fake_client):
            resp = TestClient(app).get(
                "/api/v1/auth/me",
                headers={"Authorization": "Bearer some-jwt"},
            )
        assert resp.status_code == 200
        # Verify the Authorization header was forwarded
        assert fake_client.calls[0][2]["headers"]["Authorization"] == "Bearer some-jwt"


# ==================================================================
# 2. Audit endpoints
# ==================================================================


class TestAuditEndpoints:
    def _sample_row(self, **overrides):
        base = {
            "interaction_id": uuid4(),
            "tenant_id": "t1",
            "user_id": "u1",
            "department": "engineering",
            "created_at": datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc),
            "enforcement_action": "ALLOW",
            "enforcement_reason": None,
            "pii_detected": False,
            "pii_entity_types": [],
            "pii_risk_level": None,
            "injection_score": 0.12,
            "injection_type": None,
            "response_violated": False,
            "total_latency_ms": 123,
        }
        base.update(overrides)
        return base

    def test_list_audit_logs_filters_by_tenant(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [self._sample_row(), self._sample_row()]
        fake_conn.fetchval.return_value = 2

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/audit/logs?limit=10&offset=0")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["logs"]) == 2
        assert data["logs"][0]["tenant_id"] == "t1"
        # The query must include tenant_id filter
        call_args = fake_conn.fetch.call_args.args
        assert "tenant_id = $1" in call_args[0]
        assert call_args[1] == "t1"

    def test_list_audit_logs_applies_action_filter(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = []
        fake_conn.fetchval.return_value = 0

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/audit/logs?action=BLOCK")

        assert resp.status_code == 200
        call_args = fake_conn.fetch.call_args.args
        assert "enforcement_action" in call_args[0]
        assert "BLOCK" in call_args

    def test_get_audit_log_not_found_returns_404(self):
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = None

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get(f"/api/v1/audit/logs/{uuid4()}")

        assert resp.status_code == 404

    def test_get_audit_log_invalid_uuid_returns_400(self):
        app = _make_app(_COMPLIANCE)
        resp = TestClient(app).get("/api/v1/audit/logs/not-a-uuid")
        assert resp.status_code == 400

    def test_export_audit_logs_csv(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [self._sample_row()]

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/audit/export?format=csv&limit=100")

        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "attachment" in resp.headers["content-disposition"]
        # CSV should have header row + data row
        body = resp.text
        assert "interaction_id" in body
        assert "tenant_id" in body

    def test_export_audit_logs_json(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [self._sample_row()]

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/audit/export?format=json")

        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == "t1"
        assert data["count"] == 1

    def test_verify_audit_log_proxies_to_audit_service(self):
        fake_client = FakeHttpxClient(FakeResponse(200, {"verified": True, "interaction_id": "x", "tenant_id": "t1"}))
        iid = str(uuid4())

        app = _make_app(_COMPLIANCE)
        with _patch_httpx(fake_client):
            resp = TestClient(app).post(f"/api/v1/audit/verify/{iid}")

        assert resp.status_code == 200
        assert resp.json()["verified"] is True
        assert any(f"/verify/{iid}" in c[1] for c in fake_client.calls)


# ==================================================================
# 3. Policy endpoints
# ==================================================================


class TestPolicyEndpoints:
    def _policy_row(self, version="1.0.0", is_active=True):
        return {
            "id": uuid4(),
            "tenant_id": "t1",
            "config": '{"pii": {"enabled": true}}',  # JSONB comes back as str
            "version": version,
            "is_active": is_active,
            "created_at": datetime(2026, 4, 1, tzinfo=timezone.utc),
            "notes": None,
        }

    def test_get_active_policy_returns_row(self):
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = self._policy_row()

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/policy")

        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "1.0.0"
        assert data["is_active"] is True
        assert data["config"]["pii"]["enabled"] is True

    def test_get_active_policy_404_when_none(self):
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = None

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/policy")

        assert resp.status_code == 404

    def test_update_policy_bumps_patch_version(self):
        fake_conn = FakeConn()
        # First call: current version lookup (1.0.0)
        # Second call: INSERT RETURNING new row (1.0.1)
        fake_conn.fetchrow.side_effect = [
            {"version": "1.0.0"},
            self._policy_row(version="1.0.1"),
        ]

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).put(
                "/api/v1/policy",
                json={"config": {"pii": {"enabled": True}}, "notes": "bump"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "1.0.1"
        # One UPDATE to deactivate, one INSERT via fetchrow
        assert fake_conn.execute.call_count == 1
        assert "UPDATE policies" in fake_conn.execute.call_args.args[0]

    def test_update_policy_first_version_is_1_0_0(self):
        fake_conn = FakeConn()
        # No current version → first insert should be 1.0.0
        fake_conn.fetchrow.side_effect = [
            None,
            self._policy_row(version="1.0.0"),
        ]

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).put(
                "/api/v1/policy",
                json={"config": {"injection": {"threshold": 0.7}}},
            )

        assert resp.status_code == 200
        # The INSERT fetchrow call must have "1.0.0" as the version arg
        insert_call = fake_conn.fetchrow.call_args_list[-1]
        assert "1.0.0" in insert_call.args

    def test_list_policy_versions(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [
            self._policy_row(version="1.0.1", is_active=True),
            self._policy_row(version="1.0.0", is_active=False),
        ]

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/policy/versions")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["versions"]) == 2
        assert data["versions"][0]["version"] == "1.0.1"


# ==================================================================
# 4. Users endpoints
# ==================================================================


class TestUsersEndpoints:
    def _user_row(self, external_id="u1", role="user"):
        return {
            "id": uuid4(),
            "tenant_id": "t1",
            "external_id": external_id,
            "email": f"{external_id}@ex.com",
            "department": "eng",
            "role": role,
            "is_active": True,
            "created_at": datetime(2026, 4, 1, tzinfo=timezone.utc),
        }

    def test_list_users_tenant_filtered(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [self._user_row("u1"), self._user_row("u2")]

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/users")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["users"]) == 2
        call_args = fake_conn.fetch.call_args.args
        assert "tenant_id = $1" in call_args[0]
        assert call_args[1] == "t1"

    def test_create_user_success(self):
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = self._user_row("new-user", role="compliance")

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).post(
                "/api/v1/users",
                json={
                    "external_id": "new-user",
                    "email": "new@ex.com",
                    "role": "compliance",
                    "department": "legal",
                },
            )

        assert resp.status_code == 201
        assert resp.json()["role"] == "compliance"

    def test_create_user_duplicate_returns_409(self):
        fake_conn = FakeConn()
        fake_conn.fetchrow.side_effect = asyncpg.UniqueViolationError("duplicate key")

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).post(
                "/api/v1/users",
                json={"external_id": "dup", "role": "user"},
            )

        assert resp.status_code == 409

    def test_delete_user_soft_deletes(self):
        user_uuid = uuid4()
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = {"id": user_uuid}

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).delete(f"/api/v1/users/{user_uuid}")

        assert resp.status_code == 200
        assert resp.json()["message"] == "User deactivated"
        # UPDATE is via fetchrow (RETURNING id), not execute
        call_args = fake_conn.fetchrow.call_args.args
        assert "is_active = FALSE" in call_args[0]

    def test_delete_user_not_found(self):
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = None

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).delete(f"/api/v1/users/{uuid4()}")

        assert resp.status_code == 404


# ==================================================================
# 5. Escalations endpoints
# ==================================================================


class TestEscalationsEndpoints:
    def _escalation_row(self, status="PENDING"):
        return {
            "id": uuid4(),
            "interaction_id": uuid4(),
            "tenant_id": "t1",
            "created_at": datetime(2026, 4, 1, tzinfo=timezone.utc),
            "reason": "Critical PII detected",
            "status": status,
            "reviewed_by": None,
            "reviewed_at": None,
            "notes": None,
        }

    def test_list_escalations_no_filter(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [
            self._escalation_row("PENDING"),
            self._escalation_row("REVIEWED"),
        ]

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/escalations")

        assert resp.status_code == 200
        assert len(resp.json()["escalations"]) == 2

    def test_list_escalations_with_status_filter(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [self._escalation_row("PENDING")]

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/escalations?status=PENDING")

        assert resp.status_code == 200
        call_args = fake_conn.fetch.call_args.args
        assert "status = $2" in call_args[0]
        assert "PENDING" in call_args

    def test_update_escalation_sets_reviewed_at(self):
        esc_uuid = uuid4()
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = self._escalation_row("REVIEWED")

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).put(
                f"/api/v1/escalations/{esc_uuid}",
                json={"status": "REVIEWED", "notes": "looked at it"},
            )

        assert resp.status_code == 200
        call_args = fake_conn.fetchrow.call_args.args
        assert "reviewed_at = NOW()" in call_args[0]
        assert "REVIEWED" in call_args


# ==================================================================
# 6. Stats endpoints
# ==================================================================


class TestStatsEndpoints:
    def test_stats_overview(self):
        fake_conn = FakeConn()
        fake_conn.fetchrow.return_value = {
            "total_requests": 1000,
            "violations": 42,
            "pii_detections": 15,
            "injection_blocks": 7,
            "avg_latency_ms": 123.456,
        }

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/stats/overview")

        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == "t1"
        assert data["total_requests"] == 1000
        assert data["violations"] == 42
        assert data["avg_latency_ms"] == 123.5
        assert data["period"] == "24h"

    def test_stats_timeseries(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [
            {
                "hour": datetime(2026, 4, 1, 10, tzinfo=timezone.utc),
                "total": 50,
                "violations": 2,
                "pii": 1,
            },
            {
                "hour": datetime(2026, 4, 1, 11, tzinfo=timezone.utc),
                "total": 75,
                "violations": 3,
                "pii": 0,
            },
        ]

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/stats/timeseries?hours=24")

        assert resp.status_code == 200
        data = resp.json()
        assert data["hours"] == 24
        assert len(data["buckets"]) == 2
        assert data["buckets"][0]["total"] == 50

    def test_stats_departments(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = [
            {"department": "engineering", "total": 500, "violations": 10},
            {"department": "legal", "total": 200, "violations": 5},
        ]

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/stats/departments")

        assert resp.status_code == 200
        data = resp.json()
        assert data["period"] == "7d"
        assert len(data["departments"]) == 2
        assert data["departments"][0]["department"] == "engineering"


# ==================================================================
# 7. Tenant admin proxy endpoints
# ==================================================================


class TestTenantProxies:
    def test_tenant_provision_forwards(self):
        fake_client = FakeHttpxClient(FakeResponse(201, {"tenant_id": "acme", "api_key": "k"}))
        app = _make_app(_ADMIN)
        with _patch_httpx(fake_client):
            resp = TestClient(app).post(
                "/api/v1/tenant/provision",
                json={"name": "Acme Corp", "admin_email": "a@a.com", "plan": "starter"},
            )
        assert resp.status_code == 200  # _passthrough doesn't rewrite 201 → 200 but doesn't fail
        assert resp.json()["tenant_id"] == "acme"
        assert any(c[1].endswith("/provision") for c in fake_client.calls)

    def test_tenant_usage_uses_ctx_tenant_id(self):
        fake_client = FakeHttpxClient(FakeResponse(200, {"tenant_id": "t1", "requests_today": 100}))
        app = _make_app(_ADMIN)
        with _patch_httpx(fake_client):
            resp = TestClient(app).get("/api/v1/tenant/usage")
        assert resp.status_code == 200
        # URL must contain the caller's tenant_id
        assert any("/tenants/t1/usage" in c[1] for c in fake_client.calls)

    def test_tenant_settings_forwards_put(self):
        fake_client = FakeHttpxClient(FakeResponse(200, {"ok": True}))
        app = _make_app(_ADMIN)
        with _patch_httpx(fake_client):
            resp = TestClient(app).put(
                "/api/v1/tenant/settings",
                json={"settings": {"requests_per_minute": 60}},
            )
        assert resp.status_code == 200
        assert any("/tenants/t1/settings" in c[1] and c[0] == "PUT" for c in fake_client.calls)


# ==================================================================
# 8. RBAC enforcement
# ==================================================================


class TestRBACEnforcement:
    def test_user_role_cannot_list_audit_logs(self):
        app = _make_app(_USER)
        resp = TestClient(app).get("/api/v1/audit/logs")
        assert resp.status_code == 403

    def test_user_role_cannot_update_policy(self):
        app = _make_app(_USER)
        resp = TestClient(app).put(
            "/api/v1/policy",
            json={"config": {}},
        )
        assert resp.status_code == 403

    def test_compliance_cannot_update_policy_needs_admin(self):
        app = _make_app(_COMPLIANCE)
        resp = TestClient(app).put(
            "/api/v1/policy",
            json={"config": {}},
        )
        assert resp.status_code == 403

    def test_compliance_can_read_audit_logs(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = []
        fake_conn.fetchval.return_value = 0

        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/audit/logs")

        assert resp.status_code == 200

    def test_admin_bypasses_compliance_gate(self):
        fake_conn = FakeConn()
        fake_conn.fetch.return_value = []
        fake_conn.fetchval.return_value = 0

        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/audit/logs")

        assert resp.status_code == 200

    def test_user_role_cannot_list_users(self):
        app = _make_app(_USER)
        resp = TestClient(app).get("/api/v1/users")
        assert resp.status_code == 403


# ==================================================================
# 9. Compliance Reports
# ==================================================================


def _make_fake_conn_for_reports(
    total_requests: int = 100,
    total_pii: int = 10,
    pii_redacted: int = 7,
    pii_blocked: int = 2,
    pii_escalated: int = 1,
    esc_total: int = 3,
    esc_pending: int = 1,
    esc_resolved: int = 2,
    policy_changes: int = 2,
    policy_config: dict | None = None,
) -> FakeConn:
    """Build a FakeConn that returns realistic data for report queries."""
    if policy_config is None:
        policy_config = {
            "pii": {"enabled": True, "critical_action": "BLOCK", "custom_patterns": {}},
            "injection": {"enabled": True, "block_threshold": 0.65},
        }

    import json as _json

    fake_conn = FakeConn()

    # fetchrow is called 3× in order: agg, esc_agg, active_policy_row
    call_count = [0]

    async def _fetchrow_side_effect(query, *args):
        call_count[0] += 1
        n = call_count[0]
        if n == 1:  # core agg
            return {
                "total_requests": total_requests,
                "total_pii": total_pii,
                "pii_redacted": pii_redacted,
                "pii_blocked": pii_blocked,
                "pii_escalated": pii_escalated,
            }
        if n == 2:  # escalation agg
            return {
                "total": esc_total,
                "pending": esc_pending,
                "resolved": esc_resolved,
            }
        # active policy config
        return {"config": _json.dumps(policy_config)}

    fake_conn.fetchrow = _fetchrow_side_effect  # type: ignore[assignment]
    fake_conn.fetchval = AsyncMock(return_value=policy_changes)
    return fake_conn


class TestComplianceReports:
    def test_gdpr_report_returns_200_with_required_keys(self):
        fake_conn = _make_fake_conn_for_reports()
        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/gdpr")

        assert resp.status_code == 200
        body = resp.json()
        assert body["report_type"] == "gdpr"
        assert "generated_at" in body
        assert "tenant_id" in body
        assert "total_requests" in body
        assert "total_pii_detections" in body
        assert "pii_redacted" in body
        assert "pii_blocked" in body
        assert "pii_escalated" in body
        assert "data_categories_processed" in body
        assert "cross_border_transfers" in body
        assert "retention_policy" in body
        assert "findings" in body

    def test_gdpr_report_values_match_db(self):
        fake_conn = _make_fake_conn_for_reports(
            total_requests=500, total_pii=40, pii_redacted=30, pii_blocked=5, pii_escalated=5
        )
        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/gdpr")

        body = resp.json()
        assert body["total_requests"] == 500
        assert body["total_pii_detections"] == 40
        assert body["pii_redacted"] == 30

    def test_gdpr_report_tenant_id_matches_auth_ctx(self):
        fake_conn = _make_fake_conn_for_reports()
        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/gdpr")

        assert resp.json()["tenant_id"] == "t1"

    def test_eu_ai_act_report_returns_200_with_required_keys(self):
        fake_conn = _make_fake_conn_for_reports()
        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/eu-ai-act")

        assert resp.status_code == 200
        body = resp.json()
        assert body["report_type"] == "eu-ai-act"
        assert body["system_name"] == "AGCMS"
        assert "risk_classification" in body
        assert "injection_detection_enabled" in body
        assert "human_oversight_escalations" in body
        assert "audit_trail_signed" in body
        assert "policy_changes_30d" in body
        assert "findings" in body

    def test_eu_ai_act_escalation_counts_match_db(self):
        fake_conn = _make_fake_conn_for_reports(esc_total=5, esc_pending=2, esc_resolved=3)
        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/eu-ai-act")

        body = resp.json()
        assert body["human_oversight_escalations"] == 5
        assert body["pending_escalations"] == 2
        assert body["resolved_escalations"] == 3

    def test_unknown_report_type_returns_404(self):
        fake_conn = FakeConn()
        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/soc2")

        assert resp.status_code == 404

    def test_compliance_role_can_access_reports(self):
        fake_conn = _make_fake_conn_for_reports()
        app = _make_app(_COMPLIANCE)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/gdpr")
        assert resp.status_code == 200

    def test_admin_role_can_access_reports(self):
        fake_conn = _make_fake_conn_for_reports()
        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/gdpr")
        assert resp.status_code == 200

    def test_user_role_cannot_access_reports(self):
        app = _make_app(_USER)
        resp = TestClient(app).get("/api/v1/reports/gdpr")
        assert resp.status_code == 403

    def test_gdpr_findings_list_is_non_empty(self):
        fake_conn = _make_fake_conn_for_reports()
        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/gdpr")

        findings = resp.json()["findings"]
        assert isinstance(findings, list)
        assert len(findings) > 0
        for f in findings:
            assert "check" in f
            assert f["status"] in ("pass", "fail", "warning")
            assert "detail" in f

    def test_eu_ai_act_audit_trail_signed_is_true(self):
        fake_conn = _make_fake_conn_for_reports()
        app = _make_app(_ADMIN)
        with _patch_asyncpg(fake_conn):
            resp = TestClient(app).get("/api/v1/reports/eu-ai-act")
        assert resp.json()["audit_trail_signed"] is True
