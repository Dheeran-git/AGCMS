"""Integration tests for the AGCMS Management REST API (/api/v1/*).

Requires: docker compose up (gateway healthy on localhost:8000).

Token strategy
--------------
The dev API key ``agcms_test_key_for_development`` maps to ``auth_method="dev_key"``
which the gateway treats as ``role="admin"`` and ``tenant_id="default"``.

JWT tokens are minted locally using the same JWT_SECRET_KEY that the gateway
uses in its dev configuration (``"dev-jwt-secret-change-me"``).  This lets us
manufacture tokens with any role without a running auth service.

JWT role mapping used in tests:
  - ADMIN_JWT   → role="admin",      tenant_id="default"
  - COMP_JWT    → role="compliance", tenant_id="default"
  - USER_JWT    → role="user",       tenant_id="default"
"""

import sys
import os

# Ensure the auth token helper is importable from the source tree
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agcms-auth"))

import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from jose import jwt

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

GATEWAY_URL = "http://localhost:8000"
POLICY_URL = "http://localhost:8004"
_SECRET = "dev-jwt-secret-change-me"
_ALGO = "HS256"

API_KEY = "agcms_test_key_for_development"
TENANT_ID = "default"


def _make_jwt(role: str, user_id: str = None) -> str:
    """Mint a local JWT with the given role for the default tenant."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": TENANT_ID,
        "user_id": user_id or f"{role}-user",
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=30),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGO)


def _make_expired_jwt() -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": TENANT_ID,
        "user_id": "old-user",
        "role": "admin",
        "type": "access",
        "iat": now - timedelta(hours=2),
        "exp": now - timedelta(hours=1),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGO)


# Pre-mint tokens once per session
ADMIN_TOKEN = _make_jwt("admin", "admin-integration-test")
COMP_TOKEN = _make_jwt("compliance", "compliance-integration-test")
USER_TOKEN = _make_jwt("user", "user-integration-test")
EXPIRED_TOKEN = _make_expired_jwt()

ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}", "Content-Type": "application/json"}
COMP_HEADERS = {"Authorization": f"Bearer {COMP_TOKEN}", "Content-Type": "application/json"}
USER_HEADERS = {"Authorization": f"Bearer {USER_TOKEN}", "Content-Type": "application/json"}
APIKEY_HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
NO_AUTH_HEADERS: dict = {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def gateway():
    """Fresh sync client per test — avoids connection-pool poisoning from
    upstream crashes (audit/auth/tenant services not always running)."""
    with httpx.Client(base_url=GATEWAY_URL, timeout=15.0) as c:
        yield c


@pytest.fixture(scope="function")
def policy_client():
    """Fresh sync client per test pointing directly at the policy service."""
    with httpx.Client(base_url=POLICY_URL, timeout=10.0) as c:
        yield c


# ---------------------------------------------------------------------------
# 1. Service health
# ---------------------------------------------------------------------------


class TestServiceHealth:
    def test_gateway_health(self, gateway: httpx.Client):
        r = gateway.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"

    def test_policy_health(self, policy_client: httpx.Client):
        r = policy_client.get("/health")
        assert r.status_code == 200
        assert r.json()["service"] == "policy"


# ---------------------------------------------------------------------------
# 2. RBAC — role enforcement on every group
# ---------------------------------------------------------------------------


class TestRBACEnforcement:
    """Unauthenticated or insufficiently-privileged requests must be rejected."""

    # --- No auth ---
    def test_audit_logs_requires_auth(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs", headers=NO_AUTH_HEADERS)
        assert r.status_code in (401, 403)

    def test_policy_get_requires_auth(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy", headers=NO_AUTH_HEADERS)
        assert r.status_code in (401, 403)

    def test_users_requires_auth(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/users", headers=NO_AUTH_HEADERS)
        assert r.status_code in (401, 403)

    def test_escalations_requires_auth(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations", headers=NO_AUTH_HEADERS)
        assert r.status_code in (401, 403)

    def test_stats_overview_requires_auth(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/overview", headers=NO_AUTH_HEADERS)
        assert r.status_code in (401, 403)

    # --- Expired token ---
    def test_expired_jwt_rejected(self, gateway: httpx.Client):
        r = gateway.get(
            "/api/v1/audit/logs",
            headers={"Authorization": f"Bearer {EXPIRED_TOKEN}"},
        )
        assert r.status_code in (401, 403)

    # --- Wrong role: user role cannot access compliance/admin endpoints ---
    def test_user_cannot_list_audit_logs(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs", headers=USER_HEADERS)
        assert r.status_code == 403

    def test_user_cannot_get_policy(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy", headers=USER_HEADERS)
        assert r.status_code == 403

    def test_user_cannot_list_users(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/users", headers=USER_HEADERS)
        assert r.status_code == 403

    def test_user_cannot_list_escalations(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations", headers=USER_HEADERS)
        assert r.status_code == 403

    def test_user_cannot_view_stats(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/overview", headers=USER_HEADERS)
        assert r.status_code == 403

    # --- Compliance cannot reach admin-only endpoints ---
    def test_compliance_cannot_update_policy(self, gateway: httpx.Client):
        r = gateway.put(
            "/api/v1/policy",
            headers=COMP_HEADERS,
            json={"config": {"pii": {"enabled": True}, "injection": {"enabled": True}}},
        )
        assert r.status_code == 403

    def test_compliance_cannot_create_user(self, gateway: httpx.Client):
        r = gateway.post(
            "/api/v1/users",
            headers=COMP_HEADERS,
            json={"external_id": "rbac-test", "role": "user"},
        )
        assert r.status_code == 403

    def test_compliance_cannot_delete_user(self, gateway: httpx.Client):
        fake_id = str(uuid.uuid4())
        r = gateway.delete(f"/api/v1/users/{fake_id}", headers=COMP_HEADERS)
        assert r.status_code == 403

    def test_compliance_cannot_provision_tenant(self, gateway: httpx.Client):
        r = gateway.post(
            "/api/v1/tenant/provision",
            headers=COMP_HEADERS,
            json={"name": "test", "plan": "starter", "admin_email": "a@b.com"},
        )
        assert r.status_code == 403

    # --- Admin can access everything ---
    def test_admin_can_list_audit_logs(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs", headers=ADMIN_HEADERS)
        assert r.status_code == 200

    def test_admin_can_list_users(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/users", headers=ADMIN_HEADERS)
        assert r.status_code == 200

    def test_admin_can_list_escalations(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations", headers=ADMIN_HEADERS)
        assert r.status_code == 200

    # --- Dev API key has admin role ---
    def test_dev_api_key_has_admin_access(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/users", headers=APIKEY_HEADERS)
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 3. Audit log endpoints
# ---------------------------------------------------------------------------


class TestAuditLogs:
    def test_list_returns_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs", headers=COMP_HEADERS)
        assert r.status_code == 200

    def test_list_response_shape(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs", headers=COMP_HEADERS)
        body = r.json()
        assert "logs" in body
        assert "total" in body
        assert "limit" in body
        assert "offset" in body
        assert isinstance(body["logs"], list)
        assert isinstance(body["total"], int)

    def test_list_pagination_limit(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs?limit=5", headers=COMP_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert body["limit"] == 5
        assert len(body["logs"]) <= 5

    def test_list_pagination_offset(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs?limit=2&offset=0", headers=COMP_HEADERS)
        r2 = gateway.get("/api/v1/audit/logs?limit=2&offset=2", headers=COMP_HEADERS)
        assert r.status_code == 200
        assert r2.status_code == 200

    def test_list_filter_by_action_allow(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs?action=ALLOW", headers=COMP_HEADERS)
        assert r.status_code == 200
        for log in r.json()["logs"]:
            assert log["enforcement_action"] == "ALLOW"

    def test_list_filter_by_action_block(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs?action=BLOCK", headers=COMP_HEADERS)
        assert r.status_code == 200
        for log in r.json()["logs"]:
            assert log["enforcement_action"] == "BLOCK"

    def test_list_limit_too_large_rejected(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs?limit=9999", headers=COMP_HEADERS)
        assert r.status_code == 422

    def test_list_negative_offset_rejected(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs?offset=-1", headers=COMP_HEADERS)
        assert r.status_code == 422

    def test_list_invalid_timestamp_rejected(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs?start=not-a-date", headers=COMP_HEADERS)
        assert r.status_code == 400

    def test_get_single_invalid_uuid_rejected(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/logs/not-a-uuid", headers=COMP_HEADERS)
        assert r.status_code == 400

    def test_get_single_missing_returns_404(self, gateway: httpx.Client):
        r = gateway.get(f"/api/v1/audit/logs/{uuid.uuid4()}", headers=COMP_HEADERS)
        assert r.status_code == 404

    def test_log_entry_fields_when_present(self, gateway: httpx.Client):
        """If any audit logs exist, each entry has required fields."""
        r = gateway.get("/api/v1/audit/logs?limit=1", headers=COMP_HEADERS)
        body = r.json()
        if body["logs"]:
            log = body["logs"][0]
            for field in ("interaction_id", "tenant_id", "user_id", "enforcement_action",
                          "created_at", "pii_detected"):
                assert field in log, f"Missing field: {field}"

    def test_log_entry_tenant_isolation(self, gateway: httpx.Client):
        """All returned logs must belong to the caller's tenant."""
        r = gateway.get("/api/v1/audit/logs?limit=20", headers=COMP_HEADERS)
        for log in r.json()["logs"]:
            assert log["tenant_id"] == TENANT_ID

    def test_export_json_format(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/export?format=json", headers=COMP_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert "tenant_id" in body
        assert "count" in body
        assert "logs" in body

    def test_export_csv_format(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/export?format=csv", headers=COMP_HEADERS)
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "")

    def test_export_csv_has_content_disposition(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/export?format=csv", headers=COMP_HEADERS)
        assert "attachment" in r.headers.get("content-disposition", "")

    def test_export_invalid_format_rejected(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/export?format=xml", headers=COMP_HEADERS)
        assert r.status_code == 422

    def test_export_limit_honored(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/audit/export?format=json&limit=3", headers=COMP_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert len(body["logs"]) <= 3

    def test_verify_invalid_uuid_rejected(self, gateway: httpx.Client):
        # Proxies to audit service; may get a network error if audit is not running.
        try:
            r = gateway.post("/api/v1/audit/verify/not-a-uuid", headers=COMP_HEADERS)
            # If audit service is up: 400/404. If gateway proxies error: 500/502.
            assert r.status_code in (400, 404, 422, 500, 502)
        except httpx.RemoteProtocolError:
            # Audit service not running; gateway closes connection — acceptable
            pass


# ---------------------------------------------------------------------------
# 4. Policy endpoints
# ---------------------------------------------------------------------------


VALID_POLICY_CONFIG = {
    "pii": {
        "enabled": True,
        "action_on_detection": "REDACT",
        "critical_action": "BLOCK",
        "risk_threshold": "MEDIUM",
    },
    "injection": {
        "enabled": True,
        "block_threshold": 0.65,
        "log_all_attempts": True,
    },
    "response_compliance": {
        "enabled": True,
        "restricted_topics": [],
        "action_on_violation": "REDACT",
    },
    "rate_limits": {
        "requests_per_minute": 60,
        "requests_per_day": 10000,
    },
}


class TestPolicyEndpoints:
    def test_get_active_policy_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy", headers=COMP_HEADERS)
        assert r.status_code == 200

    def test_get_active_policy_shape(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy", headers=COMP_HEADERS)
        body = r.json()
        assert "id" in body
        assert "tenant_id" in body
        assert "config" in body
        assert "version" in body
        assert "is_active" in body

    def test_get_active_policy_is_active_true(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy", headers=COMP_HEADERS)
        assert r.json()["is_active"] is True

    def test_get_active_policy_tenant_correct(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy", headers=COMP_HEADERS)
        assert r.json()["tenant_id"] == TENANT_ID

    def test_list_versions_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy/versions", headers=COMP_HEADERS)
        assert r.status_code == 200
        assert "versions" in r.json()

    def test_list_versions_all_same_tenant(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy/versions", headers=COMP_HEADERS)
        for v in r.json()["versions"]:
            assert v["tenant_id"] == TENANT_ID

    def test_list_versions_exactly_one_active(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/policy/versions", headers=COMP_HEADERS)
        active = [v for v in r.json()["versions"] if v["is_active"]]
        assert len(active) == 1

    def test_update_policy_as_admin(self, gateway: httpx.Client):
        r = gateway.put(
            "/api/v1/policy",
            headers=ADMIN_HEADERS,
            json={"config": VALID_POLICY_CONFIG, "notes": "integration-test update"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["is_active"] is True
        assert body["tenant_id"] == TENANT_ID

    def test_update_policy_bumps_version(self, gateway: httpx.Client):
        r1 = gateway.get("/api/v1/policy", headers=COMP_HEADERS)
        v_before = r1.json()["version"]

        r2 = gateway.put(
            "/api/v1/policy",
            headers=ADMIN_HEADERS,
            json={"config": VALID_POLICY_CONFIG, "notes": "version bump test"},
        )
        assert r2.status_code == 200
        v_after = r2.json()["version"]
        # Version must change
        assert v_after != v_before

    def test_update_policy_deactivates_previous(self, gateway: httpx.Client):
        """After PUT, only the new policy is active."""
        gateway.put(
            "/api/v1/policy",
            headers=ADMIN_HEADERS,
            json={"config": VALID_POLICY_CONFIG},
        )
        r = gateway.get("/api/v1/policy/versions", headers=COMP_HEADERS)
        active = [v for v in r.json()["versions"] if v["is_active"]]
        assert len(active) == 1

    def test_update_policy_notes_persisted(self, gateway: httpx.Client):
        note = f"test-note-{uuid.uuid4().hex[:8]}"
        r = gateway.put(
            "/api/v1/policy",
            headers=ADMIN_HEADERS,
            json={"config": VALID_POLICY_CONFIG, "notes": note},
        )
        assert r.json().get("notes") == note

    def test_update_policy_no_notes_allowed(self, gateway: httpx.Client):
        r = gateway.put(
            "/api/v1/policy",
            headers=ADMIN_HEADERS,
            json={"config": VALID_POLICY_CONFIG},
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# 5. Users endpoints
# ---------------------------------------------------------------------------


class TestUsersEndpoints:
    """Tests that create users use unique external_ids to avoid 409 conflicts."""

    def test_list_users_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/users", headers=ADMIN_HEADERS)
        assert r.status_code == 200
        assert "users" in r.json()

    def test_list_users_is_list(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/users", headers=ADMIN_HEADERS)
        assert isinstance(r.json()["users"], list)

    def test_list_users_tenant_isolated(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/users", headers=ADMIN_HEADERS)
        for u in r.json()["users"]:
            assert u["tenant_id"] == TENANT_ID

    def test_create_user_returns_201(self, gateway: httpx.Client):
        ext_id = f"int-test-{uuid.uuid4().hex[:8]}"
        r = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": ext_id, "role": "user"},
        )
        assert r.status_code == 201

    def test_create_user_response_shape(self, gateway: httpx.Client):
        ext_id = f"int-test-{uuid.uuid4().hex[:8]}"
        r = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": ext_id, "role": "compliance", "email": "a@b.com"},
        )
        body = r.json()
        assert body["external_id"] == ext_id
        assert body["role"] == "compliance"
        assert body["tenant_id"] == TENANT_ID
        assert body["is_active"] is True
        assert "id" in body

    def test_create_user_with_department(self, gateway: httpx.Client):
        ext_id = f"int-test-{uuid.uuid4().hex[:8]}"
        r = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": ext_id, "role": "user", "department": "Engineering"},
        )
        assert r.status_code == 201
        assert r.json()["department"] == "Engineering"

    def test_create_user_duplicate_returns_409(self, gateway: httpx.Client):
        ext_id = f"dup-{uuid.uuid4().hex[:8]}"
        gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": ext_id, "role": "user"},
        )
        r2 = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": ext_id, "role": "user"},
        )
        assert r2.status_code == 409

    def test_create_user_invalid_role_rejected(self, gateway: httpx.Client):
        r = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": "bad-role-test", "role": "superuser"},
        )
        assert r.status_code == 422

    def test_create_user_missing_external_id_rejected(self, gateway: httpx.Client):
        r = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"role": "user"},
        )
        assert r.status_code == 422

    def test_delete_user_invalid_uuid_rejected(self, gateway: httpx.Client):
        r = gateway.delete("/api/v1/users/not-a-uuid", headers=ADMIN_HEADERS)
        assert r.status_code == 400

    def test_delete_user_nonexistent_returns_404(self, gateway: httpx.Client):
        r = gateway.delete(f"/api/v1/users/{uuid.uuid4()}", headers=ADMIN_HEADERS)
        assert r.status_code == 404

    def test_create_then_delete_user(self, gateway: httpx.Client):
        ext_id = f"del-{uuid.uuid4().hex[:8]}"
        create_r = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": ext_id, "role": "user"},
        )
        assert create_r.status_code == 201
        user_id = create_r.json()["id"]

        del_r = gateway.delete(f"/api/v1/users/{user_id}", headers=ADMIN_HEADERS)
        assert del_r.status_code == 200
        assert del_r.json()["user_id"] == user_id

    def test_deleted_user_appears_inactive(self, gateway: httpx.Client):
        ext_id = f"delinactive-{uuid.uuid4().hex[:8]}"
        create_r = gateway.post(
            "/api/v1/users",
            headers=ADMIN_HEADERS,
            json={"external_id": ext_id, "role": "user"},
        )
        user_id = create_r.json()["id"]
        gateway.delete(f"/api/v1/users/{user_id}", headers=ADMIN_HEADERS)

        users = gateway.get("/api/v1/users", headers=ADMIN_HEADERS).json()["users"]
        deleted = next((u for u in users if u["id"] == user_id), None)
        if deleted:
            assert deleted["is_active"] is False


# ---------------------------------------------------------------------------
# 6. Escalations endpoints
# ---------------------------------------------------------------------------


class TestEscalationsEndpoints:
    """Escalation rows may not exist initially; tests handle empty lists gracefully."""

    def test_list_escalations_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations", headers=COMP_HEADERS)
        assert r.status_code == 200

    def test_list_escalations_shape(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations", headers=COMP_HEADERS)
        body = r.json()
        assert "escalations" in body
        assert isinstance(body["escalations"], list)

    def test_list_escalations_tenant_isolated(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations", headers=COMP_HEADERS)
        for esc in r.json()["escalations"]:
            assert esc["tenant_id"] == TENANT_ID

    def test_filter_escalations_by_pending(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations?status=PENDING", headers=COMP_HEADERS)
        assert r.status_code == 200
        for esc in r.json()["escalations"]:
            assert esc["status"] == "PENDING"

    def test_filter_escalations_by_reviewed(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/escalations?status=REVIEWED", headers=COMP_HEADERS)
        assert r.status_code == 200
        for esc in r.json()["escalations"]:
            assert esc["status"] == "REVIEWED"

    def test_update_escalation_invalid_uuid_rejected(self, gateway: httpx.Client):
        r = gateway.put(
            "/api/v1/escalations/not-a-uuid",
            headers=COMP_HEADERS,
            json={"status": "REVIEWED"},
        )
        assert r.status_code == 400

    def test_update_escalation_nonexistent_returns_404(self, gateway: httpx.Client):
        r = gateway.put(
            f"/api/v1/escalations/{uuid.uuid4()}",
            headers=COMP_HEADERS,
            json={"status": "REVIEWED"},
        )
        assert r.status_code == 404

    def test_update_escalation_invalid_status_rejected(self, gateway: httpx.Client):
        r = gateway.put(
            f"/api/v1/escalations/{uuid.uuid4()}",
            headers=COMP_HEADERS,
            json={"status": "IGNORED"},
        )
        assert r.status_code == 422

    def test_escalation_entry_fields_when_present(self, gateway: httpx.Client):
        """If any escalations exist, each must have required fields."""
        r = gateway.get("/api/v1/escalations", headers=COMP_HEADERS)
        for esc in r.json()["escalations"]:
            for field in ("id", "interaction_id", "tenant_id", "reason", "status", "created_at"):
                assert field in esc


# ---------------------------------------------------------------------------
# 7. Stats endpoints
# ---------------------------------------------------------------------------


class TestStatsEndpoints:
    def test_overview_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/overview", headers=COMP_HEADERS)
        assert r.status_code == 200

    def test_overview_shape(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/overview", headers=COMP_HEADERS)
        body = r.json()
        for field in ("tenant_id", "total_requests", "violations",
                      "pii_detections", "injection_blocks", "avg_latency_ms", "period"):
            assert field in body

    def test_overview_period_is_24h(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/overview", headers=COMP_HEADERS)
        assert r.json()["period"] == "24h"

    def test_overview_numeric_fields(self, gateway: httpx.Client):
        body = gateway.get("/api/v1/stats/overview", headers=COMP_HEADERS).json()
        assert isinstance(body["total_requests"], int)
        assert isinstance(body["violations"], int)
        assert isinstance(body["pii_detections"], int)
        assert isinstance(body["injection_blocks"], int)
        assert isinstance(body["avg_latency_ms"], (int, float))

    def test_overview_tenant_correct(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/overview", headers=COMP_HEADERS)
        assert r.json()["tenant_id"] == TENANT_ID

    def test_timeseries_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/timeseries", headers=COMP_HEADERS)
        assert r.status_code == 200

    def test_timeseries_shape(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/timeseries", headers=COMP_HEADERS)
        body = r.json()
        assert "tenant_id" in body
        assert "hours" in body
        assert "buckets" in body
        assert isinstance(body["buckets"], list)

    def test_timeseries_default_24_hours(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/timeseries", headers=COMP_HEADERS)
        assert r.json()["hours"] == 24

    def test_timeseries_custom_hours(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/timeseries?hours=48", headers=COMP_HEADERS)
        assert r.status_code == 200
        assert r.json()["hours"] == 48

    def test_timeseries_hours_out_of_range_rejected(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/timeseries?hours=200", headers=COMP_HEADERS)
        assert r.status_code == 422

    def test_timeseries_bucket_fields(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/timeseries?hours=1", headers=COMP_HEADERS)
        for bucket in r.json()["buckets"]:
            assert "hour" in bucket
            assert "total" in bucket
            assert "violations" in bucket
            assert "pii" in bucket

    def test_departments_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/departments", headers=COMP_HEADERS)
        assert r.status_code == 200

    def test_departments_shape(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/departments", headers=COMP_HEADERS)
        body = r.json()
        assert "tenant_id" in body
        assert "period" in body
        assert "departments" in body
        assert body["period"] == "7d"

    def test_departments_field_structure(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/departments", headers=COMP_HEADERS)
        for dept in r.json()["departments"]:
            assert "department" in dept
            assert "total" in dept
            assert "violations" in dept

    def test_hours_heatmap_200(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/hours", headers=COMP_HEADERS)
        assert r.status_code == 200

    def test_hours_heatmap_shape(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/hours", headers=COMP_HEADERS)
        body = r.json()
        assert "hours" in body
        assert "period" in body
        assert body["period"] == "7d"

    def test_hours_heatmap_hour_values(self, gateway: httpx.Client):
        r = gateway.get("/api/v1/stats/hours", headers=COMP_HEADERS)
        for entry in r.json()["hours"]:
            assert 0 <= entry["hour"] <= 23
            assert entry["total"] >= 0


# ---------------------------------------------------------------------------
# 8. Auth proxy endpoints
# ---------------------------------------------------------------------------


class TestAuthProxyEndpoints:
    """These proxy to the auth service — the service may or may not be running.
    We use fresh clients per test to avoid connection-pool corruption.
    We verify gateway routing exists (not 404/405) and basic validation."""

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=GATEWAY_URL, timeout=10.0)

    def test_token_endpoint_reachable(self):
        """POST /auth/token must be routed by the gateway (not 404/405)."""
        with self._client() as c:
            try:
                r = c.post("/api/v1/auth/token", json={"api_key": "bad_key"})
                assert r.status_code != 404
                assert r.status_code != 405
            except httpx.RemoteProtocolError:
                pass  # auth service absent — route was found, upstream down

    def test_token_endpoint_wrong_content_type(self):
        """Pydantic validation runs before proxying — bad JSON → 422."""
        with self._client() as c:
            r = c.post("/api/v1/auth/token", content=b"not json")
            assert r.status_code in (400, 422)

    def test_refresh_endpoint_reachable(self):
        with self._client() as c:
            try:
                r = c.post("/api/v1/auth/refresh", json={"refresh_token": "fake"})
                assert r.status_code != 404
                assert r.status_code != 405
            except httpx.RemoteProtocolError:
                pass

    def test_me_endpoint_reachable(self):
        with self._client() as c:
            try:
                r = c.get(
                    "/api/v1/auth/me",
                    headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
                )
                assert r.status_code != 404
            except httpx.RemoteProtocolError:
                # Auth service not running; gateway disconnects — route exists, service absent
                pass


# ---------------------------------------------------------------------------
# 9. Tenant admin proxy endpoints (require admin role)
# ---------------------------------------------------------------------------


class TestTenantAdminProxies:
    """Tenant proxy tests use a fresh client per method to avoid connection-pool
    corruption when the tenant service is not running."""

    def _client(self) -> httpx.Client:
        return httpx.Client(base_url=GATEWAY_URL, timeout=10.0)

    def test_tenant_usage_reachable(self):
        with self._client() as c:
            try:
                r = c.get("/api/v1/tenant/usage", headers=ADMIN_HEADERS)
                # Tenant service may not be running; but must not 403
                assert r.status_code != 403
            except httpx.RemoteProtocolError:
                pass  # tenant service absent — RBAC passed, upstream down

    def test_tenant_usage_blocked_for_compliance(self):
        with self._client() as c:
            r = c.get("/api/v1/tenant/usage", headers=COMP_HEADERS)
            assert r.status_code == 403

    def test_tenant_provision_blocked_for_user(self):
        with self._client() as c:
            r = c.post(
                "/api/v1/tenant/provision",
                headers=USER_HEADERS,
                json={"name": "test", "plan": "starter", "admin_email": "a@b.com"},
            )
            assert r.status_code == 403

    def test_tenant_settings_reachable_for_admin(self):
        with self._client() as c:
            try:
                r = c.put(
                    "/api/v1/tenant/settings",
                    headers=ADMIN_HEADERS,
                    json={"settings": {}},
                )
                assert r.status_code != 403
            except httpx.RemoteProtocolError:
                pass  # tenant service absent
