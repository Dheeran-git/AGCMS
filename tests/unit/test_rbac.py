"""Unit tests for the gateway RBAC dependencies.

Covers:
  - get_current_auth: missing header, invalid JWT, valid auth
  - require_role: admin bypass, exact role match, role mismatch, multi-role
  - Dev key fast path produces admin role (passes all gates)
"""

import os
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from agcms.gateway.auth import AuthContext  # noqa: E402
from agcms.gateway.rbac import (  # noqa: E402
    get_current_auth,
    require_admin,
    require_compliance,
    require_role,
)


_DEV_KEY = "agcms_test_key_for_development"


# ==================================================================
# Test harness: mini FastAPI app mounting the deps
# ==================================================================


def _make_test_app() -> FastAPI:
    app = FastAPI()

    @app.get("/auth-only")
    async def auth_only(ctx: AuthContext = Depends(get_current_auth)):
        return {"tenant_id": ctx.tenant_id, "role": ctx.role}

    @app.get("/admin-only")
    async def admin_only(ctx: AuthContext = Depends(require_admin)):
        return {"tenant_id": ctx.tenant_id, "role": ctx.role}

    @app.get("/compliance-only")
    async def compliance_only(ctx: AuthContext = Depends(require_compliance)):
        return {"tenant_id": ctx.tenant_id, "role": ctx.role}

    @app.get("/custom-roles")
    async def custom_roles(ctx: AuthContext = Depends(require_role("compliance", "user"))):
        return {"tenant_id": ctx.tenant_id, "role": ctx.role}

    return app


# ==================================================================
# 1. get_current_auth
# ==================================================================


class TestGetCurrentAuth:
    def test_missing_header_returns_401(self):
        client = TestClient(_make_test_app())
        resp = client.get("/auth-only")
        assert resp.status_code == 401

    def test_invalid_jwt_returns_401(self):
        client = TestClient(_make_test_app())
        resp = client.get("/auth-only", headers={"Authorization": "Bearer bad.jwt.token"})
        assert resp.status_code == 401

    def test_dev_key_returns_admin_auth(self):
        client = TestClient(_make_test_app())
        resp = client.get("/auth-only", headers={"Authorization": f"Bearer {_DEV_KEY}"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["tenant_id"] == "default"
        assert body["role"] == "admin"


# ==================================================================
# 2. require_admin — admin gate
# ==================================================================


class TestRequireAdmin:
    def test_dev_key_admin_passes(self):
        client = TestClient(_make_test_app())
        resp = client.get("/admin-only", headers={"Authorization": f"Bearer {_DEV_KEY}"})
        assert resp.status_code == 200

    def test_missing_header_returns_401(self):
        client = TestClient(_make_test_app())
        resp = client.get("/admin-only")
        assert resp.status_code == 401

    def test_non_admin_role_returns_403(self):
        """Override get_current_auth to inject a non-admin role."""
        app = _make_test_app()

        def fake_user_ctx() -> AuthContext:
            return AuthContext(
                tenant_id="t1", user_id="u1", role="user", auth_method="jwt",
            )

        app.dependency_overrides[get_current_auth] = fake_user_ctx
        client = TestClient(app)
        resp = client.get("/admin-only", headers={"Authorization": "Bearer anything"})
        assert resp.status_code == 403
        assert "user" in resp.json()["detail"]


# ==================================================================
# 3. require_compliance — compliance or admin gate
# ==================================================================


class TestRequireCompliance:
    def test_admin_passes_compliance_gate(self):
        """Admin implicitly passes every require_role() gate."""
        client = TestClient(_make_test_app())
        resp = client.get(
            "/compliance-only", headers={"Authorization": f"Bearer {_DEV_KEY}"}
        )
        assert resp.status_code == 200

    def test_compliance_role_passes(self):
        app = _make_test_app()
        app.dependency_overrides[get_current_auth] = lambda: AuthContext(
            tenant_id="t1", user_id="u1", role="compliance", auth_method="jwt",
        )
        client = TestClient(app)
        resp = client.get("/compliance-only", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 200

    def test_user_role_fails_compliance_gate(self):
        app = _make_test_app()
        app.dependency_overrides[get_current_auth] = lambda: AuthContext(
            tenant_id="t1", user_id="u1", role="user", auth_method="jwt",
        )
        client = TestClient(app)
        resp = client.get("/compliance-only", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 403


# ==================================================================
# 4. require_role with multiple allowed roles
# ==================================================================


class TestCustomRoles:
    def test_user_role_in_allowed_list_passes(self):
        app = _make_test_app()
        app.dependency_overrides[get_current_auth] = lambda: AuthContext(
            tenant_id="t1", user_id="u1", role="user", auth_method="jwt",
        )
        client = TestClient(app)
        resp = client.get("/custom-roles", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 200

    def test_compliance_role_in_allowed_list_passes(self):
        app = _make_test_app()
        app.dependency_overrides[get_current_auth] = lambda: AuthContext(
            tenant_id="t1", user_id="u1", role="compliance", auth_method="jwt",
        )
        client = TestClient(app)
        resp = client.get("/custom-roles", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 200

    def test_admin_bypasses_custom_gate(self):
        """Even if admin isn't explicitly in the allowed list, it passes."""
        app = _make_test_app()
        app.dependency_overrides[get_current_auth] = lambda: AuthContext(
            tenant_id="t1", user_id="u1", role="admin", auth_method="jwt",
        )
        client = TestClient(app)
        resp = client.get("/custom-roles", headers={"Authorization": "Bearer x"})
        assert resp.status_code == 200
