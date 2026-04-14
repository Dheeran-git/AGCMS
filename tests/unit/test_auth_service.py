"""Unit tests for the AGCMS Auth Service.

Covers:
  - JWT token creation and verification (tokens.py)
  - Access token: correct claims, expiry, type field
  - Refresh token: correct claims, expiry, type field
  - Token rejection: wrong type, expired, tampered signature
  - POST /v1/auth/token: valid key, invalid key, inactive tenant
  - POST /v1/auth/refresh: valid refresh, invalid refresh, wrong type
  - GET /v1/auth/me: valid access token, missing header, invalid token
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from jose import jwt

# Set JWT secret before importing app modules
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from agcms.auth.tokens import (  # noqa: E402
    create_access_token,
    create_refresh_token,
    verify_access_token,
    verify_refresh_token,
)

# Import app after env is set
from agcms.auth.main import app  # noqa: E402

_SECRET = "test-secret-for-unit-tests"
_ALGORITHM = "HS256"

_TENANT = {
    "id": "default",
    "name": "Default Organization",
    "plan": "business",
    "admin_email": "admin@agcms.local",
    "is_active": True,
}

_USER = {
    "id": "some-uuid",
    "external_id": "admin",
    "email": "admin@agcms.local",
    "role": "admin",
}


# ==================================================================
# 1. Token Creation
# ==================================================================


class TestTokenCreation:
    def test_access_token_is_string(self):
        token = create_access_token("tenant1", "admin", "user1")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_access_token_claims(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_access_token("tenant1", "admin", "user1")
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        assert payload["sub"] == "tenant1"
        assert payload["role"] == "admin"
        assert payload["user_id"] == "user1"
        assert payload["type"] == "access"

    def test_access_token_expires_in_15_minutes(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_access_token("tenant1", "admin", "user1")
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        assert 14 * 60 < (exp - iat).total_seconds() <= 15 * 60

    def test_refresh_token_claims(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_refresh_token("tenant1")
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        assert payload["sub"] == "tenant1"
        assert payload["type"] == "refresh"
        assert "jti" in payload  # single-use enforcement requires jti

    def test_refresh_tokens_have_unique_jtis(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            t1 = create_refresh_token("tenant1")
            t2 = create_refresh_token("tenant1")
        p1 = jwt.decode(t1, _SECRET, algorithms=[_ALGORITHM])
        p2 = jwt.decode(t2, _SECRET, algorithms=[_ALGORITHM])
        assert p1["jti"] != p2["jti"]

    def test_refresh_token_expires_in_7_days(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_refresh_token("tenant1")
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        iat = datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
        assert 6 * 86400 < (exp - iat).total_seconds() <= 7 * 86400


# ==================================================================
# 2. Token Verification
# ==================================================================


class TestTokenVerification:
    def test_valid_access_token_returns_payload(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_access_token("t1", "admin", "u1")
            payload = verify_access_token(token)
        assert payload is not None
        assert payload["sub"] == "t1"

    def test_valid_refresh_token_returns_payload(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_refresh_token("t1")
            payload = verify_refresh_token(token)
        assert payload is not None
        assert payload["sub"] == "t1"

    def test_access_token_rejected_as_refresh(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_access_token("t1", "admin", "u1")
            result = verify_refresh_token(token)
        assert result is None

    def test_refresh_token_rejected_as_access(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_refresh_token("t1")
            result = verify_access_token(token)
        assert result is None

    def test_tampered_token_rejected(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_access_token("t1", "admin", "u1")
        # Flip last character
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        assert verify_access_token(tampered) is None

    def test_expired_token_rejected(self):
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "t1",
            "user_id": "u1",
            "role": "admin",
            "type": "access",
            "iat": now - timedelta(minutes=30),
            "exp": now - timedelta(minutes=15),
        }
        expired_token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            assert verify_access_token(expired_token) is None

    def test_wrong_secret_rejected(self):
        token = jwt.encode(
            {"sub": "t1", "type": "access", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            "wrong-secret",
            algorithm=_ALGORITHM,
        )
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            assert verify_access_token(token) is None

    def test_garbage_token_rejected(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            assert verify_access_token("not.a.token") is None


# ==================================================================
# 3. POST /v1/auth/token
# ==================================================================


class TestIssueToken:
    @pytest.fixture
    def client(self):
        return TestClient(app, raise_server_exceptions=True)

    def test_valid_api_key_returns_tokens(self, client):
        with patch("agcms.auth.main.get_tenant_by_api_key", new_callable=AsyncMock) as mock_t, \
             patch("agcms.auth.main.get_admin_user", new_callable=AsyncMock) as mock_u:
            mock_t.return_value = _TENANT
            mock_u.return_value = _USER
            resp = client.post("/v1/auth/token", json={"api_key": "agcms_test_key_for_development"})

        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 900

    def test_invalid_api_key_returns_401(self, client):
        with patch("agcms.auth.main.get_tenant_by_api_key", new_callable=AsyncMock) as mock_t:
            mock_t.return_value = None
            resp = client.post("/v1/auth/token", json={"api_key": "wrong_key"})

        assert resp.status_code == 401

    def test_inactive_tenant_returns_401(self, client):
        inactive = {**_TENANT, "is_active": False}
        with patch("agcms.auth.main.get_tenant_by_api_key", new_callable=AsyncMock) as mock_t:
            mock_t.return_value = None  # db.py returns None for inactive
            resp = client.post("/v1/auth/token", json={"api_key": "any_key"})

        assert resp.status_code == 401

    def test_access_token_has_correct_role(self, client):
        with patch("agcms.auth.main.get_tenant_by_api_key", new_callable=AsyncMock) as mock_t, \
             patch("agcms.auth.main.get_admin_user", new_callable=AsyncMock) as mock_u:
            mock_t.return_value = _TENANT
            mock_u.return_value = _USER
            resp = client.post("/v1/auth/token", json={"api_key": "test_key"})

        token = resp.json()["access_token"]
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        assert payload["role"] == "admin"
        assert payload["sub"] == "default"


# ==================================================================
# 4. POST /v1/auth/refresh
# ==================================================================


class TestRefreshToken:
    @pytest.fixture
    def client(self):
        return TestClient(app, raise_server_exceptions=True)

    @pytest.fixture
    def valid_refresh(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            return create_refresh_token("default")

    def test_valid_refresh_returns_new_access_token(self, client, valid_refresh):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}), \
             patch("agcms.auth.main.get_admin_user", new_callable=AsyncMock) as mock_u, \
             patch("agcms.auth.main.is_jti_blacklisted", new_callable=AsyncMock) as mock_bl, \
             patch("agcms.auth.main.blacklist_jti", new_callable=AsyncMock):
            mock_u.return_value = _USER
            mock_bl.return_value = False
            resp = client.post("/v1/auth/refresh", json={"refresh_token": valid_refresh})

        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_invalid_refresh_token_returns_401(self, client):
        resp = client.post("/v1/auth/refresh", json={"refresh_token": "bad.token.here"})
        assert resp.status_code == 401

    def test_access_token_as_refresh_returns_401(self, client):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            access = create_access_token("default", "admin", "admin")
        resp = client.post("/v1/auth/refresh", json={"refresh_token": access})
        assert resp.status_code == 401

    def test_replayed_refresh_token_returns_401(self, client, valid_refresh):
        """A blacklisted jti must be rejected — replay attack prevention."""
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}), \
             patch("agcms.auth.main.is_jti_blacklisted", new_callable=AsyncMock) as mock_bl:
            mock_bl.return_value = True  # simulate already-used token
            resp = client.post("/v1/auth/refresh", json={"refresh_token": valid_refresh})

        assert resp.status_code == 401
        assert "already used" in resp.json()["detail"]

    def test_blacklist_called_after_successful_refresh(self, client, valid_refresh):
        """jti must be blacklisted after a successful token exchange."""
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}), \
             patch("agcms.auth.main.get_admin_user", new_callable=AsyncMock) as mock_u, \
             patch("agcms.auth.main.is_jti_blacklisted", new_callable=AsyncMock) as mock_bl, \
             patch("agcms.auth.main.blacklist_jti", new_callable=AsyncMock) as mock_blist:
            mock_u.return_value = _USER
            mock_bl.return_value = False
            resp = client.post("/v1/auth/refresh", json={"refresh_token": valid_refresh})

        assert resp.status_code == 200
        mock_blist.assert_called_once()


# ==================================================================
# 5. GET /v1/auth/me
# ==================================================================


class TestMe:
    @pytest.fixture
    def client(self):
        return TestClient(app, raise_server_exceptions=True)

    @pytest.fixture
    def valid_access(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            return create_access_token("default", "admin", "admin")

    def test_valid_token_returns_identity(self, client, valid_access):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            resp = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {valid_access}"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == "default"
        assert data["user_id"] == "admin"
        assert data["role"] == "admin"

    def test_missing_authorization_returns_401(self, client):
        resp = client.get("/v1/auth/me")
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client):
        resp = client.get("/v1/auth/me", headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == 401

    def test_refresh_token_as_access_returns_401(self, client):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            refresh = create_refresh_token("default")
        resp = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {refresh}"})
        assert resp.status_code == 401

    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["service"] == "auth"
