"""Unit tests for Phase 6.5 — session revocation.

Covers:
  - access tokens now carry jti + tuid + iat claims
  - session recording on issuance (best-effort, swallows DB errors)
  - list/revoke endpoints and their auth checks
  - revoke-all writes both per-jti blacklist and the user revoked_before pivot
  - gateway auth.authenticate rejects a revoked jti
  - gateway auth.authenticate rejects a token whose iat precedes revoked_before
"""
from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from jose import jwt

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from agcms.auth import sessions as session_store  # noqa: E402
from agcms.auth.main import app  # noqa: E402
from agcms.auth.tokens import create_access_token, issue_access_token  # noqa: E402

_SECRET = "test-secret-for-unit-tests"
_ALGORITHM = "HS256"

_TENANT = {
    "id": "default",
    "name": "Default Organization",
    "plan": "business",
    "admin_email": "admin@agcms.local",
    "is_active": True,
}

_TENANT_USER_ID = str(uuid.uuid4())

_USER = {
    "id": _TENANT_USER_ID,
    "tenant_id": "default",
    "external_id": "admin",
    "email": "admin@agcms.local",
    "role": "admin",
    "is_active": True,
}


# ==================================================================
# 1. Access tokens carry the new revocation claims
# ==================================================================


class TestAccessTokenClaims:
    def test_access_token_has_jti(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_access_token("t1", "admin", "u1")
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        assert "jti" in payload
        # Must be a UUID
        uuid.UUID(payload["jti"])

    def test_two_access_tokens_have_different_jtis(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            t1 = create_access_token("t1", "admin", "u1")
            t2 = create_access_token("t1", "admin", "u1")
        p1 = jwt.decode(t1, _SECRET, algorithms=[_ALGORITHM])
        p2 = jwt.decode(t2, _SECRET, algorithms=[_ALGORITHM])
        assert p1["jti"] != p2["jti"]

    def test_access_token_carries_tuid_when_supplied(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = create_access_token(
                "t1", "admin", "u1", tenant_user_id=_TENANT_USER_ID
            )
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        assert payload["tuid"] == _TENANT_USER_ID

    def test_issue_access_token_metadata_matches_claims(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            issued = issue_access_token(
                tenant_id="t1", role="admin", user_id="u1"
            )
        payload = jwt.decode(issued.token, _SECRET, algorithms=[_ALGORITHM])
        assert payload["jti"] == issued.jti
        # iat/exp in claims match issued metadata (drop to 1s precision)
        assert abs(payload["iat"] - int(issued.issued_at.timestamp())) <= 1
        assert abs(payload["exp"] - int(issued.expires_at.timestamp())) <= 1


# ==================================================================
# 2. Session recording on token issuance
# ==================================================================


class TestSessionRecordingOnIssue:
    @pytest.fixture
    def client(self):
        return TestClient(app, raise_server_exceptions=True)

    def test_issue_token_records_session_row(self, client):
        with patch("agcms.auth.main.get_tenant_by_api_key", new_callable=AsyncMock) as m_t, \
             patch("agcms.auth.main.get_admin_user", new_callable=AsyncMock) as m_u, \
             patch("agcms.auth.main.mfa_db.fetch_mfa", new_callable=AsyncMock) as m_mfa, \
             patch("agcms.auth.main.session_store.record_session", new_callable=AsyncMock) as m_rec:
            m_t.return_value = _TENANT
            m_u.return_value = _USER
            m_mfa.return_value = None
            resp = client.post("/v1/auth/token", json={"api_key": "anything"})

        assert resp.status_code == 200
        m_rec.assert_awaited_once()
        kwargs = m_rec.await_args.kwargs
        assert kwargs["tenant_id"] == "default"
        assert kwargs["tenant_user_id"] == _TENANT_USER_ID
        assert kwargs["issued_via"] == "api_key"
        # jti from the issued access token
        issued_access = resp.json()["access_token"]
        claims = jwt.decode(issued_access, _SECRET, algorithms=[_ALGORITHM])
        assert kwargs["jti"] == claims["jti"]

    def test_record_session_db_error_does_not_fail_login(self, client):
        """Best-effort: DB outage on session write still returns usable tokens."""
        with patch("agcms.auth.main.get_tenant_by_api_key", new_callable=AsyncMock) as m_t, \
             patch("agcms.auth.main.get_admin_user", new_callable=AsyncMock) as m_u, \
             patch("agcms.auth.main.mfa_db.fetch_mfa", new_callable=AsyncMock) as m_mfa, \
             patch("agcms.auth.main.session_store.record_session", new_callable=AsyncMock) as m_rec:
            m_t.return_value = _TENANT
            m_u.return_value = _USER
            m_mfa.return_value = None
            m_rec.side_effect = RuntimeError("db down")
            resp = client.post("/v1/auth/token", json={"api_key": "anything"})

        # Login still succeeds — session row is best-effort
        assert resp.status_code == 200
        assert "access_token" in resp.json()


# ==================================================================
# 3. /v1/auth/sessions endpoints
# ==================================================================


def _valid_access_token_with_tuid() -> str:
    """Build an access token carrying the test tenant_user_id as tuid."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "default",
        "user_id": "admin",
        "tuid": _TENANT_USER_ID,
        "role": "admin",
        "type": "access",
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=15),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


class TestSessionEndpoints:
    @pytest.fixture
    def client(self):
        return TestClient(app, raise_server_exceptions=True)

    def _patch_me(self):
        """Replace the /me-style user lookup with our fake admin."""
        return patch(
            "agcms.auth.main.mfa_db.fetch_user_by_external_id",
            new_callable=AsyncMock,
            return_value=_USER,
        )

    def test_list_my_sessions_returns_empty_when_none(self, client):
        token = _valid_access_token_with_tuid()
        with self._patch_me(), \
             patch("agcms.auth.main.session_store.list_sessions_for_user",
                   new_callable=AsyncMock, return_value=[]):
            resp = client.get(
                "/v1/auth/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"sessions": []}

    def test_list_my_sessions_marks_current(self, client):
        token = _valid_access_token_with_tuid()
        claims = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        now = datetime.now(timezone.utc)
        rows = [
            {
                "jti": claims["jti"],
                "issued_at": now,
                "expires_at": now + timedelta(minutes=15),
                "last_seen_at": None,
                "revoked_at": None,
                "revoke_reason": None,
                "user_agent": "UA",
                "ip_address": "1.2.3.4",
                "issued_via": "api_key",
            },
            {
                "jti": "other-jti",
                "issued_at": now - timedelta(hours=1),
                "expires_at": now,
                "last_seen_at": None,
                "revoked_at": None,
                "revoke_reason": None,
                "user_agent": None,
                "ip_address": None,
                "issued_via": "refresh",
            },
        ]
        with self._patch_me(), \
             patch("agcms.auth.main.session_store.list_sessions_for_user",
                   new_callable=AsyncMock, return_value=rows):
            resp = client.get(
                "/v1/auth/sessions",
                headers={"Authorization": f"Bearer {token}"},
            )

        sessions = resp.json()["sessions"]
        assert sessions[0]["current"] is True
        assert sessions[1]["current"] is False

    def test_revoke_own_session_blacklists_and_returns_ok(self, client):
        token = _valid_access_token_with_tuid()
        now = datetime.now(timezone.utc)
        target = "11111111-1111-1111-1111-111111111111"
        with self._patch_me(), \
             patch("agcms.auth.main.session_store.fetch_session",
                   new_callable=AsyncMock,
                   return_value={"jti": target, "tenant_user_id": _TENANT_USER_ID,
                                 "tenant_id": "default", "issued_at": now,
                                 "expires_at": now + timedelta(minutes=10),
                                 "revoked_at": None}), \
             patch("agcms.auth.main.session_store.revoke_session",
                   new_callable=AsyncMock,
                   return_value={"jti": target, "tenant_user_id": _TENANT_USER_ID,
                                 "tenant_id": "default", "issued_at": now,
                                 "expires_at": now + timedelta(minutes=10)}), \
             patch("agcms.auth.main.blacklist_access_jti",
                   new_callable=AsyncMock) as m_bl:
            resp = client.delete(
                f"/v1/auth/sessions/{target}",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"revoked": True, "jti": target}
        m_bl.assert_awaited_once()

    def test_revoke_session_belonging_to_other_user_returns_404(self, client):
        token = _valid_access_token_with_tuid()
        other_user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        target = "22222222-2222-2222-2222-222222222222"
        with self._patch_me(), \
             patch("agcms.auth.main.session_store.fetch_session",
                   new_callable=AsyncMock,
                   return_value={"jti": target, "tenant_user_id": other_user_id,
                                 "tenant_id": "default", "issued_at": now,
                                 "expires_at": now + timedelta(minutes=10),
                                 "revoked_at": None}):
            resp = client.delete(
                f"/v1/auth/sessions/{target}",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 404

    def test_revoke_all_blacklists_each_and_publishes_pivot(self, client):
        token = _valid_access_token_with_tuid()
        now = datetime.now(timezone.utc)
        revoked = [
            {"jti": "j1", "expires_at": now + timedelta(minutes=10)},
            {"jti": "j2", "expires_at": now + timedelta(minutes=10)},
        ]
        with self._patch_me(), \
             patch("agcms.auth.main.session_store.revoke_all_sessions_for_user",
                   new_callable=AsyncMock, return_value=revoked), \
             patch("agcms.auth.main.blacklist_access_jti",
                   new_callable=AsyncMock) as m_bl, \
             patch("agcms.auth.main.set_user_revoked_before",
                   new_callable=AsyncMock) as m_pivot:
            resp = client.post(
                "/v1/auth/sessions/revoke-all",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"revoked_count": 2}
        assert m_bl.await_count == 2
        m_pivot.assert_awaited_once()
        args, _ = m_pivot.await_args
        assert args[0] == _TENANT_USER_ID  # keyed by tenant_user_id

    def test_admin_sessions_requires_admin_role(self, client):
        """A compliance-role token must NOT see the tenant-wide view."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "default", "user_id": "compliance-user",
            "tuid": _TENANT_USER_ID, "role": "compliance", "type": "access",
            "jti": str(uuid.uuid4()), "iat": now,
            "exp": now + timedelta(minutes=15),
        }
        compliance_token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)
        non_admin = {**_USER, "role": "compliance"}
        with patch("agcms.auth.main.mfa_db.fetch_user_by_external_id",
                   new_callable=AsyncMock, return_value=non_admin):
            resp = client.get(
                "/v1/auth/admin/sessions",
                headers={"Authorization": f"Bearer {compliance_token}"},
            )
        assert resp.status_code == 403


# ==================================================================
# 4. Gateway auth rejects revoked tokens
# ==================================================================


from agcms.gateway import auth as gw_auth  # noqa: E402


class _FakeRedis:
    """In-memory Redis stand-in for the gateway's revocation check."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def exists(self, key: str) -> int:
        return 1 if key in self.store else 0

    async def get(self, key: str) -> str | None:
        return self.store.get(key)


@pytest.fixture(autouse=True)
def _reset_gateway_redis():
    """Ensure each test starts with a clean, Redis-less gateway."""
    gw_auth._redis_client = None
    yield
    gw_auth._redis_client = None


@pytest.mark.anyio
class TestGatewayRevocation:
    async def test_jwt_with_revoked_jti_is_rejected(self):
        tuid = _TENANT_USER_ID
        jti = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "default", "user_id": "admin", "tuid": tuid, "role": "admin",
            "type": "access", "jti": jti, "iat": now,
            "exp": now + timedelta(minutes=15),
        }
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)

        fake = _FakeRedis()
        fake.store[f"agcms:at:blacklist:{jti}"] = "1"

        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}), \
             patch.object(gw_auth, "_get_redis", return_value=fake):
            ctx, err = await gw_auth.authenticate(f"Bearer {token}")

        assert ctx is None
        assert err is not None
        assert "revoked" in err.lower()

    async def test_jwt_older_than_pivot_is_rejected(self):
        tuid = _TENANT_USER_ID
        now = datetime.now(timezone.utc)
        # Token issued 5 seconds ago.
        payload = {
            "sub": "default", "user_id": "admin", "tuid": tuid, "role": "admin",
            "type": "access", "jti": str(uuid.uuid4()),
            "iat": now - timedelta(seconds=5),
            "exp": now + timedelta(minutes=15),
        }
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)

        fake = _FakeRedis()
        # Pivot is "now" — token's iat is older → rejected
        fake.store[f"agcms:at:revoked_before:{tuid}"] = str(int(now.timestamp()))

        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}), \
             patch.object(gw_auth, "_get_redis", return_value=fake):
            ctx, err = await gw_auth.authenticate(f"Bearer {token}")

        assert ctx is None
        assert err is not None

    async def test_jwt_newer_than_pivot_is_accepted(self):
        tuid = _TENANT_USER_ID
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "default", "user_id": "admin", "tuid": tuid, "role": "admin",
            "type": "access", "jti": str(uuid.uuid4()), "iat": now,
            "exp": now + timedelta(minutes=15),
        }
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)

        fake = _FakeRedis()
        # Pivot is older than iat → accept
        fake.store[f"agcms:at:revoked_before:{tuid}"] = str(
            int((now - timedelta(minutes=5)).timestamp())
        )

        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}), \
             patch.object(gw_auth, "_get_redis", return_value=fake):
            ctx, err = await gw_auth.authenticate(f"Bearer {token}")

        assert err is None
        assert ctx is not None
        assert ctx.tenant_id == "default"

    async def test_redis_unavailable_fails_open(self):
        """Redis outage must not kill the hot path."""
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "default", "user_id": "admin", "tuid": _TENANT_USER_ID,
            "role": "admin", "type": "access", "jti": str(uuid.uuid4()),
            "iat": now, "exp": now + timedelta(minutes=15),
        }
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)

        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}), \
             patch.object(gw_auth, "_get_redis", return_value=None):
            ctx, err = await gw_auth.authenticate(f"Bearer {token}")

        assert err is None
        assert ctx is not None


# ==================================================================
# 5. Sessions module DB helpers — conn is a mock, we check SQL shape
# ==================================================================


class _FakeConn:
    def __init__(self):
        self.executes: list[tuple] = []
        self.fetchrows: list[tuple] = []
        self.fetchrow_results: list = []
        self.fetch_results: list = []
        self.closed = False

    async def execute(self, sql, *args):
        self.executes.append((sql, args))
        return "UPDATE 1"

    async def fetchrow(self, sql, *args):
        self.fetchrows.append((sql, args))
        return self.fetchrow_results.pop(0) if self.fetchrow_results else None

    async def fetch(self, sql, *args):
        return self.fetch_results.pop(0) if self.fetch_results else []

    @asynccontextmanager
    async def transaction(self):
        yield self

    async def close(self):
        self.closed = True


def _patch_connect(fake: _FakeConn):
    async def factory(*_a, **_kw):
        return fake
    return patch("agcms.auth.sessions.asyncpg.connect", side_effect=factory)


class TestSessionsHelpers:
    @pytest.mark.anyio
    async def test_record_session_inserts_row(self):
        fake = _FakeConn()
        now = datetime.now(timezone.utc)
        with _patch_connect(fake):
            await session_store.record_session(
                jti="j1",
                tenant_user_id="user-1",
                tenant_id="default",
                issued_at=now,
                expires_at=now + timedelta(minutes=15),
                issued_via="api_key",
                user_agent="UA",
                ip_address="1.2.3.4",
            )
        assert len(fake.executes) == 1
        sql, args = fake.executes[0]
        assert "INSERT INTO auth_sessions" in sql
        assert args[0] == "j1"
        assert args[5] == "api_key"

    @pytest.mark.anyio
    async def test_revoke_all_bumps_pivot(self):
        """revoke_all_sessions_for_user must UPDATE tenant_users.revoked_before."""
        fake = _FakeConn()
        fake.fetch_results.append([
            {"jti": "j1", "expires_at": datetime.now(timezone.utc)},
        ])
        with _patch_connect(fake):
            out = await session_store.revoke_all_sessions_for_user(
                tenant_user_id="user-1",
                revoked_by="user-1",
                reason="user_revoked_all",
            )
        assert len(out) == 1
        # There must be an UPDATE that sets revoked_before on tenant_users
        saw_pivot = any(
            "UPDATE tenant_users" in sql and "revoked_before" in sql
            for sql, _ in fake.executes
        )
        assert saw_pivot

    @pytest.mark.anyio
    async def test_revoke_session_returns_none_when_missing(self):
        fake = _FakeConn()
        fake.fetchrow_results.append(None)
        with _patch_connect(fake):
            out = await session_store.revoke_session(
                jti="missing", revoked_by="u1", reason="x"
            )
        assert out is None
