"""Unit tests for the AGCMS Gateway dual-mode authentication.

Covers:
  - AuthContext dataclass
  - Dev API key fast path (backward compat)
  - "Bearer " prefix stripping
  - Missing / empty Authorization header
  - JWT path: valid access token, refresh token rejected, expired, tampered,
    wrong secret, garbage token, missing claims
  - API-key path (DB-backed): valid key, unknown key, inactive tenant,
    DB connection failure
  - Selection logic: 2-dot token → JWT path; otherwise → API-key path
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from jose import jwt

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from agcms.gateway.auth import (  # noqa: E402
    AuthContext,
    authenticate,
)

_SECRET = "test-secret-for-unit-tests"
_ALGORITHM = "HS256"
_DEV_KEY = "agcms_test_key_for_development"


def _make_jwt(
    token_type: str = "access",
    tenant_id: str = "tenant1",
    user_id: str = "user1",
    role: str = "admin",
    exp_delta: timedelta = timedelta(minutes=15),
    secret: str = _SECRET,
    extra: dict | None = None,
) -> str:
    """Build a signed JWT with the given claims."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": tenant_id,
        "user_id": user_id,
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + exp_delta,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, secret, algorithm=_ALGORITHM)


# ==================================================================
# 1. AuthContext dataclass
# ==================================================================


class TestAuthContext:
    def test_instantiation(self):
        ctx = AuthContext(
            tenant_id="t1", user_id="u1", role="admin", auth_method="jwt",
        )
        assert ctx.tenant_id == "t1"
        assert ctx.user_id == "u1"
        assert ctx.role == "admin"
        assert ctx.auth_method == "jwt"

    def test_is_frozen(self):
        ctx = AuthContext(tenant_id="t1", user_id="u1", role="admin", auth_method="jwt")
        with pytest.raises(Exception):
            ctx.tenant_id = "other"  # type: ignore[misc]


# ==================================================================
# 2. Missing / empty Authorization
# ==================================================================


class TestMissingAuth:
    async def test_none_header_returns_error(self):
        ctx, err = await authenticate(None)
        assert ctx is None
        assert err is not None

    async def test_empty_header_returns_error(self):
        ctx, err = await authenticate("")
        assert ctx is None
        assert err is not None

    async def test_bearer_with_no_token_returns_error(self):
        ctx, err = await authenticate("Bearer ")
        assert ctx is None
        assert err is not None


# ==================================================================
# 3. Dev key fast path (backward compat)
# ==================================================================


class TestDevKeyFastPath:
    async def test_dev_key_raw_works(self):
        ctx, err = await authenticate(_DEV_KEY)
        assert err is None
        assert ctx is not None
        assert ctx.tenant_id == "default"
        assert ctx.auth_method == "dev_key"
        assert ctx.role == "admin"

    async def test_dev_key_with_bearer_prefix_works(self):
        ctx, err = await authenticate(f"Bearer {_DEV_KEY}")
        assert err is None
        assert ctx is not None
        assert ctx.auth_method == "dev_key"
        assert ctx.tenant_id == "default"


# ==================================================================
# 4. JWT path
# ==================================================================


class TestJWTAuth:
    async def test_valid_access_token(self):
        token = _make_jwt(
            token_type="access",
            tenant_id="acme",
            user_id="alice",
            role="admin",
        )
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            ctx, err = await authenticate(f"Bearer {token}")

        assert err is None
        assert ctx is not None
        assert ctx.tenant_id == "acme"
        assert ctx.user_id == "alice"
        assert ctx.role == "admin"
        assert ctx.auth_method == "jwt"

    async def test_refresh_token_rejected(self):
        token = _make_jwt(token_type="refresh")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            ctx, err = await authenticate(f"Bearer {token}")
        assert ctx is None
        assert err is not None

    async def test_expired_token_rejected(self):
        token = _make_jwt(exp_delta=timedelta(minutes=-5))  # already expired
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            ctx, err = await authenticate(f"Bearer {token}")
        assert ctx is None
        assert err is not None

    async def test_tampered_token_rejected(self):
        token = _make_jwt()
        tampered = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            ctx, err = await authenticate(f"Bearer {tampered}")
        assert ctx is None
        assert err is not None

    async def test_wrong_secret_rejected(self):
        token = _make_jwt(secret="different-secret")
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            ctx, err = await authenticate(f"Bearer {token}")
        assert ctx is None
        assert err is not None

    async def test_garbage_two_dot_string_rejected(self):
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            ctx, err = await authenticate("Bearer not.a.token")
        assert ctx is None
        assert err is not None

    async def test_jwt_missing_claims_rejected(self):
        # Token has type=access but no sub/user_id/role
        now = datetime.now(timezone.utc)
        payload = {
            "type": "access",
            "iat": now,
            "exp": now + timedelta(minutes=15),
        }
        token = jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)
        with patch.dict(os.environ, {"JWT_SECRET_KEY": _SECRET}):
            ctx, err = await authenticate(f"Bearer {token}")
        assert ctx is None
        assert err is not None


# ==================================================================
# 5. API-key path (DB-backed)
# ==================================================================


def _make_mock_connect(row: dict | None, legacy_row: dict | None = None):
    """Return an AsyncMock that behaves like asyncpg.connect → conn.

    ``row`` is returned for the first ``fetchrow`` (scoped api_keys lookup).
    ``legacy_row`` is returned for the second (fallback to tenants.api_key_hash).
    """
    conn = AsyncMock()
    conn.fetchrow.side_effect = [row, legacy_row]
    conn.close.return_value = None
    conn.execute.return_value = None
    return AsyncMock(return_value=conn)


class TestAPIKeyDBAuth:
    async def test_valid_api_key_returns_ctx(self):
        scoped_row = {
            "id": "api-key-uuid",
            "tenant_id": "acme-corp",
            "scopes": ["ingest", "read:audit"],
        }
        mock_connect = _make_mock_connect(scoped_row)
        with patch("agcms.gateway.auth.asyncpg.connect", mock_connect):
            ctx, err = await authenticate("Bearer agcms_prod_key_xyz")

        assert err is None
        assert ctx is not None
        assert ctx.tenant_id == "acme-corp"
        assert ctx.auth_method == "api_key"
        assert ctx.user_id == "api_key"
        assert ctx.role == "user"
        assert ctx.scopes == frozenset({"ingest", "read:audit"})
        assert ctx.api_key_id == "api-key-uuid"

        # Confirm the query was called with the SHA-256 of the token
        expected_hash = hashlib.sha256(b"agcms_prod_key_xyz").hexdigest()
        conn = mock_connect.return_value
        assert conn.fetchrow.call_args_list[0].args[1] == expected_hash
        # last_used_at updated
        assert conn.execute.await_count == 1

    async def test_legacy_api_key_fallback(self):
        """Pre-6.4 keys only exist in tenants.api_key_hash — must still auth."""
        mock_connect = _make_mock_connect(None, legacy_row={"id": "legacy-tenant"})
        with patch("agcms.gateway.auth.asyncpg.connect", mock_connect):
            ctx, err = await authenticate("Bearer agcms_legacy_key")

        assert err is None
        assert ctx is not None
        assert ctx.tenant_id == "legacy-tenant"
        # Legacy keys retain full scope set (behavior preservation).
        assert "admin" in ctx.scopes

    async def test_unknown_api_key_returns_error(self):
        mock_connect = _make_mock_connect(None, legacy_row=None)
        with patch("agcms.gateway.auth.asyncpg.connect", mock_connect):
            ctx, err = await authenticate("Bearer agcms_unknown_key")
        assert ctx is None
        assert err is not None

    async def test_scoped_key_has_only_granted_scopes(self):
        scoped_row = {
            "id": "k1",
            "tenant_id": "t1",
            "scopes": ["ingest"],
        }
        mock_connect = _make_mock_connect(scoped_row)
        with patch("agcms.gateway.auth.asyncpg.connect", mock_connect):
            ctx, err = await authenticate("Bearer agcms_ingest_only")

        assert err is None
        assert ctx.has_scope("ingest")
        assert not ctx.has_scope("admin")
        assert not ctx.has_scope("write:policy")

    async def test_db_connection_failure_returns_error(self):
        def raise_conn(*_a, **_kw):
            raise RuntimeError("db down")

        async def failing_connect(*_a, **_kw):
            raise RuntimeError("db down")

        with patch("agcms.gateway.auth.asyncpg.connect", side_effect=failing_connect):
            ctx, err = await authenticate("Bearer agcms_prod_key_xyz")
        assert ctx is None
        assert err is not None


# ==================================================================
# 6. Selection logic — JWT shape vs API-key shape
# ==================================================================


class TestSelectionLogic:
    async def test_two_dots_uses_jwt_path(self):
        # A string with exactly two dots goes down the JWT path — DB should not
        # be touched. We patch asyncpg.connect to raise if called.
        async def should_not_be_called(*_a, **_kw):
            raise AssertionError("DB was queried for a 2-dot token")

        with patch("agcms.gateway.auth.asyncpg.connect", side_effect=should_not_be_called):
            ctx, err = await authenticate("Bearer invalid.jwt.value")

        # Decode will fail → error, but importantly no DB call
        assert ctx is None
        assert err is not None

    async def test_no_dots_uses_api_key_path(self):
        # Non-dev, non-JWT token must hit the DB
        mock_connect = _make_mock_connect({
            "id": "k1", "tenant_id": "t1", "scopes": ["ingest"],
        })
        with patch("agcms.gateway.auth.asyncpg.connect", mock_connect):
            ctx, err = await authenticate("Bearer plainapikey123")
        assert err is None
        assert ctx is not None
        assert ctx.auth_method == "api_key"
