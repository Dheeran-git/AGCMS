"""Unit tests for the AGCMS Tenant Management Service.

Covers:
  - API key generation (length, prefix, uniqueness)
  - ID slugification (spaces, special chars, long names)
  - SHA-256 hashing used for provisioned keys
  - provision_tenant: happy path, invalid plan, duplicate ID collision
  - get_tenant: found, not found
  - get_usage: aggregation query calls
  - update_settings: merge, not found
  - HTTP endpoints via FastAPI TestClient (mocked service layer)
"""

import hashlib
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# ------------------------------------------------------------------ #
# Import the modules under test                                        #
# ------------------------------------------------------------------ #
from agcms.tenant.service import (
    _generate_api_key,
    _hash_key,
    _slugify,
    provision_tenant,
    get_tenant,
    get_usage,
    update_settings,
)
from agcms.tenant.schemas import (
    ProvisionResponse,
    TenantDetail,
    UsageStats,
)
from agcms.tenant.main import app


# ==================================================================
# 1. Helper function unit tests (pure / no I/O)
# ==================================================================


class TestSlugify:
    def test_simple_name(self):
        assert _slugify("Acme Corp") == "acme-corp"

    def test_special_chars_become_dashes(self):
        slug = _slugify("Acme & Co. Ltd!")
        assert all(c.isalnum() or c == "-" for c in slug)

    def test_consecutive_dashes_collapsed(self):
        slug = _slugify("A  B")  # two spaces → two dashes → one
        assert "--" not in slug

    def test_max_length_28(self):
        long_name = "a" * 100
        assert len(_slugify(long_name)) <= 28

    def test_empty_string(self):
        # Empty string slugifies to empty; caller handles fallback
        assert _slugify("") == ""


class TestGenerateApiKey:
    def test_prefix(self):
        key = _generate_api_key("acme-corp")
        assert key.startswith("agcms_acme-cor_")

    def test_length(self):
        key = _generate_api_key("t1")
        # "agcms_" (6) + up to 8 chars of tenant_id + "_" (1) + 32 random = at least 39
        assert len(key) >= 39

    def test_uniqueness(self):
        keys = {_generate_api_key("tenant") for _ in range(50)}
        assert len(keys) == 50  # all distinct


class TestHashKey:
    def test_matches_sha256(self):
        key = "agcms_test_key_for_development"
        expected = hashlib.sha256(key.encode()).hexdigest()
        assert _hash_key(key) == expected

    def test_output_length(self):
        assert len(_hash_key("anything")) == 64


# ==================================================================
# 2. provision_tenant (DB mocked)
# ==================================================================


def _mock_db_for_provision(id_exists: bool = False):
    """Return an async mock for agcms.tenant.db.fetch_one that simulates
    id existence check (returns a row if exists, None otherwise)."""
    async def fake_fetch_one(query, *args):
        if "WHERE id = $1" in query:
            return {"id": args[0]} if id_exists else None
        return None
    return fake_fetch_one


class _FakeConn:
    """Async context / conn mock capturing every write for assertions.

    Mimics the asyncpg subset the service uses: execute, fetchrow,
    transaction(). fetchrow returns None so mint_and_store takes the
    'no active DEK → insert new row' path.
    """
    def __init__(self):
        self.executes: list[tuple[str, tuple]] = []

    async def execute(self, query, *args):
        self.executes.append((query, args))
        return "OK"

    async def fetchrow(self, query, *args):
        return None

    def transaction(self):
        class _Tx:
            async def __aenter__(self_inner): return None
            async def __aexit__(self_inner, *a): return False
        return _Tx()


def _patch_conn(fake: _FakeConn):
    """Patch db.connection so `async with db.connection() as conn`
    yields our FakeConn."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_connection():
        yield fake

    return patch("agcms.tenant.service.db.connection", fake_connection)


class TestProvisionTenant:
    async def test_happy_path(self):
        fake = _FakeConn()
        with (
            patch("agcms.tenant.service.db.fetch_one", side_effect=_mock_db_for_provision(False)),
            _patch_conn(fake),
        ):
            result = await provision_tenant("Acme Corp", "admin@acme.com", "starter")

        assert isinstance(result, ProvisionResponse)
        assert result.tenant_id == "acme-corp"
        assert result.api_key.startswith("agcms_acme-cor_")
        assert result.plan == "starter"
        assert result.admin_email == "admin@acme.com"
        # tenant + admin user + default policy + tenant_keys DEK insert = 4
        assert len(fake.executes) == 4

    async def test_invalid_plan_raises(self):
        with pytest.raises(ValueError, match="Invalid plan"):
            await provision_tenant("Test Co", "t@t.com", "nonexistent")

    async def test_duplicate_id_gets_suffix(self):
        call_count = 0

        async def fake_fetch_one(query, *args):
            nonlocal call_count
            if "WHERE id = $1" in query:
                call_count += 1
                # First check: ID "acme-corp" exists; second check: "acme-corp-2" does not
                return {"id": args[0]} if call_count == 1 else None
            return None

        fake = _FakeConn()
        with (
            patch("agcms.tenant.service.db.fetch_one", side_effect=fake_fetch_one),
            _patch_conn(fake),
        ):
            result = await provision_tenant("Acme Corp", "admin@acme.com", "business")

        assert result.tenant_id == "acme-corp-2"

    async def test_api_key_is_hashed_in_db_insert(self):
        fake = _FakeConn()

        async def fake_fetch_one(query, *args):
            return None

        with (
            patch("agcms.tenant.service.db.fetch_one", side_effect=fake_fetch_one),
            _patch_conn(fake),
        ):
            result = await provision_tenant("Hash Test", "h@t.com", "enterprise")

        # First execute is the tenant INSERT: args are (id, name, plan, email, key_hash)
        tenant_insert_args = fake.executes[0][1]
        stored_hash = tenant_insert_args[4]  # 5th positional arg
        expected_hash = _hash_key(result.api_key)
        assert stored_hash == expected_hash, "API key must be stored as its SHA-256 hash"


# ==================================================================
# 3. get_tenant
# ==================================================================


class TestGetTenant:
    async def test_found(self):
        from datetime import datetime, timezone
        fake_row = {
            "id": "acme-corp",
            "name": "Acme Corp",
            "plan": "starter",
            "admin_email": "a@a.com",
            "is_active": True,
            "settings": {},
            "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        }
        with patch("agcms.tenant.service.db.fetch_one", new_callable=AsyncMock, return_value=fake_row):
            tenant = await get_tenant("acme-corp")

        assert tenant is not None
        assert tenant.id == "acme-corp"
        assert tenant.plan == "starter"

    async def test_not_found(self):
        with patch("agcms.tenant.service.db.fetch_one", new_callable=AsyncMock, return_value=None):
            tenant = await get_tenant("no-such-tenant")
        assert tenant is None


# ==================================================================
# 4. get_usage
# ==================================================================


class TestGetUsage:
    async def test_returns_usage_stats(self):
        # fetch_val is called 5 times for the 5 counters
        with patch("agcms.tenant.service.db.fetch_val", new_callable=AsyncMock, return_value=42):
            stats = await get_usage("acme-corp")

        assert isinstance(stats, UsageStats)
        assert stats.tenant_id == "acme-corp"
        assert stats.requests_today == 42
        assert stats.blocked_today == 42

    async def test_none_values_default_to_zero(self):
        with patch("agcms.tenant.service.db.fetch_val", new_callable=AsyncMock, return_value=None):
            stats = await get_usage("empty-tenant")
        assert stats.requests_today == 0
        assert stats.requests_this_month == 0


# ==================================================================
# 5. update_settings
# ==================================================================


class TestUpdateSettings:
    async def test_found_updates(self):
        with (
            patch("agcms.tenant.service.db.fetch_one", new_callable=AsyncMock, return_value={"id": "t1"}),
            patch("agcms.tenant.service.db.execute", new_callable=AsyncMock) as mock_exec,
        ):
            result = await update_settings("t1", {"requests_per_minute": 30})

        assert result is True
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args.args
        assert "UPDATE tenants" in call_args[0]

    async def test_not_found_returns_false(self):
        with patch("agcms.tenant.service.db.fetch_one", new_callable=AsyncMock, return_value=None):
            result = await update_settings("ghost", {"x": 1})
        assert result is False


# ==================================================================
# 6. HTTP endpoint tests (FastAPI TestClient)
# ==================================================================


class TestHTTPEndpoints:
    def setup_method(self):
        self.client = TestClient(app)

    def test_health(self):
        resp = self.client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_provision_bad_plan(self):
        resp = self.client.post("/provision", json={
            "name": "Bad Plan Co",
            "admin_email": "b@b.com",
            "plan": "free",
        })
        assert resp.status_code == 400
        assert "Invalid plan" in resp.json()["detail"]

    def test_get_tenant_not_found(self):
        with patch("agcms.tenant.main.service.get_tenant", new_callable=AsyncMock, return_value=None):
            resp = self.client.get("/tenants/no-such")
        assert resp.status_code == 404

    def test_provision_success(self):
        async def fake_provision(name, admin_email, plan):
            return ProvisionResponse(
                tenant_id="test-co",
                api_key="agcms_test-co__abcdef",
                name=name,
                plan=plan,
                admin_email=admin_email,
                message="done",
            )

        with patch("agcms.tenant.main.service.provision_tenant", side_effect=fake_provision):
            resp = self.client.post("/provision", json={
                "name": "Test Co",
                "admin_email": "t@t.com",
                "plan": "business",
            })

        assert resp.status_code == 201
        data = resp.json()
        assert data["tenant_id"] == "test-co"
        assert "api_key" in data

    def test_get_tenant_found(self):
        from datetime import datetime, timezone
        fake_tenant = TenantDetail(
            id="t1", name="T1", plan="starter",
            admin_email="a@a.com", is_active=True,
            settings={}, created_at="2026-01-01T00:00:00+00:00",
        )
        with patch("agcms.tenant.main.service.get_tenant", new_callable=AsyncMock, return_value=fake_tenant):
            resp = self.client.get("/tenants/t1")

        assert resp.status_code == 200
        assert resp.json()["id"] == "t1"

    def test_update_settings_not_found(self):
        with patch("agcms.tenant.main.service.update_settings", new_callable=AsyncMock, return_value=False):
            resp = self.client.put("/tenants/ghost/settings", json={
                "settings": {"requests_per_minute": 30}
            })
        assert resp.status_code == 404
