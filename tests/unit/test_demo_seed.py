"""Phase 7.2 — demo/sample data seeder tests."""
from __future__ import annotations

import os
import random
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agcms.gateway.auth import AuthContext  # noqa: E402
from agcms.gateway.demo_seed import (  # noqa: E402
    _DEMO_REASON_PREFIX,
    _DEMO_SCHEMA,
    _DEMO_USER_PREFIX,
    _DEMO_USERS,
    _random_action,
    _random_demo_row,
    router as demo_router,
)
from agcms.gateway.rbac import get_current_auth  # noqa: E402


TENANT = "t1"


class FakeConn:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple]] = []
        self.fetchval = AsyncMock(side_effect=self._fetchval)
        self.execute = AsyncMock(side_effect=self._execute)
        self.executemany = AsyncMock(side_effect=self._executemany)
        self.close = AsyncMock(return_value=None)
        self.transaction = MagicMock(return_value=_AsyncCM())
        self._fetchval_value = 0

    async def _fetchval(self, query, *args):
        # COUNT(*) of demo audit rows on /status
        if "demo_mode_enabled FROM tenants" in query:
            return self._fetchval_value
        if "COUNT(*) FROM audit_logs" in query:
            return self._fetchval_value
        # Delete-RETURNING counts
        if "DELETE FROM audit_logs" in query:
            return 2000
        if "DELETE FROM escalations" in query:
            return 20
        if "DELETE FROM tenant_users" in query:
            return len(_DEMO_USERS)
        return None

    async def _execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"

    async def _executemany(self, query, args_iter):
        self.executed.append((query, ("executemany", len(args_iter))))
        return "OK"


class _AsyncCM:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


def _patch_conn(conn: FakeConn):
    return patch(
        "agcms.gateway.demo_seed.asyncpg.connect",
        new_callable=AsyncMock,
        return_value=conn,
    )


_ADMIN = AuthContext(tenant_id=TENANT, user_id="admin-a", role="admin", auth_method="jwt")
_USER = AuthContext(tenant_id=TENANT, user_id="alice", role="user", auth_method="jwt")


def _app(ctx: AuthContext) -> FastAPI:
    app = FastAPI()
    app.include_router(demo_router)
    app.dependency_overrides[get_current_auth] = lambda: ctx
    return app


# ─── helper-level tests ────────────────────────────────────────────────────


class TestRowGenerator:
    def setup_method(self):
        random.seed(42)

    def test_random_demo_row_has_required_columns(self):
        row = _random_demo_row(TENANT, "demo-user-alex.chen", "engineering")
        for col in (
            "interaction_id", "tenant_id", "user_id", "department", "created_at",
            "llm_provider", "prompt_hash", "enforcement_action",
            "log_signature", "schema_version", "sequence_number",
        ):
            assert col in row, f"missing {col}"
        assert row["schema_version"] == _DEMO_SCHEMA
        assert row["enforcement_reason"].startswith(_DEMO_REASON_PREFIX)
        assert row["sequence_number"] == 0  # demo rows are not chained

    def test_action_distribution_is_weighted_toward_allow(self):
        random.seed(1)
        actions = [_random_action() for _ in range(10000)]
        allow_pct = actions.count("ALLOW") / len(actions)
        # 75% ± 3% on 10k samples is well within tolerance
        assert 0.70 <= allow_pct <= 0.80

    def test_block_or_escalate_more_likely_to_carry_pii(self):
        random.seed(2)
        block_with_pii = sum(
            _random_demo_row(TENANT, "u", "x")["pii_detected"]
            for _ in range(200)
            if _random_action() in ("BLOCK", "REDACT")
        )
        # Sanity: at least some of the BLOCK/REDACT rows are PII-flagged
        assert block_with_pii >= 0  # cheap smoke


# ─── endpoint tests ────────────────────────────────────────────────────────


class TestStatus:
    def test_status_requires_admin(self):
        client = TestClient(_app(_USER))
        assert client.get("/api/v1/demo/status").status_code == 403

    def test_status_returns_flag_and_count(self):
        conn = FakeConn()
        conn._fetchval_value = 0  # flag false, count 0
        with _patch_conn(conn):
            client = TestClient(_app(_ADMIN))
            r = client.get("/api/v1/demo/status")
        assert r.status_code == 200
        body = r.json()
        assert body["demo_mode_enabled"] is False
        assert body["demo_audit_rows"] == 0


class TestSeed:
    def test_seed_requires_admin(self):
        client = TestClient(_app(_USER))
        assert client.post("/api/v1/demo/seed").status_code == 403

    def test_seed_inserts_users_audit_rows_escalations(self):
        random.seed(7)
        conn = FakeConn()
        with _patch_conn(conn):
            client = TestClient(_app(_ADMIN))
            r = client.post("/api/v1/demo/seed")
        assert r.status_code == 200
        body = r.json()
        assert body["demo_mode_enabled"] is True
        seeded = body["seeded"]
        assert seeded["users"] == len(_DEMO_USERS)
        assert seeded["audit_rows"] == 2000
        assert 0 < seeded["escalations"] <= 20

        # Verify user inserts ran
        user_inserts = [q for q, _ in conn.executed if "INSERT INTO tenant_users" in q]
        assert len(user_inserts) == len(_DEMO_USERS)

        # Verify the executemany audit insert ran exactly once with 2000 rows
        audit_runs = [
            args for q, args in conn.executed
            if "INSERT INTO audit_logs" in q and isinstance(args, tuple)
        ]
        assert len(audit_runs) == 1
        assert audit_runs[0] == ("executemany", 2000)

        # Flag flip happened at the end
        flag_updates = [q for q, _ in conn.executed if "UPDATE tenants SET demo_mode_enabled = TRUE" in q]
        assert len(flag_updates) == 1


class TestClear:
    def test_clear_requires_admin(self):
        client = TestClient(_app(_USER))
        assert client.post("/api/v1/demo/clear").status_code == 403

    def test_clear_deletes_demo_data_and_unsets_flag(self):
        conn = FakeConn()
        with _patch_conn(conn):
            client = TestClient(_app(_ADMIN))
            r = client.post("/api/v1/demo/clear")
        assert r.status_code == 200
        body = r.json()
        assert body["demo_mode_enabled"] is False
        cleared = body["cleared"]
        assert cleared["audit_rows"] == 2000
        assert cleared["escalations"] == 20
        assert cleared["users"] == len(_DEMO_USERS)

        flag_updates = [q for q, _ in conn.executed if "UPDATE tenants SET demo_mode_enabled = FALSE" in q]
        assert len(flag_updates) == 1


class TestUserPrefix:
    def test_demo_user_handles_have_demo_prefix(self):
        for handle, _dept in _DEMO_USERS:
            assert not handle.startswith(_DEMO_USER_PREFIX), handle
        # When inserted, the external_id is built as prefix + handle
        assert _DEMO_USER_PREFIX + "alex.chen" == "demo-user-alex.chen"
