"""Unit tests for agcms.common.tenant_keys — DEK persistence + hydration.

Uses an in-memory fake connection that implements the asyncpg subset
the module needs (execute / fetch / fetchrow). This keeps the tests
hermetic — no Postgres required — while still exercising the DEK
lifecycle end-to-end: mint → persist → cache wipe → hydrate → decrypt.
"""
from __future__ import annotations

from typing import Any, List

import pytest

from agcms.common import crypto, tenant_keys


class FakeConn:
    """Minimal asyncpg stand-in that stores wrapped DEKs in a list."""

    def __init__(self) -> None:
        self.rows: List[dict] = []

    async def execute(self, sql: str, *args: Any) -> str:
        sql_lower = sql.strip().lower()
        if sql_lower.startswith("insert into tenant_keys"):
            tenant_id, kid, wrapped, kek_id = args
            self.rows.append({
                "tenant_id": tenant_id,
                "kid": kid,
                "wrapped_dek": wrapped,
                "kek_id": kek_id,
                "is_active": True,
            })
        elif sql_lower.startswith("update tenant_keys"):
            tenant_id, = args
            for row in self.rows:
                if row["tenant_id"] == tenant_id and row["is_active"]:
                    row["is_active"] = False
        else:
            raise AssertionError(f"unexpected execute: {sql!r}")
        return "OK"

    async def fetchrow(self, sql: str, *args: Any):
        if "is_active = TRUE" in sql and "WHERE tenant_id" in sql:
            tenant_id, = args
            for row in self.rows:
                if row["tenant_id"] == tenant_id and row["is_active"]:
                    return row
            return None
        raise AssertionError(f"unexpected fetchrow: {sql!r}")

    async def fetch(self, sql: str, *args: Any):
        if "WHERE is_active = TRUE AND tenant_id = ANY" in sql:
            (ids,) = args
            return [r for r in self.rows if r["is_active"] and r["tenant_id"] in ids]
        if sql.strip().lower().startswith("select tenant_id, wrapped_dek"):
            return [r for r in self.rows if r["is_active"]]
        raise AssertionError(f"unexpected fetch: {sql!r}")

    def transaction(self):
        # Treat as a no-op context manager — tests drive one operation at a time.
        class _Tx:
            async def __aenter__(self_inner): return None
            async def __aexit__(self_inner, *a): return False
        return _Tx()


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("AGCMS_KMS_LOCAL_KEY", raising=False)
    monkeypatch.delenv("AGCMS_KMS_BACKEND", raising=False)
    crypto.reset_kms()
    crypto.reset_cache()
    yield
    crypto.reset_kms()
    crypto.reset_cache()


class TestMintAndStore:
    async def test_mints_and_persists(self):
        conn = FakeConn()
        key = await tenant_keys.mint_and_store(conn, "hospital-a")
        assert len(key.dek) == 32
        assert len(conn.rows) == 1
        assert conn.rows[0]["tenant_id"] == "hospital-a"
        assert conn.rows[0]["kid"] == key.kid
        assert conn.rows[0]["is_active"] is True

    async def test_idempotent_when_active_dek_exists(self):
        conn = FakeConn()
        first = await tenant_keys.mint_and_store(conn, "t1")
        second = await tenant_keys.mint_and_store(conn, "t1")
        assert first.kid == second.kid  # same DEK returned
        assert len(conn.rows) == 1      # no second insert


class TestHydrate:
    async def test_installs_all_active_deks(self):
        conn = FakeConn()
        await tenant_keys.mint_and_store(conn, "t1")
        await tenant_keys.mint_and_store(conn, "t2")

        # Simulate process restart — tenant cache wiped.
        crypto.reset_cache()
        with pytest.raises(crypto.KMSError):
            crypto.encrypt_for_tenant("t1", b"x")

        loaded = await tenant_keys.hydrate(conn)
        assert set(loaded) == {"t1", "t2"}
        assert crypto.decrypt_for_tenant(
            "t1", crypto.encrypt_for_tenant("t1", b"hello")
        ) == b"hello"

    async def test_hydrate_accepts_tenant_filter(self):
        conn = FakeConn()
        await tenant_keys.mint_and_store(conn, "t1")
        await tenant_keys.mint_and_store(conn, "t2")
        crypto.reset_cache()

        loaded = await tenant_keys.hydrate(conn, ["t1"])
        assert loaded == ["t1"]
        # t2 remains un-hydrated
        with pytest.raises(crypto.KMSError):
            crypto.encrypt_for_tenant("t2", b"x")

    async def test_hydrate_empty_filter_noops(self):
        conn = FakeConn()
        await tenant_keys.mint_and_store(conn, "t1")
        crypto.reset_cache()
        loaded = await tenant_keys.hydrate(conn, [])
        assert loaded == []


class TestRoundTripAcrossRestart:
    async def test_encrypt_persist_restart_decrypt(self):
        conn = FakeConn()
        await tenant_keys.mint_and_store(conn, "hospital-a")
        ciphertext = crypto.encrypt_for_tenant(
            "hospital-a", b"alice@example.com", aad=b"col:email"
        )

        # Hard restart: wipe both KMS singleton + per-tenant cache.
        crypto.reset_cache()
        await tenant_keys.hydrate(conn)

        assert crypto.decrypt_for_tenant(
            "hospital-a", ciphertext, aad=b"col:email"
        ) == b"alice@example.com"


class TestRotate:
    async def test_rotate_issues_new_dek_and_retires_old(self):
        conn = FakeConn()
        old = await tenant_keys.mint_and_store(conn, "t1")
        # Encrypt under old key
        old_ct = crypto.encrypt_for_tenant("t1", b"legacy")

        new = await tenant_keys.rotate(conn, "t1")
        assert new.kid != old.kid

        active = [r for r in conn.rows if r["is_active"]]
        retired = [r for r in conn.rows if not r["is_active"]]
        assert len(active) == 1
        assert len(retired) == 1
        assert active[0]["kid"] == new.kid

        # New ciphertexts bind to the new DEK.
        new_ct = crypto.encrypt_for_tenant("t1", b"fresh")
        assert crypto.decrypt_for_tenant("t1", new_ct) == b"fresh"

        # Old ciphertext decryption would require the retired DEK to
        # still be reachable via its kid — single-DEK lookup rejects it.
        with pytest.raises(crypto.KMSError):
            crypto.decrypt_for_tenant("t1", old_ct)
