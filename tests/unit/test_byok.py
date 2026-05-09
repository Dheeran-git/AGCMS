"""Unit tests for Bring-Your-Own-Key (BYOK) envelope encryption.

Verifies the full lifecycle:
  * AwsKmsClient wraps/unwraps DEKs by delegating to a boto3-shaped
    client, with correct kek_id derivation.
  * Per-tenant registry pins a KMS so encrypt/decrypt routes through it.
  * tenant_keys.mint_and_store reads BYOK from the tenants table and
    persists the wrapped-DEK bytes emitted by the customer KMS.
  * hydrate + install re-route through the same BYOK client after a
    simulated process restart — this is the "prove decrypt still works
    after an AGCMS pod restart" property.
  * rotate switches KMS when the BYOK config changes.

No AWS credentials or boto3 imports are required — we inject a
fake KMS client that emulates the ``encrypt`` / ``decrypt`` shape.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, List

import pytest

from agcms.common import byok, crypto, tenant_keys
from agcms.common.crypto import KMSError


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class FakeAwsKms:
    """Stand-in for boto3.client('kms'). Wraps DEKs with a reversible XOR
    under a key derived from the ARN. Real AWS KMS is opaque; this just
    needs to round-trip deterministically."""

    def __init__(self, arn: str) -> None:
        self._arn = arn
        self._mask = hashlib.sha256(arn.encode()).digest()  # 32 bytes
        self.encrypt_calls = 0
        self.decrypt_calls = 0

    def encrypt(self, *, KeyId: str, Plaintext: bytes) -> dict:
        assert KeyId == self._arn
        self.encrypt_calls += 1
        ct = bytes(b ^ m for b, m in zip(Plaintext, self._mask))
        # Pretend the AWS envelope adds a prefix so wrapped != plaintext.
        return {"CiphertextBlob": b"AWSKMS1|" + ct, "KeyId": KeyId}

    def decrypt(self, *, CiphertextBlob: bytes, KeyId: str) -> dict:
        assert KeyId == self._arn
        assert CiphertextBlob.startswith(b"AWSKMS1|")
        self.decrypt_calls += 1
        ct = CiphertextBlob[len(b"AWSKMS1|"):]
        pt = bytes(b ^ m for b, m in zip(ct, self._mask))
        return {"Plaintext": pt, "KeyId": KeyId}


class FakeConnWithByok:
    """FakeConn that also returns ``tenants.kms_key_arn`` + provider,
    simulating a DB that already has migration 014 applied."""

    def __init__(self) -> None:
        self.tenants: dict[str, dict] = {}
        self.tenant_keys_rows: List[dict] = []

    def add_tenant(self, tenant_id: str, arn: str | None, provider: str | None = "aws") -> None:
        self.tenants[tenant_id] = {
            "kms_key_arn": arn,
            "kms_key_provider": provider if arn else None,
        }

    async def execute(self, sql: str, *args: Any) -> str:
        s = sql.strip().lower()
        if s.startswith("insert into tenant_keys"):
            tenant_id, kid, wrapped, kek_id = args
            self.tenant_keys_rows.append({
                "tenant_id": tenant_id,
                "kid": kid,
                "wrapped_dek": wrapped,
                "kek_id": kek_id,
                "is_active": True,
            })
        elif s.startswith("update tenant_keys"):
            (tenant_id,) = args
            for row in self.tenant_keys_rows:
                if row["tenant_id"] == tenant_id and row["is_active"]:
                    row["is_active"] = False
        else:
            raise AssertionError(f"unexpected execute: {sql!r}")
        return "OK"

    async def fetchrow(self, sql: str, *args: Any):
        s = sql.strip().lower()
        if "from tenants" in s and "kms_key_arn" in s:
            (tenant_id,) = args
            t = self.tenants.get(tenant_id)
            if not t:
                return None
            return t
        if "from tenant_keys" in s and "is_active = true" in s:
            (tenant_id,) = args
            for row in self.tenant_keys_rows:
                if row["tenant_id"] == tenant_id and row["is_active"]:
                    return row
            return None
        raise AssertionError(f"unexpected fetchrow: {sql!r}")

    async def fetch(self, sql: str, *args: Any):
        s = sql.strip().lower()
        if "where is_active = true and tenant_id = any" in s:
            (ids,) = args
            return [r for r in self.tenant_keys_rows
                    if r["is_active"] and r["tenant_id"] in ids]
        if s.startswith("select tenant_id, wrapped_dek"):
            return [r for r in self.tenant_keys_rows if r["is_active"]]
        raise AssertionError(f"unexpected fetch: {sql!r}")

    def transaction(self):
        class _Tx:
            async def __aenter__(self_inner): return None
            async def __aexit__(self_inner, *a): return False
        return _Tx()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("AGCMS_KMS_LOCAL_KEY", raising=False)
    monkeypatch.delenv("AGCMS_KMS_BACKEND", raising=False)
    crypto.reset_kms()
    crypto.reset_cache()
    byok.reset_registry()
    yield
    crypto.reset_kms()
    crypto.reset_cache()
    byok.reset_registry()


ARN = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-efgh"


# ---------------------------------------------------------------------------
# AwsKmsClient
# ---------------------------------------------------------------------------


class TestAwsKmsClient:
    def test_wrap_then_unwrap_round_trips(self):
        fake = FakeAwsKms(ARN)
        client = byok.AwsKmsClient(ARN, client=fake)
        dek = b"a" * 32
        wrapped = client.wrap(dek)
        assert wrapped != dek
        assert wrapped.startswith(b"AWSKMS1|")
        assert client.unwrap(wrapped) == dek
        assert fake.encrypt_calls == 1 and fake.decrypt_calls == 1

    def test_kek_id_derives_stable_fingerprint_from_arn(self):
        c1 = byok.AwsKmsClient(ARN, client=FakeAwsKms(ARN))
        c2 = byok.AwsKmsClient(ARN, client=FakeAwsKms(ARN))
        assert c1.kek_id == c2.kek_id
        assert c1.kek_id.startswith("aws-kms:")
        # Different ARN -> different kek_id
        other = "arn:aws:kms:us-east-1:123456789012:key/zzzz"
        c3 = byok.AwsKmsClient(other, client=FakeAwsKms(other))
        assert c3.kek_id != c1.kek_id

    def test_empty_arn_rejected(self):
        with pytest.raises(KMSError):
            byok.AwsKmsClient("", client=FakeAwsKms(""))

    def test_wrap_failure_raises_kms_error(self):
        class Broken:
            def encrypt(self, **_kw): raise RuntimeError("AccessDenied")
        c = byok.AwsKmsClient(ARN, client=Broken())
        with pytest.raises(KMSError, match="AWS KMS encrypt failed"):
            c.wrap(b"x" * 32)

    def test_unwrap_failure_raises_kms_error(self):
        class Broken:
            def decrypt(self, **_kw): raise RuntimeError("KeyUnavailable")
        c = byok.AwsKmsClient(ARN, client=Broken())
        with pytest.raises(KMSError, match="AWS KMS decrypt failed"):
            c.unwrap(b"AWSKMS1|garbage")

    def test_unexpected_dek_length_rejected(self):
        class WrongLen:
            def decrypt(self, **_kw): return {"Plaintext": b"short"}
        c = byok.AwsKmsClient(ARN, client=WrongLen())
        with pytest.raises(KMSError, match="unexpected DEK length"):
            c.unwrap(b"AWSKMS1|x")


# ---------------------------------------------------------------------------
# Per-tenant registry
# ---------------------------------------------------------------------------


class TestTenantRegistry:
    def test_set_and_get_and_clear(self):
        fake = byok.AwsKmsClient(ARN, client=FakeAwsKms(ARN))
        byok.register_tenant_kms("t1", fake)
        assert byok.get_tenant_kms("t1") is fake
        byok.register_tenant_kms("t1", None)
        assert byok.get_tenant_kms("t1") is None

    def test_build_returns_none_when_unset(self):
        assert byok.build_kms_for_tenant(None) is None
        assert byok.build_kms_for_tenant(byok.ByokConfig("aws", "")) is None

    def test_build_rejects_unimplemented_provider(self):
        with pytest.raises(KMSError, match="not implemented yet"):
            byok.build_kms_for_tenant(byok.ByokConfig("azure", ARN))


# ---------------------------------------------------------------------------
# tenant_keys + crypto integration
# ---------------------------------------------------------------------------


class TestMintAndStoreWithByok:
    @pytest.mark.asyncio
    async def test_byok_tenant_wraps_through_customer_kms(self, monkeypatch):
        conn = FakeConnWithByok()
        conn.add_tenant("t1", ARN, "aws")

        fake = FakeAwsKms(ARN)
        # Pin the fake so the real boto3 import path isn't taken.
        monkeypatch.setattr(
            byok, "build_kms_for_tenant",
            lambda cfg: byok.AwsKmsClient(ARN, client=fake) if cfg else None,
        )

        key = await tenant_keys.mint_and_store(conn, "t1")

        # The stored wrapped_dek is what AWS KMS returned.
        stored = conn.tenant_keys_rows[0]
        assert stored["wrapped_dek"].startswith(b"AWSKMS1|")
        assert stored["kek_id"].startswith("aws-kms:")
        assert fake.encrypt_calls == 1

        # Encrypt/decrypt round-trips through the customer key.
        ct = crypto.encrypt_for_tenant("t1", b"phi")
        assert crypto.decrypt_for_tenant("t1", ct) == b"phi"

        # Cleanliness: the cached TenantKey.dek matches what KMS unwrapped.
        assert len(key.dek) == 32

    @pytest.mark.asyncio
    async def test_non_byok_tenant_uses_platform_kek(self):
        conn = FakeConnWithByok()
        conn.add_tenant("t1", None)  # No BYOK

        await tenant_keys.mint_and_store(conn, "t1")

        stored = conn.tenant_keys_rows[0]
        assert not stored["wrapped_dek"].startswith(b"AWSKMS1|")
        assert stored["kek_id"].startswith("local:")

    @pytest.mark.asyncio
    async def test_hydrate_rewires_byok_after_restart(self, monkeypatch):
        conn = FakeConnWithByok()
        conn.add_tenant("t1", ARN, "aws")

        fake = FakeAwsKms(ARN)
        monkeypatch.setattr(
            byok, "build_kms_for_tenant",
            lambda cfg: byok.AwsKmsClient(ARN, client=fake) if cfg else None,
        )

        await tenant_keys.mint_and_store(conn, "t1")
        ct = crypto.encrypt_for_tenant("t1", b"phi")

        # Simulated pod restart: wipe caches, reset registry.
        crypto.reset_cache()
        byok.reset_registry()

        loaded = await tenant_keys.hydrate(conn)
        assert loaded == ["t1"]
        assert crypto.decrypt_for_tenant("t1", ct) == b"phi"

    @pytest.mark.asyncio
    async def test_rotate_uses_byok_kms(self, monkeypatch):
        conn = FakeConnWithByok()
        conn.add_tenant("t1", ARN, "aws")

        fake = FakeAwsKms(ARN)
        monkeypatch.setattr(
            byok, "build_kms_for_tenant",
            lambda cfg: byok.AwsKmsClient(ARN, client=fake) if cfg else None,
        )

        old = await tenant_keys.mint_and_store(conn, "t1")
        new = await tenant_keys.rotate(conn, "t1")

        assert old.kid != new.kid
        # Two DEKs minted via the customer KMS: initial + rotation.
        assert fake.encrypt_calls == 2
        # Ciphertexts under the new key round-trip.
        assert crypto.decrypt_for_tenant(
            "t1", crypto.encrypt_for_tenant("t1", b"new")
        ) == b"new"


# ---------------------------------------------------------------------------
# Backwards compat: older DB without migration 014
# ---------------------------------------------------------------------------


class TestMissingByokColumnToleratesOldSchemas:
    @pytest.mark.asyncio
    async def test_falls_back_to_platform_kek_when_column_missing(self):
        """tenant_keys must still work if migration 014 has not run yet."""

        class OldConn(FakeConnWithByok):
            async def fetchrow(self, sql: str, *args: Any):
                # Simulate a pre-014 DB that errors on kms_key_arn.
                if "kms_key_arn" in sql:
                    raise Exception('column "kms_key_arn" does not exist')
                return await super().fetchrow(sql, *args)

        conn = OldConn()
        conn.add_tenant("t1", None)

        await tenant_keys.mint_and_store(conn, "t1")
        stored = conn.tenant_keys_rows[0]
        assert stored["kek_id"].startswith("local:")
