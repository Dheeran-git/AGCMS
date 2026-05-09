"""Unit tests for agcms.common.crypto — envelope encryption primitives."""
from __future__ import annotations

import base64

import pytest

from agcms.common import crypto


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    """Reset KMS + tenant cache + env for each test."""
    monkeypatch.delenv("AGCMS_KMS_LOCAL_KEY", raising=False)
    monkeypatch.delenv("AGCMS_KMS_BACKEND", raising=False)
    crypto.reset_kms()
    crypto.reset_cache()
    yield
    crypto.reset_kms()
    crypto.reset_cache()


class TestLocalKMS:
    def test_wrap_roundtrip(self):
        kms = crypto.LocalKMS(b"0" * 32)
        dek = crypto.new_dek()
        wrapped = kms.wrap(dek)
        assert wrapped != dek
        assert kms.unwrap(wrapped) == dek

    def test_wrap_is_nondeterministic(self):
        kms = crypto.LocalKMS(b"0" * 32)
        dek = crypto.new_dek()
        assert kms.wrap(dek) != kms.wrap(dek)

    def test_from_env_uses_provided_key(self, monkeypatch):
        k = bytes(32)
        monkeypatch.setenv("AGCMS_KMS_LOCAL_KEY", base64.b64encode(k).decode())
        kms = crypto.LocalKMS.from_env()
        dek = crypto.new_dek()
        assert kms.unwrap(kms.wrap(dek)) == dek

    def test_from_env_dev_fallback(self):
        # No env set — falls back without crashing
        kms = crypto.LocalKMS.from_env()
        dek = crypto.new_dek()
        assert kms.unwrap(kms.wrap(dek)) == dek

    def test_wrong_kek_cannot_unwrap(self):
        kms1 = crypto.LocalKMS(b"0" * 32)
        kms2 = crypto.LocalKMS(b"1" * 32)
        dek = crypto.new_dek()
        wrapped = kms1.wrap(dek)
        with pytest.raises(crypto.KMSError):
            kms2.unwrap(wrapped)

    def test_bad_kek_size_rejected(self):
        with pytest.raises(crypto.KMSError):
            crypto.LocalKMS(b"short")


class TestGetKMS:
    def test_default_is_local(self):
        kms = crypto.get_kms()
        assert isinstance(kms, crypto.LocalKMS)

    def test_singleton_is_memoized(self):
        assert crypto.get_kms() is crypto.get_kms()

    def test_unsupported_backend_raises(self, monkeypatch):
        monkeypatch.setenv("AGCMS_KMS_BACKEND", "aws")
        with pytest.raises(crypto.KMSError, match="not implemented"):
            crypto.get_kms()


class TestTenantEncryption:
    def test_roundtrip(self):
        key = crypto.mint_tenant_key("hospital-a")
        assert len(key.dek) == 32
        ct = crypto.encrypt_for_tenant("hospital-a", b"alice@example.com")
        assert crypto.decrypt_for_tenant("hospital-a", ct) == b"alice@example.com"

    def test_ciphertext_starts_with_magic(self):
        crypto.mint_tenant_key("t1")
        ct = crypto.encrypt_for_tenant("t1", b"hello")
        assert ct.startswith(crypto.MAGIC)

    def test_same_plaintext_yields_different_ciphertext(self):
        crypto.mint_tenant_key("t1")
        assert crypto.encrypt_for_tenant("t1", b"x") != crypto.encrypt_for_tenant("t1", b"x")

    def test_cross_tenant_decrypt_rejected(self):
        crypto.mint_tenant_key("tenant-a")
        crypto.mint_tenant_key("tenant-b")
        ct = crypto.encrypt_for_tenant("tenant-a", b"secret")
        # Decrypting the tenant-a ciphertext under tenant-b's DEK must fail.
        with pytest.raises(crypto.KMSError):
            crypto.decrypt_for_tenant("tenant-b", ct)

    def test_tamper_detected(self):
        crypto.mint_tenant_key("t1")
        ct = bytearray(crypto.encrypt_for_tenant("t1", b"hello"))
        # Flip a bit in the body (past magic + kid + nonce) and decrypt must fail.
        ct[-1] ^= 0x01
        with pytest.raises(crypto.KMSError):
            crypto.decrypt_for_tenant("t1", bytes(ct))

    def test_bad_magic_rejected(self):
        crypto.mint_tenant_key("t1")
        with pytest.raises(crypto.KMSError, match="magic"):
            crypto.decrypt_for_tenant("t1", b"\x00" * 64)

    def test_install_recovers_from_wrapped(self):
        k1 = crypto.mint_tenant_key("t1")
        wrapped = k1.wrapped_dek
        ct = crypto.encrypt_for_tenant("t1", b"persisted")

        # Simulate a process restart: tenant cache is wiped.
        crypto.reset_cache()
        with pytest.raises(crypto.KMSError):
            crypto.decrypt_for_tenant("t1", ct)

        # After installing the wrapped DEK, decrypt works.
        crypto.install_tenant_key("t1", wrapped)
        assert crypto.decrypt_for_tenant("t1", ct) == b"persisted"

    def test_aad_binding(self):
        crypto.mint_tenant_key("t1")
        ct = crypto.encrypt_for_tenant("t1", b"v", aad=b"column:email")
        # Correct AAD decrypts
        assert crypto.decrypt_for_tenant("t1", ct, aad=b"column:email") == b"v"
        # Wrong AAD fails
        with pytest.raises(crypto.KMSError):
            crypto.decrypt_for_tenant("t1", ct, aad=b"column:full_name")


class TestMissingDEK:
    def test_encrypt_without_install_raises(self):
        with pytest.raises(crypto.KMSError, match="No DEK loaded"):
            crypto.encrypt_for_tenant("unknown-tenant", b"x")
