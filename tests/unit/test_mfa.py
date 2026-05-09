"""Unit tests for the pure MFA helpers in `agcms.auth.mfa`.

These tests require no database, network, or time mocking beyond the
standard pyotp clock.
"""
from __future__ import annotations

import re

import pyotp
import pytest

from agcms.auth import mfa


class TestNewSecret:
    def test_length_is_32(self):
        s = mfa.new_secret()
        # 20 random bytes → 32 base32 chars with no padding
        assert len(s) == 32

    def test_is_uppercase_base32(self):
        s = mfa.new_secret()
        assert re.fullmatch(r"[A-Z2-7]+", s), s

    def test_each_call_is_unique(self):
        seen = {mfa.new_secret() for _ in range(20)}
        # Collisions at 160 bits would be a bug in secrets.token_bytes
        assert len(seen) == 20


class TestProvisioningURI:
    def test_contains_issuer_and_email(self):
        secret = mfa.new_secret()
        uri = mfa.provisioning_uri(secret, email="alice@example.com")
        assert uri.startswith("otpauth://totp/")
        assert "AGCMS" in uri
        assert "alice%40example.com" in uri
        assert f"secret={secret}" in uri


class TestVerifyTOTP:
    def test_correct_code_verifies(self):
        secret = mfa.new_secret()
        code = pyotp.TOTP(secret).now()
        assert mfa.verify_totp(secret, code) is True

    def test_empty_and_malformed_codes_rejected(self):
        secret = mfa.new_secret()
        assert mfa.verify_totp(secret, "") is False
        assert mfa.verify_totp(secret, "abc123") is False
        assert mfa.verify_totp(secret, "12345") is False  # too short
        assert mfa.verify_totp(secret, "1234567") is False  # too long

    def test_wrong_secret_rejected(self):
        secret = mfa.new_secret()
        other = mfa.new_secret()
        code = pyotp.TOTP(other).now()
        assert mfa.verify_totp(secret, code) is False


class TestRecoveryCodes:
    def test_generate_default_count(self):
        codes = mfa.generate_recovery_codes()
        assert len(codes) == 10

    def test_generate_custom_count(self):
        assert len(mfa.generate_recovery_codes(3)) == 3

    def test_codes_use_unambiguous_alphabet(self):
        for code in mfa.generate_recovery_codes():
            assert len(code) == 10
            assert re.fullmatch(r"[A-HJ-KM-NP-Z2-9]+", code), code

    def test_codes_are_unique_within_a_batch(self):
        codes = mfa.generate_recovery_codes(10)
        assert len(set(codes)) == 10

    def test_hash_is_case_and_whitespace_insensitive(self):
        code = "ABCDE23456"
        assert mfa.hash_recovery_code(code) == mfa.hash_recovery_code("abcde23456")
        assert mfa.hash_recovery_code(code) == mfa.hash_recovery_code("ABCDE 23456")
        assert mfa.hash_recovery_code(code) == mfa.hash_recovery_code("ABCDE-23456")
        assert mfa.hash_recovery_code(code) == mfa.hash_recovery_code("  abcde23456  ")

    def test_consume_removes_the_matching_hash(self):
        codes = ("AAAA", "BBBB", "CCCC")
        hashes = mfa.hash_recovery_codes(codes)
        ok, remaining = mfa.consume_recovery_code("bbbb", hashes)
        assert ok is True
        assert len(remaining) == 2
        assert mfa.hash_recovery_code("BBBB") not in remaining
        # Other hashes preserved
        assert mfa.hash_recovery_code("AAAA") in remaining
        assert mfa.hash_recovery_code("CCCC") in remaining

    def test_consume_reject_on_unknown_code(self):
        hashes = mfa.hash_recovery_codes(("AAAA",))
        ok, remaining = mfa.consume_recovery_code("ZZZZ", hashes)
        assert ok is False
        assert remaining == hashes

    def test_consume_rejects_the_same_code_twice(self):
        hashes = mfa.hash_recovery_codes(("AAAA", "BBBB"))
        ok1, after = mfa.consume_recovery_code("AAAA", hashes)
        ok2, _ = mfa.consume_recovery_code("AAAA", after)
        assert ok1 is True
        assert ok2 is False


class TestBeginEnrollment:
    def test_returns_matching_hashes_for_plaintext_codes(self):
        mat = mfa.begin_enrollment(email="dana@example.com")
        assert mat.secret
        assert mat.provisioning_uri.startswith("otpauth://totp/")
        assert len(mat.recovery_codes) == 10
        # Each plaintext hashes to its corresponding hash
        for plain, h in zip(mat.recovery_codes, mat.recovery_hashes):
            assert mfa.hash_recovery_code(plain) == h

    def test_enrollment_secret_verifies_current_totp(self):
        mat = mfa.begin_enrollment(email="dana@example.com")
        assert mfa.verify_totp(mat.secret, pyotp.TOTP(mat.secret).now())


class TestQRCodeDataURL:
    def test_emits_png_data_url(self):
        pytest.importorskip("qrcode")
        url = mfa.qr_png_data_url("otpauth://totp/AGCMS:alice?secret=ABC")
        assert url.startswith("data:image/png;base64,")
        assert len(url) > 200  # non-empty PNG
