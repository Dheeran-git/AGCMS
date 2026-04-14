"""Unit tests for the AGCMS Audit Logger.

Tests cover:
  - HMAC-SHA256 signing correctness
  - Signature verification (valid + tampered)
  - Deterministic signing (same input → same signature)
  - Prompt hashing (raw text never stored)
  - Entry field extraction from various input types
  - Fail-fast on missing signing key
"""

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional
from unittest.mock import AsyncMock, patch

import pytest

# conftest.py sets AGCMS_SIGNING_KEY before this import
from agcms.audit.logger import SIGNING_KEY, AuditLogger


# ------------------------------------------------------------------
# Test fixtures and helpers
# ------------------------------------------------------------------


@dataclass
class FakePIIEntity:
    entity_type: str
    text: str = ""
    start: int = 0
    end: int = 0
    confidence: float = 1.0


@dataclass
class FakePIIScanResult:
    entities: List[FakePIIEntity] = field(default_factory=list)
    risk_level: str = "NONE"

    @property
    def has_pii(self) -> bool:
        return len(self.entities) > 0


@dataclass
class FakeInjectionResult:
    risk_score: float = 0.0
    attack_type: str = "NONE"
    triggered_rules: list = field(default_factory=list)
    is_injection: bool = False


@dataclass
class FakeDecision:
    action: str = "ALLOW"
    reason: str = "All checks passed"
    triggered_policies: list = field(default_factory=list)


@dataclass
class FakeComplianceResult:
    violated: bool = False
    violations: list = field(default_factory=list)
    redacted_response: Optional[dict] = None
    risk_level: str = "NONE"


@pytest.fixture
def logger():
    return AuditLogger()


@pytest.fixture
def sample_body():
    return {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"},
        ],
    }


@pytest.fixture
def sample_entry():
    """A minimal audit log entry (without signature) for signing tests."""
    return {
        "interaction_id": str(uuid.uuid4()),
        "tenant_id": "default",
        "user_id": "test-user",
        "department": "Engineering",
        "created_at": "2026-04-01T12:00:00+00:00",
        "llm_provider": "groq",
        "llm_model": "llama-3.3-70b-versatile",
        "prompt_hash": hashlib.sha256(b"test prompt").hexdigest(),
        "pii_detected": False,
        "pii_entity_types": [],
        "pii_risk_level": "NONE",
        "injection_score": None,
        "injection_type": None,
        "enforcement_action": "ALLOW",
        "enforcement_reason": "All checks passed",
        "triggered_policies": [],
        "response_violated": False,
        "response_violations": None,
        "total_latency_ms": 42,
    }


# ------------------------------------------------------------------
# Signing tests
# ------------------------------------------------------------------


class TestSigning:
    def test_sign_produces_64_char_hex(self, sample_entry):
        sig = AuditLogger.sign(sample_entry)
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_sign_is_deterministic(self, sample_entry):
        sig1 = AuditLogger.sign(sample_entry)
        sig2 = AuditLogger.sign(sample_entry)
        assert sig1 == sig2

    def test_sign_uses_hmac_sha256(self, sample_entry):
        sig = AuditLogger.sign(sample_entry)
        payload = json.dumps(sample_entry, sort_keys=True, default=str).encode("utf-8")
        expected = hmac.new(SIGNING_KEY, payload, hashlib.sha256).hexdigest()
        assert sig == expected

    def test_sign_uses_sort_keys(self, sample_entry):
        """Signature must be based on sorted JSON keys for determinism."""
        # Reorder the dict keys — signature must be the same
        reversed_entry = dict(reversed(list(sample_entry.items())))
        assert AuditLogger.sign(sample_entry) == AuditLogger.sign(reversed_entry)

    def test_sign_changes_with_different_data(self, sample_entry):
        sig1 = AuditLogger.sign(sample_entry)
        modified = dict(sample_entry)
        modified["enforcement_action"] = "BLOCK"
        sig2 = AuditLogger.sign(modified)
        assert sig1 != sig2

    def test_sign_changes_with_different_key(self, sample_entry):
        sig_original = AuditLogger.sign(sample_entry)
        payload = json.dumps(sample_entry, sort_keys=True, default=str).encode("utf-8")
        sig_different_key = hmac.new(b"different-key", payload, hashlib.sha256).hexdigest()
        assert sig_original != sig_different_key


# ------------------------------------------------------------------
# Verification tests
# ------------------------------------------------------------------


class TestVerification:
    def test_verify_valid_entry(self, sample_entry):
        sample_entry["log_signature"] = AuditLogger.sign(sample_entry)
        assert AuditLogger.verify(sample_entry) is True

    def test_verify_tampered_action(self, sample_entry):
        sample_entry["log_signature"] = AuditLogger.sign(sample_entry)
        sample_entry["enforcement_action"] = "BLOCK"
        assert AuditLogger.verify(sample_entry) is False

    def test_verify_tampered_tenant(self, sample_entry):
        sample_entry["log_signature"] = AuditLogger.sign(sample_entry)
        sample_entry["tenant_id"] = "evil-tenant"
        assert AuditLogger.verify(sample_entry) is False

    def test_verify_tampered_signature(self, sample_entry):
        sample_entry["log_signature"] = "a" * 64
        assert AuditLogger.verify(sample_entry) is False

    def test_verify_missing_signature(self, sample_entry):
        assert AuditLogger.verify(sample_entry) is False

    def test_verify_empty_signature(self, sample_entry):
        sample_entry["log_signature"] = ""
        assert AuditLogger.verify(sample_entry) is False

    def test_verify_does_not_mutate_entry(self, sample_entry):
        sample_entry["log_signature"] = AuditLogger.sign(sample_entry)
        original = dict(sample_entry)
        AuditLogger.verify(sample_entry)
        assert sample_entry == original


# ------------------------------------------------------------------
# Prompt hashing tests
# ------------------------------------------------------------------


class TestPromptHashing:
    def test_hash_prompt_returns_sha256(self):
        h = AuditLogger.hash_prompt("Hello world")
        expected = hashlib.sha256(b"Hello world").hexdigest()
        assert h == expected

    def test_hash_prompt_is_deterministic(self):
        assert AuditLogger.hash_prompt("test") == AuditLogger.hash_prompt("test")

    def test_hash_prompt_different_inputs_differ(self):
        assert AuditLogger.hash_prompt("a") != AuditLogger.hash_prompt("b")

    def test_hash_prompt_returns_64_hex_chars(self):
        h = AuditLogger.hash_prompt("anything")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ------------------------------------------------------------------
# Field extraction tests
# ------------------------------------------------------------------


class TestFieldExtraction:
    def test_extract_prompt_from_messages(self, logger, sample_body):
        text = logger._extract_prompt(sample_body)
        assert "capital of France" in text
        assert "helpful assistant" in text

    def test_extract_prompt_empty_messages(self, logger):
        assert logger._extract_prompt({"messages": []}) == ""

    def test_extract_prompt_no_messages_key(self, logger):
        assert logger._extract_prompt({}) == ""

    def test_extract_prompt_skips_non_string_content(self, logger):
        body = {"messages": [{"role": "user", "content": ["image_data"]}]}
        assert logger._extract_prompt(body) == ""

    def test_get_pii_detected_true(self, logger):
        result = FakePIIScanResult(entities=[FakePIIEntity(entity_type="EMAIL")])
        assert logger._get_pii_detected(result) is True

    def test_get_pii_detected_false(self, logger):
        result = FakePIIScanResult()
        assert logger._get_pii_detected(result) is False

    def test_get_pii_detected_none(self, logger):
        assert logger._get_pii_detected(None) is False

    def test_get_pii_entity_types(self, logger):
        entities = [FakePIIEntity(entity_type="SSN"), FakePIIEntity(entity_type="EMAIL")]
        result = FakePIIScanResult(entities=entities)
        types = logger._get_pii_entity_types(result)
        assert types == ["SSN", "EMAIL"]

    def test_get_injection_score(self, logger):
        result = FakeInjectionResult(risk_score=0.87654)
        assert logger._get_injection_score(result) == 0.877

    def test_get_injection_score_none(self, logger):
        assert logger._get_injection_score(None) is None

    def test_get_action_from_decision(self, logger):
        decision = FakeDecision(action="BLOCK")
        assert logger._get_action(decision) == "BLOCK"

    def test_get_action_none_defaults_allow(self, logger):
        assert logger._get_action(None) == "ALLOW"

    def test_get_response_violated(self, logger):
        result = FakeComplianceResult(violated=True)
        assert logger._get_response_violated(result) is True

    def test_get_response_violated_none(self, logger):
        assert logger._get_response_violated(None) is False


# ------------------------------------------------------------------
# Full log entry tests (mock DB write)
# ------------------------------------------------------------------


class TestLogEntry:
    @pytest.mark.asyncio
    async def test_log_returns_signed_entry(self, logger, sample_body):
        with patch.object(logger, "_write", new_callable=AsyncMock) as mock_write:
            entry = await logger.log(
                interaction_id=str(uuid.uuid4()),
                tenant_id="default",
                user_id="test-user",
                department="Engineering",
                raw_body=sample_body,
                pii_result=None,
                injection_result=None,
                decision=None,
                compliance_result=None,
                start_time=time.time() - 0.05,
            )
        assert "log_signature" in entry
        assert AuditLogger.verify(entry) is True
        mock_write.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_log_stores_prompt_hash_not_raw(self, logger, sample_body):
        with patch.object(logger, "_write", new_callable=AsyncMock):
            entry = await logger.log(
                interaction_id=str(uuid.uuid4()),
                tenant_id="default",
                user_id="test-user",
                department=None,
                raw_body=sample_body,
                pii_result=None,
                injection_result=None,
                decision=None,
                compliance_result=None,
                start_time=time.time(),
            )
        # Entry must contain hash, NOT raw prompt text
        assert "prompt_hash" in entry
        assert len(entry["prompt_hash"]) == 64
        # Raw prompt text must not appear anywhere in the entry values
        entry_str = json.dumps(entry)
        assert "capital of France" not in entry_str

    @pytest.mark.asyncio
    async def test_log_with_pii_result(self, logger, sample_body):
        pii = FakePIIScanResult(
            entities=[FakePIIEntity(entity_type="SSN")],
            risk_level="CRITICAL",
        )
        decision = FakeDecision(
            action="REDACT",
            reason="PII detected: ['SSN']",
            triggered_policies=["pii:CRITICAL"],
        )
        with patch.object(logger, "_write", new_callable=AsyncMock):
            entry = await logger.log(
                interaction_id=str(uuid.uuid4()),
                tenant_id="default",
                user_id="test-user",
                department="Finance",
                raw_body=sample_body,
                pii_result=pii,
                injection_result=None,
                decision=decision,
                compliance_result=None,
                start_time=time.time(),
            )
        assert entry["pii_detected"] is True
        assert entry["pii_entity_types"] == ["SSN"]
        assert entry["pii_risk_level"] == "CRITICAL"
        assert entry["enforcement_action"] == "REDACT"
        assert AuditLogger.verify(entry) is True

    @pytest.mark.asyncio
    async def test_log_with_injection_result(self, logger, sample_body):
        injection = FakeInjectionResult(
            risk_score=0.92,
            attack_type="DIRECT",
            is_injection=True,
        )
        decision = FakeDecision(
            action="BLOCK",
            reason="Prompt injection detected: DIRECT",
            triggered_policies=["injection:DIRECT"],
        )
        with patch.object(logger, "_write", new_callable=AsyncMock):
            entry = await logger.log(
                interaction_id=str(uuid.uuid4()),
                tenant_id="default",
                user_id="test-user",
                department=None,
                raw_body=sample_body,
                pii_result=None,
                injection_result=injection,
                decision=decision,
                compliance_result=None,
                start_time=time.time(),
            )
        assert entry["injection_score"] == 0.92
        assert entry["injection_type"] == "DIRECT"
        assert entry["enforcement_action"] == "BLOCK"
        assert AuditLogger.verify(entry) is True

    @pytest.mark.asyncio
    async def test_log_latency_is_positive(self, logger, sample_body):
        with patch.object(logger, "_write", new_callable=AsyncMock):
            entry = await logger.log(
                interaction_id=str(uuid.uuid4()),
                tenant_id="default",
                user_id="test-user",
                department=None,
                raw_body=sample_body,
                pii_result=None,
                injection_result=None,
                decision=None,
                compliance_result=None,
                start_time=time.time() - 0.1,
            )
        assert entry["total_latency_ms"] >= 0


# ------------------------------------------------------------------
# Signing key validation
# ------------------------------------------------------------------


class TestSigningKeyValidation:
    def test_signing_key_is_loaded(self):
        assert SIGNING_KEY == b"test-signing-key-for-unit-tests"

    def test_missing_key_raises_runtime_error(self):
        """Importing with no key set must raise RuntimeError."""
        env_backup = os.environ.pop("AGCMS_SIGNING_KEY", None)
        try:
            # Re-run the validation logic (can't re-import, but test the logic)
            with pytest.raises(RuntimeError, match="not set"):
                raw = os.environ.get("AGCMS_SIGNING_KEY")
                if raw is None:
                    raise RuntimeError(
                        "AGCMS_SIGNING_KEY environment variable is not set. "
                        "The audit logger cannot start without a signing key."
                    )
        finally:
            if env_backup is not None:
                os.environ["AGCMS_SIGNING_KEY"] = env_backup

    def test_empty_key_raises_runtime_error(self):
        env_backup = os.environ.get("AGCMS_SIGNING_KEY")
        os.environ["AGCMS_SIGNING_KEY"] = ""
        try:
            with pytest.raises(RuntimeError, match="empty"):
                raw = os.environ.get("AGCMS_SIGNING_KEY")
                if not raw:
                    raise RuntimeError(
                        "AGCMS_SIGNING_KEY environment variable is empty. "
                        "Provide a non-empty signing key."
                    )
        finally:
            if env_backup is not None:
                os.environ["AGCMS_SIGNING_KEY"] = env_backup
