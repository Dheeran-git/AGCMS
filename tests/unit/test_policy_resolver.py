"""Unit tests for the policy resolver (ESCALATE action) and YAML validator.

Covers:
  - PolicyResolver: ESCALATE on critical PII, ESCALATE on high-severity injection
  - PolicyResolver: existing ALLOW / BLOCK / REDACT paths still work
  - PolicyValidator: valid config passes, invalid configs produce specific errors
"""

import os

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from agcms.policy.models import EnforcementDecision  # noqa: E402
from agcms.policy.resolver import PolicyResolver  # noqa: E402
from agcms.policy.validator import validate_policy  # noqa: E402


# ==================================================================
# Helpers
# ==================================================================

def _resolver(policy: dict | None = None) -> PolicyResolver:
    """Return a PolicyResolver with no default policy file loaded."""
    r = PolicyResolver.__new__(PolicyResolver)
    r._default_policy = policy or {}
    return r


def _pii(risk_level: str = "NONE", has_pii: bool = False) -> dict:
    return {
        "has_pii": has_pii,
        "risk_level": risk_level,
        "entity_types": [],
        "entities": [],
    }


def _injection(score: float = 0.0, attack_type: str = "DIRECT") -> dict:
    return {
        "risk_score": score,
        "attack_type": attack_type,
        "is_injection": score >= 0.65,
    }


# ==================================================================
# 1. PolicyResolver — ALLOW path
# ==================================================================


class TestResolverAllow:
    def test_no_results_returns_allow(self):
        r = _resolver()
        d = r.resolve(pii_result=None, injection_result=None)
        assert d.action == "ALLOW"

    def test_low_injection_score_allows(self):
        r = _resolver()
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.3))
        assert d.action == "ALLOW"

    def test_low_pii_risk_allows(self):
        r = _resolver()
        d = r.resolve(pii_result=_pii("LOW", has_pii=True), injection_result=None)
        assert d.action == "ALLOW"


# ==================================================================
# 2. PolicyResolver — BLOCK path
# ==================================================================


class TestResolverBlock:
    def test_injection_above_threshold_blocks(self):
        r = _resolver()
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.8))
        assert d.action == "BLOCK"
        assert "injection" in d.triggered_policies

    def test_critical_pii_blocks_by_default(self):
        r = _resolver()
        d = r.resolve(pii_result=_pii("CRITICAL", has_pii=True), injection_result=None)
        assert d.action == "BLOCK"
        assert "pii_critical" in d.triggered_policies

    def test_injection_disabled_allows(self):
        policy = {"injection": {"enabled": False}}
        r = _resolver(policy)
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.99))
        assert d.action == "ALLOW"

    def test_custom_block_threshold(self):
        policy = {"injection": {"enabled": True, "block_threshold": 0.9}}
        r = _resolver(policy)
        # 0.8 is below custom threshold → ALLOW
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.8))
        assert d.action == "ALLOW"
        # 0.95 is above → BLOCK
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.95))
        assert d.action == "BLOCK"


# ==================================================================
# 3. PolicyResolver — REDACT path
# ==================================================================


class TestResolverRedact:
    def test_medium_pii_redacts_by_default(self):
        r = _resolver()
        d = r.resolve(pii_result=_pii("MEDIUM", has_pii=True), injection_result=None)
        assert d.action == "REDACT"
        assert "pii_detected" in d.triggered_policies

    def test_high_pii_redacts_by_default(self):
        r = _resolver()
        d = r.resolve(pii_result=_pii("HIGH", has_pii=True), injection_result=None)
        assert d.action == "REDACT"

    def test_pii_below_risk_threshold_allows(self):
        policy = {"pii": {"enabled": True, "risk_threshold": "HIGH"}}
        r = _resolver(policy)
        # MEDIUM is below HIGH threshold → ALLOW
        d = r.resolve(pii_result=_pii("MEDIUM", has_pii=True), injection_result=None)
        assert d.action == "ALLOW"


# ==================================================================
# 4. PolicyResolver — ESCALATE path (new in Step 7)
# ==================================================================


class TestResolverEscalate:
    def test_critical_pii_escalates_when_configured(self):
        policy = {"pii": {"enabled": True, "critical_action": "ESCALATE"}}
        r = _resolver(policy)
        d = r.resolve(pii_result=_pii("CRITICAL", has_pii=True), injection_result=None)
        assert d.action == "ESCALATE"
        assert "pii_critical" in d.triggered_policies
        assert "CRITICAL" in (d.reason or "")

    def test_injection_escalates_above_escalate_threshold(self):
        policy = {
            "injection": {
                "enabled": True,
                "block_threshold": 0.65,
                "escalate_threshold": 0.90,
            }
        }
        r = _resolver(policy)
        # Score 0.95 >= 0.65 (block) and >= 0.90 (escalate) → ESCALATE
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.95))
        assert d.action == "ESCALATE"
        assert "injection" in d.triggered_policies

    def test_injection_blocks_when_below_escalate_threshold(self):
        policy = {
            "injection": {
                "enabled": True,
                "block_threshold": 0.65,
                "escalate_threshold": 0.90,
            }
        }
        r = _resolver(policy)
        # Score 0.75 >= 0.65 (block) but < 0.90 (escalate) → BLOCK
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.75))
        assert d.action == "BLOCK"

    def test_no_escalate_threshold_falls_back_to_block(self):
        """Without escalate_threshold, high injection score should BLOCK (default)."""
        r = _resolver()
        d = r.resolve(pii_result=None, injection_result=_injection(score=0.99))
        assert d.action == "BLOCK"

    def test_escalate_reason_contains_attack_type(self):
        policy = {
            "injection": {
                "enabled": True,
                "block_threshold": 0.65,
                "escalate_threshold": 0.85,
            }
        }
        r = _resolver(policy)
        d = r.resolve(
            pii_result=None,
            injection_result=_injection(score=0.9, attack_type="JAILBREAK"),
        )
        assert d.action == "ESCALATE"
        assert "JAILBREAK" in (d.reason or "")

    def test_injection_takes_priority_over_pii_escalate(self):
        """Injection rule fires first, even if PII would also escalate."""
        policy = {
            "pii": {"enabled": True, "critical_action": "ESCALATE"},
            "injection": {
                "enabled": True,
                "block_threshold": 0.65,
                "escalate_threshold": 0.85,
            },
        }
        r = _resolver(policy)
        d = r.resolve(
            pii_result=_pii("CRITICAL", has_pii=True),
            injection_result=_injection(score=0.95),
        )
        assert d.action == "ESCALATE"
        assert "injection" in d.triggered_policies


# ==================================================================
# 5. Validator — valid configs
# ==================================================================


class TestValidatorValid:
    def test_minimal_valid_config(self):
        config = {
            "pii": {"enabled": True},
            "injection": {"enabled": True, "block_threshold": 0.65},
        }
        assert validate_policy(config) == []

    def test_full_valid_config(self):
        config = {
            "pii": {
                "enabled": True,
                "action_on_detection": "REDACT",
                "critical_action": "BLOCK",
                "risk_threshold": "MEDIUM",
                "custom_patterns": {},
            },
            "injection": {
                "enabled": True,
                "block_threshold": 0.65,
                "escalate_threshold": 0.90,
                "log_all_attempts": True,
            },
            "response_compliance": {
                "enabled": True,
                "restricted_topics": ["violence"],
                "action_on_violation": "REDACT",
            },
            "rate_limits": {
                "requests_per_minute": 60,
                "requests_per_day": 10000,
            },
        }
        assert validate_policy(config) == []

    def test_escalate_action_valid(self):
        config = {
            "pii": {"enabled": True, "critical_action": "ESCALATE"},
            "injection": {"enabled": True},
        }
        assert validate_policy(config) == []


# ==================================================================
# 6. Validator — invalid configs
# ==================================================================


class TestValidatorInvalid:
    def test_not_a_dict_returns_error(self):
        errors = validate_policy("just a string")
        assert any("must be a JSON object" in e for e in errors)

    def test_missing_pii_section(self):
        errors = validate_policy({"injection": {"enabled": True}})
        assert any("pii" in e for e in errors)

    def test_missing_injection_section(self):
        errors = validate_policy({"pii": {"enabled": True}})
        assert any("injection" in e for e in errors)

    def test_invalid_pii_action(self):
        config = {
            "pii": {"enabled": True, "action_on_detection": "EXPLODE"},
            "injection": {"enabled": True},
        }
        errors = validate_policy(config)
        assert any("action_on_detection" in e for e in errors)

    def test_invalid_critical_action(self):
        config = {
            "pii": {"enabled": True, "critical_action": "IGNORE"},
            "injection": {"enabled": True},
        }
        errors = validate_policy(config)
        assert any("critical_action" in e for e in errors)

    def test_invalid_risk_threshold(self):
        config = {
            "pii": {"enabled": True, "risk_threshold": "ULTRA"},
            "injection": {"enabled": True},
        }
        errors = validate_policy(config)
        assert any("risk_threshold" in e for e in errors)

    def test_block_threshold_out_of_range(self):
        config = {
            "pii": {"enabled": True},
            "injection": {"enabled": True, "block_threshold": 1.5},
        }
        errors = validate_policy(config)
        assert any("block_threshold" in e for e in errors)

    def test_escalate_threshold_below_block_threshold(self):
        config = {
            "pii": {"enabled": True},
            "injection": {
                "enabled": True,
                "block_threshold": 0.80,
                "escalate_threshold": 0.60,  # below block_threshold
            },
        }
        errors = validate_policy(config)
        assert any("escalate_threshold" in e for e in errors)

    def test_rate_limits_rpd_less_than_rpm(self):
        config = {
            "pii": {"enabled": True},
            "injection": {"enabled": True},
            "rate_limits": {
                "requests_per_minute": 100,
                "requests_per_day": 50,  # less than per-minute
            },
        }
        errors = validate_policy(config)
        assert any("requests_per_day" in e for e in errors)

    def test_multiple_errors_reported(self):
        config = {
            "pii": {"action_on_detection": "EXPLODE", "critical_action": "IGNORE"},
            "injection": {"block_threshold": -0.5},
        }
        errors = validate_policy(config)
        assert len(errors) >= 3

    def test_response_compliance_bad_action(self):
        config = {
            "pii": {"enabled": True},
            "injection": {"enabled": True},
            "response_compliance": {"action_on_violation": "NOOP"},
        }
        errors = validate_policy(config)
        assert any("action_on_violation" in e for e in errors)

    def test_restricted_topics_not_list(self):
        config = {
            "pii": {"enabled": True},
            "injection": {"enabled": True},
            "response_compliance": {"restricted_topics": "violence"},
        }
        errors = validate_policy(config)
        assert any("restricted_topics" in e for e in errors)
