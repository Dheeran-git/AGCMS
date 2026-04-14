"""Integration tests for the Policy service (localhost:8004).

Requires: docker compose up (policy service healthy on localhost:8004).

Tests:
  - /resolve endpoint (ALLOW / BLOCK / REDACT / ESCALATE)
  - /validate endpoint (valid configs pass; invalid configs return errors)
"""

import httpx
import pytest

POLICY_URL = "http://localhost:8004"


@pytest.fixture(scope="module")
def policy(request):
    with httpx.Client(base_url=POLICY_URL, timeout=10.0) as c:
        yield c


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class TestPolicyServiceHealth:
    def test_health(self, policy: httpx.Client):
        r = policy.get("/health")
        assert r.status_code == 200
        assert r.json()["service"] == "policy"


# ---------------------------------------------------------------------------
# /resolve — ALLOW
# ---------------------------------------------------------------------------


class TestResolveAllow:
    def test_no_pii_no_injection_allows(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": False, "risk_level": "NONE", "entity_types": [], "entities": []},
            "injection_result": {"risk_score": 0.1, "attack_type": "NONE", "is_injection": False},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"

    def test_null_results_allow(self, policy: httpx.Client):
        r = policy.post("/resolve", json={"pii_result": None, "injection_result": None})
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"

    def test_low_injection_score_allows(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.3, "attack_type": "NONE", "is_injection": False},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"

    def test_low_pii_risk_allows(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "LOW", "entity_types": ["NAME"], "entities": []},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"

    def test_injection_disabled_policy_allows_high_score(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.99, "attack_type": "DIRECT", "is_injection": True},
            "policy": {"injection": {"enabled": False}, "pii": {"enabled": True}},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"

    def test_pii_disabled_policy_allows_critical(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "CRITICAL", "entity_types": ["SSN"], "entities": []},
            "policy": {"pii": {"enabled": False}, "injection": {"enabled": True}},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"


# ---------------------------------------------------------------------------
# /resolve — BLOCK
# ---------------------------------------------------------------------------


class TestResolveBlock:
    def test_injection_above_threshold_blocks(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.9, "attack_type": "DIRECT", "is_injection": True},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "BLOCK"
        assert "injection" in r.json()["triggered_policies"]

    def test_critical_pii_blocks_default(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "CRITICAL", "entity_types": ["SSN"], "entities": []},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "BLOCK"
        assert "pii_critical" in r.json()["triggered_policies"]

    def test_injection_at_threshold_blocks(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.65, "attack_type": "JAILBREAK", "is_injection": True},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "BLOCK"

    def test_custom_block_threshold(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.8, "attack_type": "DIRECT", "is_injection": True},
            "policy": {
                "injection": {"enabled": True, "block_threshold": 0.90},
                "pii": {"enabled": True},
            },
        })
        # 0.8 < 0.90 custom threshold → ALLOW
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"

    def test_block_reason_contains_score(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.85, "attack_type": "DIRECT", "is_injection": True},
        })
        reason = r.json().get("reason", "")
        assert "0.85" in reason

    def test_block_reason_contains_attack_type(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.9, "attack_type": "JAILBREAK", "is_injection": True},
        })
        reason = r.json().get("reason", "")
        assert "JAILBREAK" in reason


# ---------------------------------------------------------------------------
# /resolve — REDACT
# ---------------------------------------------------------------------------


class TestResolveRedact:
    def test_medium_pii_redacts(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "MEDIUM", "entity_types": ["EMAIL"], "entities": []},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "REDACT"

    def test_high_pii_redacts(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "HIGH", "entity_types": ["CREDIT_CARD"], "entities": []},
        })
        assert r.status_code == 200
        assert r.json()["action"] == "REDACT"

    def test_pii_below_threshold_allows(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "MEDIUM", "entity_types": ["EMAIL"], "entities": []},
            "policy": {
                "pii": {"enabled": True, "risk_threshold": "HIGH"},
                "injection": {"enabled": True},
            },
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ALLOW"

    def test_triggered_policies_contains_pii_detected(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "MEDIUM", "entity_types": [], "entities": []},
        })
        assert "pii_detected" in r.json()["triggered_policies"]


# ---------------------------------------------------------------------------
# /resolve — ESCALATE (Step 7)
# ---------------------------------------------------------------------------


class TestResolveEscalate:
    def test_critical_pii_escalates_when_configured(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "CRITICAL", "entity_types": ["SSN"], "entities": []},
            "policy": {
                "pii": {"enabled": True, "critical_action": "ESCALATE"},
                "injection": {"enabled": True},
            },
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ESCALATE"
        assert "pii_critical" in r.json()["triggered_policies"]

    def test_high_injection_escalates_above_escalate_threshold(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.95, "attack_type": "JAILBREAK", "is_injection": True},
            "policy": {
                "pii": {"enabled": True},
                "injection": {
                    "enabled": True,
                    "block_threshold": 0.65,
                    "escalate_threshold": 0.90,
                },
            },
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ESCALATE"

    def test_injection_blocks_when_below_escalate_threshold(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.75, "attack_type": "DIRECT", "is_injection": True},
            "policy": {
                "pii": {"enabled": True},
                "injection": {
                    "enabled": True,
                    "block_threshold": 0.65,
                    "escalate_threshold": 0.90,
                },
            },
        })
        assert r.status_code == 200
        assert r.json()["action"] == "BLOCK"

    def test_escalate_reason_contains_attack_type(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.95, "attack_type": "JAILBREAK", "is_injection": True},
            "policy": {
                "pii": {"enabled": True},
                "injection": {"enabled": True, "block_threshold": 0.65, "escalate_threshold": 0.90},
            },
        })
        assert "JAILBREAK" in r.json().get("reason", "")

    def test_injection_priority_over_pii_escalate(self, policy: httpx.Client):
        """Injection rule fires first even if PII would also escalate."""
        r = policy.post("/resolve", json={
            "pii_result": {"has_pii": True, "risk_level": "CRITICAL", "entity_types": ["SSN"], "entities": []},
            "injection_result": {"risk_score": 0.95, "attack_type": "JAILBREAK", "is_injection": True},
            "policy": {
                "pii": {"enabled": True, "critical_action": "ESCALATE"},
                "injection": {"enabled": True, "block_threshold": 0.65, "escalate_threshold": 0.90},
            },
        })
        assert r.status_code == 200
        assert r.json()["action"] == "ESCALATE"
        assert "injection" in r.json()["triggered_policies"]


# ---------------------------------------------------------------------------
# /resolve — response structure
# ---------------------------------------------------------------------------


class TestResolveResponseShape:
    def test_allow_has_all_fields(self, policy: httpx.Client):
        r = policy.post("/resolve", json={})
        body = r.json()
        assert "action" in body
        assert "reason" in body
        assert "triggered_policies" in body

    def test_block_triggered_policies_is_list(self, policy: httpx.Client):
        r = policy.post("/resolve", json={
            "injection_result": {"risk_score": 0.9, "attack_type": "DIRECT", "is_injection": True},
        })
        assert isinstance(r.json()["triggered_policies"], list)

    def test_allow_triggered_policies_is_empty(self, policy: httpx.Client):
        r = policy.post("/resolve", json={})
        assert r.json()["triggered_policies"] == []

    def test_allow_reason_is_null(self, policy: httpx.Client):
        r = policy.post("/resolve", json={})
        assert r.json()["reason"] is None


# ---------------------------------------------------------------------------
# /validate — valid configs
# ---------------------------------------------------------------------------


class TestValidateValid:
    def test_minimal_config(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True},
                "injection": {"enabled": True},
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is True
        assert r.json()["errors"] == []

    def test_full_config(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {
                    "enabled": True,
                    "action_on_detection": "REDACT",
                    "critical_action": "BLOCK",
                    "risk_threshold": "MEDIUM",
                },
                "injection": {
                    "enabled": True,
                    "block_threshold": 0.65,
                    "escalate_threshold": 0.90,
                    "log_all_attempts": True,
                },
                "response_compliance": {
                    "enabled": True,
                    "restricted_topics": [],
                    "action_on_violation": "REDACT",
                },
                "rate_limits": {
                    "requests_per_minute": 60,
                    "requests_per_day": 10000,
                },
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is True

    def test_escalate_critical_action_valid(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True, "critical_action": "ESCALATE"},
                "injection": {"enabled": True},
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is True

    def test_escalate_threshold_valid(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True},
                "injection": {
                    "enabled": True,
                    "block_threshold": 0.65,
                    "escalate_threshold": 0.90,
                },
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is True


# ---------------------------------------------------------------------------
# /validate — invalid configs
# ---------------------------------------------------------------------------


class TestValidateInvalid:
    def test_not_a_dict(self, policy: httpx.Client):
        r = policy.post("/validate", json={"config": "string value"})
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert len(r.json()["errors"]) > 0

    def test_missing_pii_section(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {"injection": {"enabled": True}}
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert any("pii" in e for e in r.json()["errors"])

    def test_missing_injection_section(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {"pii": {"enabled": True}}
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert any("injection" in e for e in r.json()["errors"])

    def test_invalid_pii_action(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True, "action_on_detection": "EXPLODE"},
                "injection": {"enabled": True},
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert any("action_on_detection" in e for e in r.json()["errors"])

    def test_invalid_critical_action(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True, "critical_action": "IGNORE"},
                "injection": {"enabled": True},
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False

    def test_block_threshold_out_of_range(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True},
                "injection": {"enabled": True, "block_threshold": 1.5},
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert any("block_threshold" in e for e in r.json()["errors"])

    def test_escalate_threshold_below_block_threshold(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True},
                "injection": {
                    "enabled": True,
                    "block_threshold": 0.80,
                    "escalate_threshold": 0.50,
                },
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert any("escalate_threshold" in e for e in r.json()["errors"])

    def test_rate_limits_rpd_less_than_rpm(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True},
                "injection": {"enabled": True},
                "rate_limits": {
                    "requests_per_minute": 100,
                    "requests_per_day": 50,
                },
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False

    def test_errors_field_present_on_invalid(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {"pii": {"action_on_detection": "BAD"}}
        })
        body = r.json()
        assert "valid" in body
        assert "errors" in body
        assert isinstance(body["errors"], list)

    def test_invalid_risk_threshold(self, policy: httpx.Client):
        r = policy.post("/validate", json={
            "config": {
                "pii": {"enabled": True, "risk_threshold": "EXTREME"},
                "injection": {"enabled": True},
            }
        })
        assert r.status_code == 200
        assert r.json()["valid"] is False
