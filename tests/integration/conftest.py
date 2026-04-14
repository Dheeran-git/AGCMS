"""Shared fixtures for the AGCMS integration test suite.

session-scoped ``reset_policy`` autouse fixture ensures the DB policy is set
to the canonical default before any integration test runs.  This prevents
test-order-dependent failures when a previous run left an ESCALATE policy
in the database.
"""

import httpx
import pytest

GATEWAY_URL = "http://localhost:8000"
API_KEY = "agcms_test_key_for_development"

_CANONICAL_POLICY = {
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
        "action_on_detection": "BLOCK",
        "log_all_attempts": True,
    },
    "response_compliance": {
        "enabled": True,
        "restricted_topics": [],
        "system_prompt_keywords": [],
        "action_on_violation": "REDACT",
    },
    "rate_limits": {
        "requests_per_minute": 60,
        "requests_per_day": 10000,
    },
}


@pytest.fixture(scope="session", autouse=True)
def reset_policy_to_default():
    """Ensure the default tenant policy is set to the canonical default before
    the integration suite starts.  Silently skips if gateway is not running."""
    try:
        with httpx.Client(base_url=GATEWAY_URL, timeout=5.0) as c:
            c.put(
                "/api/v1/policy",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "config": _CANONICAL_POLICY,
                    "notes": "reset to default at start of integration suite",
                },
            )
    except Exception:
        pass  # Gateway not running — individual tests will handle their own failures
