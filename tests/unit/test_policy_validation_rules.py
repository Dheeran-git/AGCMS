"""Policy rules that keep a stored policy from breaking or blanket-blocking its tenant."""

import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from jose import jwt

from agcms.policy.validator import validate_policy
from agcms.response.agent import ResponseComplianceAgent


def _policy(**sections):
    return {"pii": {}, "injection": {}, **sections}


@pytest.mark.parametrize("patterns, fragment", [
    ({"EMP": "EMP-("}, "not a valid regex"),
    ({"ANY": ".*"}, "empty string"),
    ({"EMP": 5}, "regex string"),
    ("EMP-\d+", "must be an object"),
])
def test_bad_custom_patterns_are_rejected(patterns, fragment):
    errors = validate_policy(_policy(pii={"custom_patterns": patterns}))
    assert any(fragment in e for e in errors), errors


def test_good_custom_pattern_is_accepted():
    assert validate_policy(_policy(pii={"custom_patterns": {"EMP": r"EMP-\d{4}"}})) == []


@pytest.mark.parametrize("key", ["restricted_topics", "system_prompt_keywords"])
def test_blank_topic_or_keyword_is_rejected(key):
    errors = validate_policy(_policy(response_compliance={key: ["titan", " "]}))
    assert errors == [f"response_compliance.{key} must contain only non-empty strings"]


def test_null_section_is_rejected():
    assert validate_policy({"pii": None, "injection": {}}) == ["'pii' must be an object"]


@pytest.mark.parametrize("section", [
    {"injection": {"block_threshold": True}},
    {"rate_limits": {"requests_per_minute": True}},
])
def test_booleans_are_not_numbers(section):
    assert validate_policy(_policy(**section))


def test_disabled_response_compliance_reports_nothing():
    policy = {"response_compliance": {"enabled": False, "restricted_topics": ["titan"]}}
    result = ResponseComplianceAgent().check("Titan ships soon.", policy=policy)
    assert not result.violated


class FakeClient:
    reply: dict = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json):
        return httpx.Response(200, json=FakeClient.reply, request=httpx.Request("POST", url))


def _put_policy(monkeypatch, reply):
    from agcms.gateway.api import policy
    from agcms.gateway.main import app

    FakeClient.reply = reply
    monkeypatch.setattr(policy.httpx, "AsyncClient", FakeClient)
    now = datetime.now(timezone.utc)
    token = jwt.encode({"sub": "acme", "user_id": "u", "role": "admin", "type": "access",
                        "iat": now, "exp": now + timedelta(minutes=5)},
                       os.environ["JWT_SECRET_KEY"], algorithm="HS256")
    return TestClient(app).put("/api/v1/policy", json={"config": {"pii": None}},
                               headers={"Authorization": f"Bearer {token}"})


def test_put_policy_rejects_invalid_config_before_saving(monkeypatch):
    resp = _put_policy(monkeypatch, {"valid": False, "errors": ["'pii' must be an object"]})
    assert resp.status_code == 422
    assert "'pii' must be an object" in resp.json()["detail"]
