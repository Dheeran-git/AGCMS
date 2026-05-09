"""Phase 7.5 — notification dispatcher + provider-adapter tests."""
from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
import os
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-unit-tests")
os.environ.setdefault("DATABASE_URL", "postgresql://agcms:secret@localhost:5433/agcms")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agcms.gateway.auth import AuthContext  # noqa: E402
from agcms.gateway.notifications import (  # noqa: E402
    PROVIDER_KINDS,
    TRIGGER_EVENTS,
    SEVERITIES,
    SEVERITY_RANK,
    _matching_rules,
    _send_with_retries,
    notify,
    router as notifications_router,
    sign_webhook_payload,
    _send_slack,
    _send_pagerduty,
    _send_webhook,
    _send_splunk_hec,
    _redact_config,
)
from agcms.gateway.rbac import get_current_auth  # noqa: E402


TENANT = "t1"
_ADMIN = AuthContext(tenant_id=TENANT, user_id="admin-a", role="admin", auth_method="jwt")
_USER = AuthContext(tenant_id=TENANT, user_id="alice", role="user", auth_method="jwt")


# ============================================================
# Helpers
# ============================================================


class FakeConn:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple]] = []
        self.fetch = AsyncMock(return_value=[])
        self.fetchrow = AsyncMock(return_value=None)
        self.execute = AsyncMock(side_effect=self._execute)
        self.close = AsyncMock(return_value=None)

    async def _execute(self, query, *args):
        self.executed.append((query, args))
        if "DELETE" in query:
            return "DELETE 1"
        return "OK"


def _patch_conn(conn: FakeConn):
    return patch(
        "agcms.gateway.notifications.asyncpg.connect",
        new_callable=AsyncMock,
        return_value=conn,
    )


def _app(ctx: AuthContext) -> FastAPI:
    app = FastAPI()
    app.include_router(notifications_router)
    app.dependency_overrides[get_current_auth] = lambda: ctx
    return app


class _MockResponse:
    def __init__(self, status: int = 200) -> None:
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"status {self.status_code}", request=None, response=None
            )


class _MockAsyncClient:
    def __init__(self, response: _MockResponse) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, content=None, headers=None):
        self.calls.append({"url": url, "json": json, "content": content, "headers": headers})
        return self._response


# ============================================================
# Constants & helpers
# ============================================================


class TestConstants:
    def test_provider_kinds_match_dispatch_table(self):
        from agcms.gateway.notifications import PROVIDER_DISPATCH

        assert set(PROVIDER_DISPATCH.keys()) == set(PROVIDER_KINDS)

    def test_severity_rank_is_total_order(self):
        assert SEVERITY_RANK["info"] < SEVERITY_RANK["warning"] < SEVERITY_RANK["critical"]
        assert set(SEVERITY_RANK) == set(SEVERITIES)


class TestSigning:
    def test_hmac_signature_is_deterministic_and_verifiable(self):
        body = b'{"hello":"world"}'
        sig = sign_webhook_payload("s3cr3t", body)
        expected = hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
        assert sig == expected

        # Receiver-side verification with compare_digest
        assert hmac.compare_digest(sig, expected)

    def test_hmac_changes_when_body_changes(self):
        a = sign_webhook_payload("k", b"a")
        b = sign_webhook_payload("k", b"b")
        assert a != b


class TestRedaction:
    def test_secrets_are_masked_in_listings(self):
        cfg = {
            "url": "https://example.com",
            "signing_secret": "abcdefgh1234",
            "token": "Splunk-XYZ-999",
        }
        red = _redact_config("webhook", cfg)
        assert red["url"] == "https://example.com"
        assert red["signing_secret"].startswith("abcd") and red["signing_secret"].endswith("1234")
        assert "•" in red["signing_secret"]
        assert red["token"] != "Splunk-XYZ-999"


# ============================================================
# Provider adapters (happy path)
# ============================================================


class TestSlackAdapter:
    def test_posts_to_webhook_url_with_text(self):
        resp = _MockResponse(200)
        client = _MockAsyncClient(resp)
        with patch("agcms.gateway.notifications.httpx.AsyncClient", return_value=client):
            asyncio.run(_send_slack(
                {"webhook_url": "https://hooks.slack.com/x"},
                {"event": "violation", "severity": "warning", "summary": "PII"},
            ))
        assert len(client.calls) == 1
        assert client.calls[0]["url"] == "https://hooks.slack.com/x"
        assert "[WARNING]" in client.calls[0]["json"]["text"]
        assert "PII" in client.calls[0]["json"]["text"]

    def test_missing_url_raises(self):
        with pytest.raises(ValueError, match="webhook_url"):
            asyncio.run(_send_slack({}, {"event": "x", "severity": "info"}))


class TestPagerDutyAdapter:
    def test_posts_to_v2_enqueue(self):
        client = _MockAsyncClient(_MockResponse(202))
        with patch("agcms.gateway.notifications.httpx.AsyncClient", return_value=client):
            asyncio.run(_send_pagerduty(
                {"routing_key": "abc"},
                {"event": "audit_chain_break", "severity": "critical", "summary": "tamper"},
            ))
        call = client.calls[0]
        assert call["url"] == "https://events.pagerduty.com/v2/enqueue"
        body = call["json"]
        assert body["routing_key"] == "abc"
        assert body["event_action"] == "trigger"
        assert body["payload"]["severity"] == "critical"


class TestWebhookAdapter:
    def test_signs_payload_with_hmac(self):
        client = _MockAsyncClient(_MockResponse(200))
        secret = "s3cr3t"
        payload = {"event": "violation", "severity": "warning", "summary": "ok"}
        with patch("agcms.gateway.notifications.httpx.AsyncClient", return_value=client):
            asyncio.run(_send_webhook(
                {"url": "https://example.com/hook", "signing_secret": secret},
                payload,
            ))
        call = client.calls[0]
        assert call["url"] == "https://example.com/hook"
        body = call["content"]
        # Signature header matches recomputed HMAC over the exact bytes posted
        assert call["headers"]["X-AGCMS-Signature"] == sign_webhook_payload(secret, body)

    def test_works_without_signing_secret(self):
        client = _MockAsyncClient(_MockResponse(200))
        with patch("agcms.gateway.notifications.httpx.AsyncClient", return_value=client):
            asyncio.run(_send_webhook({"url": "http://x"}, {"event": "x", "severity": "info"}))
        assert "X-AGCMS-Signature" not in client.calls[0]["headers"]


class TestSplunkAdapter:
    def test_posts_with_splunk_token_header(self):
        client = _MockAsyncClient(_MockResponse(200))
        with patch("agcms.gateway.notifications.httpx.AsyncClient", return_value=client):
            asyncio.run(_send_splunk_hec(
                {"url": "https://splunk:8088/services/collector", "token": "TOK"},
                {"event": "violation", "severity": "warning"},
            ))
        call = client.calls[0]
        assert call["headers"]["Authorization"] == "Splunk TOK"
        assert call["json"]["sourcetype"] == "agcms:event"


# ============================================================
# Retry / dispatch
# ============================================================


class TestRetry:
    def test_returns_sent_after_first_success(self):
        called = {"n": 0}

        async def ok(_cfg, _payload):
            called["n"] += 1

        with patch.dict("agcms.gateway.notifications.PROVIDER_DISPATCH", {"slack": ok}):
            status, attempts, err = asyncio.run(_send_with_retries("slack", {}, {}))
        assert status == "sent"
        assert attempts == 1
        assert err is None
        assert called["n"] == 1

    def test_retries_then_fails_after_max_attempts(self):
        async def boom(_cfg, _payload):
            raise RuntimeError("nope")

        with patch.dict("agcms.gateway.notifications.PROVIDER_DISPATCH", {"slack": boom}):
            status, attempts, err = asyncio.run(
                _send_with_retries("slack", {}, {}, max_attempts=3)
            )
        assert status == "failed"
        assert attempts == 3
        assert "RuntimeError" in (err or "")

    def test_unknown_kind_fails_fast(self):
        status, attempts, err = asyncio.run(
            _send_with_retries("nope", {}, {}, max_attempts=5)
        )
        assert status == "failed"
        assert attempts == 1
        assert "unknown" in err.lower()


# ============================================================
# Severity matching
# ============================================================


class TestMatchingRules:
    def test_severity_floor_excludes_lower_events(self):
        # rule.severity_min = 'critical' → only critical events pass
        rule = {"rule_id": "r1", "severity_min": "critical", "provider_id": "p1",
                "kind": "slack", "config": {}}
        conn = FakeConn()
        conn.fetch = AsyncMock(return_value=[rule])

        # info event should NOT match a critical-only rule
        out = asyncio.run(_matching_rules(conn, TENANT, "violation", "info"))
        assert out == []

        # critical event should match
        out = asyncio.run(_matching_rules(conn, TENANT, "violation", "critical"))
        assert len(out) == 1


# ============================================================
# Endpoint tests
# ============================================================


class TestEndpoints:
    def test_list_providers_requires_admin(self):
        client = TestClient(_app(_USER))
        assert client.get("/api/v1/notifications/providers").status_code == 403

    def test_create_provider_validates_kind(self):
        conn = FakeConn()
        with _patch_conn(conn):
            r = TestClient(_app(_ADMIN)).post(
                "/api/v1/notifications/providers",
                json={"kind": "carrier-pigeon", "name": "p", "config": {}},
            )
        assert r.status_code == 400

    def test_create_provider_persists(self):
        conn = FakeConn()
        new_id = uuid.uuid4()
        from datetime import datetime, timezone
        conn.fetchrow = AsyncMock(return_value={
            "id": new_id, "kind": "slack", "name": "ops", "enabled": True,
            "created_at": datetime.now(timezone.utc),
        })
        with _patch_conn(conn):
            r = TestClient(_app(_ADMIN)).post(
                "/api/v1/notifications/providers",
                json={"kind": "slack", "name": "ops",
                      "config": {"webhook_url": "https://x"}},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["kind"] == "slack"
        assert body["id"] == str(new_id)

    def test_create_rule_validates_trigger_and_severity(self):
        client = TestClient(_app(_ADMIN))
        bad_trigger = client.post(
            "/api/v1/notifications/rules",
            json={"provider_id": str(uuid.uuid4()), "trigger_event": "bogus",
                  "severity_min": "info"},
        )
        assert bad_trigger.status_code == 400
        bad_sev = client.post(
            "/api/v1/notifications/rules",
            json={"provider_id": str(uuid.uuid4()), "trigger_event": "violation",
                  "severity_min": "panic"},
        )
        assert bad_sev.status_code == 400


# ============================================================
# Full notify() smoke
# ============================================================


class TestNotifyDispatch:
    def test_notify_with_no_rules_is_a_noop(self):
        conn = FakeConn()  # fetch returns []
        with _patch_conn(conn):
            count = asyncio.run(notify(TENANT, "violation", "warning", "ok"))
        assert count == 0
