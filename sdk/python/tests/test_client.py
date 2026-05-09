"""Tests for AGCMSClient — sync + async happy and error paths."""

from __future__ import annotations

import json

import httpx
import pytest

from agcms import (
    AGCMSClient,
    AsyncAGCMSClient,
    AuthError,
    BlockedError,
    RateLimitedError,
    UpstreamError,
    openai_wrap,
)


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def test_chat_completions_returns_payload_and_captures_interaction_id():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer agc_test"
        body = json.loads(request.content)
        assert body["model"] == "groq:llama-3.3-70b-versatile"
        return httpx.Response(
            200,
            json={"id": "cmpl-1", "choices": [{"message": {"content": "hi"}}]},
            headers={"X-AGCMS-Interaction-ID": "iid-123"},
        )

    client = AGCMSClient(base_url="https://gw.test", api_key="agc_test")
    client._http = httpx.Client(transport=_mock_transport(handler))

    out = client.chat.completions.create(
        model="groq:llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": "hello"}],
    )
    assert out["choices"][0]["message"]["content"] == "hi"
    assert client.last_interaction_id == "iid-123"


def test_blocked_request_raises_blocked_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": "request_blocked",
                "reason": "PII detected",
                "interaction_id": "iid-block",
            },
            headers={"X-AGCMS-Interaction-ID": "iid-block"},
        )

    client = AGCMSClient(base_url="https://gw.test", api_key="agc_test")
    client._http = httpx.Client(transport=_mock_transport(handler))

    with pytest.raises(BlockedError) as exc:
        client.chat.completions.create(model="x", messages=[])
    assert exc.value.interaction_id == "iid-block"
    assert exc.value.status_code == 403


def test_rate_limit_raises_rate_limited_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": "rate_limited", "reason": "too many"})

    client = AGCMSClient(base_url="https://gw.test", api_key="agc_test")
    client._http = httpx.Client(transport=_mock_transport(handler))

    with pytest.raises(RateLimitedError):
        client.chat.completions.create(model="x", messages=[])


def test_auth_failure_raises_auth_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "auth_failed", "reason": "no key"})

    client = AGCMSClient(base_url="https://gw.test", api_key="agc_test")
    client._http = httpx.Client(transport=_mock_transport(handler))

    with pytest.raises(AuthError):
        client.chat.completions.create(model="x", messages=[])


def test_upstream_llm_error_raises_upstream_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, json={"error": "llm_error", "reason": "groq is down"})

    client = AGCMSClient(base_url="https://gw.test", api_key="agc_test")
    client._http = httpx.Client(transport=_mock_transport(handler))

    with pytest.raises(UpstreamError):
        client.chat.completions.create(model="x", messages=[])


def test_openai_shaped_error_payload_does_not_crash_parser():
    # Some upstream proxies / providers return {"error": {"code": "...", "message": "..."}}.
    # The SDK must coerce this safely instead of raising TypeError.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={"error": {"code": "request_blocked", "message": "PII detected"}},
        )

    client = AGCMSClient(base_url="https://gw.test", api_key="agc_test")
    client._http = httpx.Client(transport=_mock_transport(handler))

    with pytest.raises(BlockedError) as exc_info:
        client.chat.completions.create(model="x", messages=[])
    assert "PII detected" in str(exc_info.value)


def test_user_id_and_department_become_request_headers():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["user"] = request.headers.get("X-AGCMS-User-ID")
        seen["dept"] = request.headers.get("X-AGCMS-Department")
        return httpx.Response(200, json={"choices": []})

    client = AGCMSClient(
        base_url="https://gw.test",
        api_key="agc_test",
        user_id="alice@corp",
        department="sec-eng",
    )
    client._http = httpx.Client(transport=_mock_transport(handler))
    client.chat.completions.create(model="x", messages=[])
    assert seen == {"user": "alice@corp", "dept": "sec-eng"}


def test_missing_base_url_raises_value_error():
    with pytest.raises(ValueError):
        AGCMSClient(base_url="", api_key="x")


def test_missing_api_key_raises_value_error():
    with pytest.raises(ValueError):
        AGCMSClient(base_url="https://gw.test", api_key="")


@pytest.mark.asyncio
async def test_async_client_returns_payload():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "async-hi"}}]},
            headers={"X-AGCMS-Interaction-ID": "iid-async"},
        )

    client = AsyncAGCMSClient(base_url="https://gw.test", api_key="agc_test")
    client._http = httpx.AsyncClient(transport=_mock_transport(handler))
    out = await client.chat.completions.create(model="x", messages=[])
    assert out["choices"][0]["message"]["content"] == "async-hi"
    assert client.last_interaction_id == "iid-async"
    await client.aclose()


def test_openai_wrap_routes_chat_through_agcms_but_passes_through_other_attrs():
    class FakeOpenAI:
        embeddings = "embed-namespace-sentinel"
        files = "files-namespace-sentinel"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(200, json={"choices": []},
                              headers={"X-AGCMS-Interaction-ID": "iid-wrap"})

    wrapped = openai_wrap(
        FakeOpenAI(),
        agcms_base_url="https://gw.test",
        agcms_api_key="agc_test",
    )
    wrapped._agcms._http = httpx.Client(transport=_mock_transport(handler))

    wrapped.chat.completions.create(model="x", messages=[])
    assert wrapped.last_interaction_id == "iid-wrap"
    assert wrapped.embeddings == "embed-namespace-sentinel"
    assert wrapped.files == "files-namespace-sentinel"
