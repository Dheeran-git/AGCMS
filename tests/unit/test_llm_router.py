"""Unit tests for the multi-LLM router with failover.

Covers provider selection, the four providers (gemini, groq, openrouter,
ollama), structured errors, endpoints and headers, default models, the
failover chain and the routing record, and list_providers().
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from agcms.gateway.router import (
    default_provider, forward_to_llm, list_providers, pop_routing, provider_order,
)

_MESSAGES = [{"role": "user", "content": "Hello"}]
_OK = {"id": "chatcmpl-abc", "object": "chat.completion",
       "choices": [{"message": {"role": "assistant", "content": "Hi there"}}]}
_ALL_KEYS = {"GEMINI_API_KEY": "g", "GROQ_API_KEY": "q", "OPENROUTER_API_KEY": "o",
             "OLLAMA_URL": "http://localhost:11434"}
_NO_FAILOVER = {"AGCMS_FAILOVER": "false"}


def _resp(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = dict(json_data or _OK)
    resp.text = text
    return resp


def _client(side_effect=None, return_value=None):
    """Patch httpx.AsyncClient; returns the mock whose .post records calls."""
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=side_effect, return_value=return_value or _resp())
    patcher = patch("agcms.gateway.router.httpx.AsyncClient", return_value=mock_client)
    return patcher, mock_client


def _env(extra=None, clear_default=True):
    env = {k: v for k, v in os.environ.items()
           if not (clear_default and k in ("AGCMS_DEFAULT_PROVIDER", "AGCMS_PROVIDER_ORDER", "AGCMS_FAILOVER"))}
    env.update(_ALL_KEYS)
    env.update(extra or {})
    return patch.dict(os.environ, env, clear=True)


class TestProviderSelection:
    def test_default_order_and_default_provider(self):
        with _env():
            assert provider_order() == ["gemini", "groq", "openrouter", "ollama"]
            assert default_provider() == "gemini"

    def test_env_default_provider(self):
        with _env({"AGCMS_DEFAULT_PROVIDER": "groq"}):
            assert default_provider() == "groq"

    def test_custom_order_drops_unknown_names(self):
        with _env({"AGCMS_PROVIDER_ORDER": "ollama, mistral ,groq"}):
            assert provider_order() == ["ollama", "groq"]

    @pytest.mark.asyncio
    async def test_explicit_provider_takes_precedence(self):
        patcher, client = _client()
        with _env(_NO_FAILOVER), patcher:
            await forward_to_llm(_MESSAGES, provider="groq")
        assert "groq.com" in client.post.call_args[0][0]

    @pytest.mark.asyncio
    async def test_default_is_gemini(self):
        patcher, client = _client()
        with _env(_NO_FAILOVER), patcher:
            await forward_to_llm(_MESSAGES)
        assert "generativelanguage.googleapis.com" in client.post.call_args[0][0]


class TestProviderErrors:
    @pytest.mark.asyncio
    async def test_missing_key_without_failover(self):
        with _env({"GROQ_API_KEY": "", **_NO_FAILOVER}):
            result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "provider_unavailable"
        assert "GROQ_API_KEY" in result["reason"]

    @pytest.mark.asyncio
    async def test_unknown_provider(self):
        with _env():
            result = await forward_to_llm(_MESSAGES, provider="openai")
        assert result["error"] == "provider_unknown"

    @pytest.mark.asyncio
    async def test_mistral_no_longer_supported(self):
        with _env():
            result = await forward_to_llm(_MESSAGES, provider="mistral")
        assert result["error"] == "provider_unknown"

    @pytest.mark.asyncio
    async def test_500_without_failover(self):
        patcher, _ = _client(return_value=_resp(500, text="Internal Server Error"))
        with _env(_NO_FAILOVER), patcher:
            result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "llm_error" and "500" in result["reason"]

    @pytest.mark.asyncio
    async def test_connect_error_without_failover(self):
        patcher, _ = _client(side_effect=httpx.ConnectError("refused"))
        with _env(_NO_FAILOVER), patcher:
            result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "provider_unreachable"

    @pytest.mark.asyncio
    async def test_timeout_without_failover(self):
        patcher, _ = _client(side_effect=httpx.TimeoutException("timeout"))
        with _env(_NO_FAILOVER), patcher:
            result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "provider_timeout"


class TestEndpointsAndHeaders:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("name,host", [
        ("gemini", "generativelanguage.googleapis.com"), ("groq", "groq.com"),
        ("openrouter", "openrouter.ai"), ("ollama", "localhost:11434"),
    ])
    async def test_endpoint(self, name, host):
        patcher, client = _client()
        with _env(_NO_FAILOVER), patcher:
            await forward_to_llm(_MESSAGES, provider=name)
        assert host in client.post.call_args[0][0]

    @pytest.mark.asyncio
    async def test_bearer_token_sent(self):
        patcher, client = _client()
        with _env({"GROQ_API_KEY": "gsk_mykey", **_NO_FAILOVER}), patcher:
            await forward_to_llm(_MESSAGES, provider="groq")
        assert client.post.call_args[1]["headers"]["Authorization"] == "Bearer gsk_mykey"

    @pytest.mark.asyncio
    async def test_ollama_sends_no_auth_header(self):
        patcher, client = _client()
        with _env(_NO_FAILOVER), patcher:
            await forward_to_llm(_MESSAGES, provider="ollama")
        assert "Authorization" not in client.post.call_args[1]["headers"]


class TestDefaultModels:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("name,model", [
        ("gemini", "gemini-3.8-flash"), ("groq", "openai/gpt-oss-120b"),
        ("openrouter", "nvidia/nemotron-3-ultra-550b-a55b:free"), ("ollama", "llama3.2:3b"),
    ])
    async def test_default_model(self, name, model):
        patcher, client = _client()
        with _env(_NO_FAILOVER), patcher:
            result = await forward_to_llm(_MESSAGES, provider=name)
        assert client.post.call_args[1]["json"]["model"] == model
        assert result["agcms_routing"] == {"provider": name, "model": model, "attempts": []}

    @pytest.mark.asyncio
    async def test_model_override_respected(self):
        patcher, client = _client()
        with _env(_NO_FAILOVER), patcher:
            await forward_to_llm(_MESSAGES, model="llama-3.1-8b-instant", provider="groq")
        assert client.post.call_args[1]["json"]["model"] == "llama-3.1-8b-instant"


class TestFailover:
    @pytest.mark.asyncio
    async def test_falls_through_to_next_provider(self):
        """Gemini 429 -> Groq answers; routing records the failed attempt."""
        patcher, client = _client(side_effect=[_resp(429, text="quota"), _resp()])
        with _env(), patcher:
            result = await forward_to_llm(_MESSAGES)
        urls = [c[0][0] for c in client.post.call_args_list]
        assert "googleapis" in urls[0] and "groq.com" in urls[1]
        routing = pop_routing(result)
        assert routing["provider"] == "groq"
        assert [a["provider"] for a in routing["attempts"]] == ["gemini"]
        assert "agcms_routing" not in result and "choices" in result

    @pytest.mark.asyncio
    async def test_missing_key_is_skipped_in_chain(self):
        patcher, client = _client()
        with _env({"GEMINI_API_KEY": ""}), patcher:
            result = await forward_to_llm(_MESSAGES)
        assert "groq.com" in client.post.call_args[0][0]
        assert result["agcms_routing"]["attempts"][0]["error"] == "provider_unavailable"

    @pytest.mark.asyncio
    async def test_model_override_only_sent_to_first_provider(self):
        patcher, client = _client(side_effect=[_resp(503), _resp()])
        with _env(), patcher:
            await forward_to_llm(_MESSAGES, model="gemini-3.7-flash")
        models = [c[1]["json"]["model"] for c in client.post.call_args_list]
        assert models == ["gemini-3.7-flash", "openai/gpt-oss-120b"]

    @pytest.mark.asyncio
    async def test_chain_starts_after_requested_provider(self):
        patcher, client = _client(side_effect=[httpx.ConnectError("x"), _resp()])
        with _env(), patcher:
            result = await forward_to_llm(_MESSAGES, provider="openrouter")
        assert "localhost:11434" in client.post.call_args_list[1][0][0]
        assert result["agcms_routing"]["provider"] == "ollama"

    @pytest.mark.asyncio
    async def test_all_fail_returns_last_error_with_attempts(self):
        patcher, _ = _client(side_effect=httpx.TimeoutException("t"))
        with _env(), patcher:
            result = await forward_to_llm(_MESSAGES)
        assert result["error"] == "provider_timeout"
        assert [a["provider"] for a in result["agcms_routing"]["attempts"]] == \
            ["gemini", "groq", "openrouter", "ollama"]

    @pytest.mark.asyncio
    async def test_failover_disabled_stops_at_first(self):
        patcher, client = _client(return_value=_resp(429, text="quota"))
        with _env(_NO_FAILOVER), patcher:
            result = await forward_to_llm(_MESSAGES)
        assert client.post.call_count == 1 and result["error"] == "llm_error"

    def test_pop_routing_on_dict_without_record(self):
        assert pop_routing({"choices": []}) == {}


class TestListProviders:
    def test_returns_four_providers_in_order(self):
        with _env():
            assert [p["provider"] for p in list_providers()] == ["gemini", "groq", "openrouter", "ollama"]

    def test_availability_follows_keys(self):
        with _env({"OPENROUTER_API_KEY": ""}):
            providers = {p["provider"]: p for p in list_providers()}
        assert providers["gemini"]["available"] is True
        assert providers["openrouter"]["available"] is False
        assert providers["ollama"]["available"] is True

    def test_each_provider_has_required_fields(self):
        for p in list_providers():
            assert {"provider", "default_model", "available", "note"} <= set(p)
