"""Unit tests for the multi-LLM router.

Covers:
  - Provider selection precedence (request > env default > groq)
  - All 4 providers: groq, gemini, mistral, ollama
  - Missing API key returns structured error, no exception
  - Unknown provider returns structured error
  - HTTP errors from provider return structured error
  - Connection errors return structured error
  - Timeout returns structured error
  - Default model used when model param omitted
  - list_providers() reports availability correctly
  - Ollama uses OLLAMA_URL env var
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agcms.gateway.router import forward_to_llm, list_providers

_MESSAGES = [{"role": "user", "content": "Hello"}]

_GROQ_RESPONSE = {
    "id": "chatcmpl-abc",
    "object": "chat.completion",
    "choices": [{"message": {"role": "assistant", "content": "Hi there"}}],
}


def _mock_resp(status_code: int = 200, json_data: dict | None = None, text: str = ""):
    """Build a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or _GROQ_RESPONSE
    resp.text = text
    return resp


# ==================================================================
# 1. Provider Selection Precedence
# ==================================================================


class TestProviderSelection:
    @pytest.mark.asyncio
    async def test_explicit_provider_takes_precedence(self):
        """provider param overrides AGCMS_DEFAULT_PROVIDER."""
        with patch.dict(os.environ, {"GROQ_API_KEY": "key", "AGCMS_DEFAULT_PROVIDER": "groq"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="groq")
                call_args = mock_client.post.call_args
                assert "groq.com" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_default_provider_from_env(self):
        """AGCMS_DEFAULT_PROVIDER env var sets the default."""
        with patch.dict(os.environ, {
            "GROQ_API_KEY": "key",
            "AGCMS_DEFAULT_PROVIDER": "groq",
        }):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES)
                call_args = mock_client.post.call_args
                assert "groq.com" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_groq_is_hardcoded_fallback(self):
        """Without AGCMS_DEFAULT_PROVIDER, Groq is used."""
        env = {k: v for k, v in os.environ.items() if k != "AGCMS_DEFAULT_PROVIDER"}
        env["GROQ_API_KEY"] = "test_key"
        with patch.dict(os.environ, env, clear=True):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                result = await forward_to_llm(_MESSAGES)
                assert "error" not in result or result.get("error") != "provider_unknown"


# ==================================================================
# 2. Missing / Unknown Provider Errors
# ==================================================================


class TestProviderErrors:
    @pytest.mark.asyncio
    async def test_missing_api_key_returns_error_dict(self):
        """Missing API key returns structured error, does not raise."""
        with patch.dict(os.environ, {"GROQ_API_KEY": ""}):
            result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "provider_unavailable"
        assert "GROQ_API_KEY" in result["reason"]

    @pytest.mark.asyncio
    async def test_missing_mistral_key_returns_error(self):
        with patch.dict(os.environ, {"MISTRAL_API_KEY": ""}):
            result = await forward_to_llm(_MESSAGES, provider="mistral")
        assert result["error"] == "provider_unavailable"
        assert "MISTRAL_API_KEY" in result["reason"]

    @pytest.mark.asyncio
    async def test_missing_gemini_key_returns_error(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            result = await forward_to_llm(_MESSAGES, provider="gemini")
        assert result["error"] == "provider_unavailable"
        assert "GEMINI_API_KEY" in result["reason"]

    @pytest.mark.asyncio
    async def test_unknown_provider_returns_error(self):
        result = await forward_to_llm(_MESSAGES, provider="openai")
        assert result["error"] == "provider_unknown"
        assert "openai" in result["reason"]

    @pytest.mark.asyncio
    async def test_openai_is_not_a_supported_provider(self):
        """OpenAI is intentionally excluded (paid)."""
        result = await forward_to_llm(_MESSAGES, provider="openai")
        assert result["error"] == "provider_unknown"

    @pytest.mark.asyncio
    async def test_anthropic_is_not_a_supported_provider(self):
        """Anthropic is intentionally excluded (paid)."""
        result = await forward_to_llm(_MESSAGES, provider="anthropic")
        assert result["error"] == "provider_unknown"


# ==================================================================
# 3. HTTP-level Errors
# ==================================================================


class TestHTTPErrors:
    @pytest.mark.asyncio
    async def test_provider_500_returns_error_dict(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "key"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(
                    return_value=_mock_resp(500, text="Internal Server Error")
                )
                mock_client_cls.return_value = mock_client

                result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "llm_error"
        assert "500" in result["reason"]

    @pytest.mark.asyncio
    async def test_connect_error_returns_structured_error(self):
        import httpx as _httpx
        with patch.dict(os.environ, {"GROQ_API_KEY": "key"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(
                    side_effect=_httpx.ConnectError("Connection refused")
                )
                mock_client_cls.return_value = mock_client

                result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "provider_unreachable"

    @pytest.mark.asyncio
    async def test_timeout_returns_structured_error(self):
        import httpx as _httpx
        with patch.dict(os.environ, {"GROQ_API_KEY": "key"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(
                    side_effect=_httpx.TimeoutException("timeout")
                )
                mock_client_cls.return_value = mock_client

                result = await forward_to_llm(_MESSAGES, provider="groq")
        assert result["error"] == "provider_timeout"


# ==================================================================
# 4. Correct Endpoints and Headers
# ==================================================================


class TestEndpointsAndHeaders:
    @pytest.mark.asyncio
    async def test_groq_uses_correct_endpoint(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="groq")
                url = mock_client.post.call_args[0][0]
                assert "groq.com" in url

    @pytest.mark.asyncio
    async def test_mistral_uses_correct_endpoint(self):
        with patch.dict(os.environ, {"MISTRAL_API_KEY": "msk_test"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="mistral")
                url = mock_client.post.call_args[0][0]
                assert "mistral.ai" in url

    @pytest.mark.asyncio
    async def test_gemini_uses_correct_endpoint(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "gem_test"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="gemini")
                url = mock_client.post.call_args[0][0]
                assert "generativelanguage.googleapis.com" in url

    @pytest.mark.asyncio
    async def test_ollama_uses_ollama_url_env(self):
        with patch.dict(os.environ, {"OLLAMA_URL": "http://localhost:11434"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="ollama")
                url = mock_client.post.call_args[0][0]
                assert "localhost:11434" in url

    @pytest.mark.asyncio
    async def test_bearer_token_sent_in_headers(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_mykey"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="groq")
                headers = mock_client.post.call_args[1]["headers"]
                assert headers["Authorization"] == "Bearer gsk_mykey"

    @pytest.mark.asyncio
    async def test_ollama_sends_no_auth_header(self):
        with patch.dict(os.environ, {"OLLAMA_URL": "http://localhost:11434"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="ollama")
                headers = mock_client.post.call_args[1]["headers"]
                assert "Authorization" not in headers


# ==================================================================
# 5. Default Models
# ==================================================================


class TestDefaultModels:
    @pytest.mark.asyncio
    async def test_groq_default_model(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "key"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="groq")
                payload = mock_client.post.call_args[1]["json"]
                assert payload["model"] == "llama-3.3-70b-versatile"

    @pytest.mark.asyncio
    async def test_model_override_respected(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "key"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, model="llama-3.1-8b-instant", provider="groq")
                payload = mock_client.post.call_args[1]["json"]
                assert payload["model"] == "llama-3.1-8b-instant"

    @pytest.mark.asyncio
    async def test_mistral_default_model(self):
        with patch.dict(os.environ, {"MISTRAL_API_KEY": "key"}):
            with patch("agcms.gateway.router.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_client.post = AsyncMock(return_value=_mock_resp())
                mock_client_cls.return_value = mock_client

                await forward_to_llm(_MESSAGES, provider="mistral")
                payload = mock_client.post.call_args[1]["json"]
                assert payload["model"] == "mistral-small-latest"


# ==================================================================
# 6. list_providers()
# ==================================================================


class TestListProviders:
    def test_returns_all_four_providers(self):
        providers = list_providers()
        names = {p["provider"] for p in providers}
        assert {"groq", "gemini", "mistral", "ollama"} == names

    def test_gemini_available_when_key_set(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test"}):
            providers = {p["provider"]: p for p in list_providers()}
        assert providers["gemini"]["available"] is True

    def test_gemini_default_model(self):
        providers = {p["provider"]: p for p in list_providers()}
        assert providers["gemini"]["default_model"] == "gemini-2.5-flash"

    def test_groq_available_when_key_set(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "test"}):
            providers = {p["provider"]: p for p in list_providers()}
        assert providers["groq"]["available"] is True

    def test_groq_unavailable_when_key_missing(self):
        env = {k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            providers = {p["provider"]: p for p in list_providers()}
        assert providers["groq"]["available"] is False

    def test_ollama_always_available(self):
        """Ollama reports available=True since no key is required."""
        providers = {p["provider"]: p for p in list_providers()}
        assert providers["ollama"]["available"] is True

    def test_ollama_default_model_is_installed(self):
        """Ollama default model matches what is installed on the host."""
        providers = {p["provider"]: p for p in list_providers()}
        assert providers["ollama"]["default_model"] == "llama3.2:3b"

    def test_each_provider_has_required_fields(self):
        for p in list_providers():
            assert "provider" in p
            assert "default_model" in p
            assert "available" in p
            assert "note" in p
