"""Multi-LLM Provider Router — routes sanitized prompts to the selected provider.

Supported providers (all free-tier):
  groq    — api.groq.com (default)                  — set GROQ_API_KEY
  gemini  — generativelanguage.googleapis.com        — set GEMINI_API_KEY (free AI Studio tier)
  mistral — api.mistral.ai                           — set MISTRAL_API_KEY (free La Plateforme tier)
  ollama  — local self-hosted                        — set OLLAMA_URL (no API key required)

Provider selection precedence:
  1. 'provider' field in the request body
  2. AGCMS_DEFAULT_PROVIDER env var
  3. 'groq' (hardcoded fallback)

All providers speak OpenAI-compatible format (Bearer auth + /v1/chat/completions),
so no per-provider request transformation is needed.

If a provider's API key env var is empty/missing, the router returns a structured
error dict instead of crashing — the gateway renders this as a 502.
"""

import os
from dataclasses import dataclass
from typing import Optional

import httpx

# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProviderConfig:
    """Static configuration for a single LLM provider."""
    env_var: Optional[str]   # env var holding the API key; None = no key needed
    endpoint: str
    default_model: str


def _ollama_endpoint() -> str:
    """Read Ollama URL at call time so OLLAMA_URL overrides work after import."""
    return os.environ.get("OLLAMA_URL", "http://ollama:11434") + "/v1/chat/completions"


_PROVIDERS: dict[str, _ProviderConfig] = {
    "groq": _ProviderConfig(
        env_var="GROQ_API_KEY",
        endpoint="https://api.groq.com/openai/v1/chat/completions",
        default_model="llama-3.3-70b-versatile",
    ),
    "gemini": _ProviderConfig(
        env_var="GEMINI_API_KEY",
        endpoint="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        default_model="gemini-2.5-flash",
    ),
    "mistral": _ProviderConfig(
        env_var="MISTRAL_API_KEY",
        endpoint="https://api.mistral.ai/v1/chat/completions",
        default_model="mistral-small-latest",
    ),
    "ollama": _ProviderConfig(
        env_var=None,                  # no API key required
        endpoint="",                   # resolved at runtime via _ollama_endpoint()
        default_model="llama3.2:3b",
    ),
}

_DEFAULT_PROVIDER = os.environ.get("AGCMS_DEFAULT_PROVIDER", "groq")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def forward_to_llm(
    messages: list,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    provider: Optional[str] = None,
) -> dict:
    """Forward a chat completion request to the selected LLM provider.

    Args:
        messages:    OpenAI-format messages list.
        model:       Model override (uses provider default if omitted).
        temperature: Sampling temperature.
        max_tokens:  Max tokens in response.
        provider:    Provider name ('groq', 'mistral', 'together', 'ollama').
                     Defaults to AGCMS_DEFAULT_PROVIDER env var, then 'groq'.

    Returns:
        OpenAI-compatible response dict on success, or an error dict on failure.
    """
    provider_name = (provider or _DEFAULT_PROVIDER).lower()

    if provider_name not in _PROVIDERS:
        return {
            "error": "provider_unknown",
            "reason": (
                f"Unknown provider '{provider_name}'. "
                f"Supported: {', '.join(_PROVIDERS)}"
            ),
        }

    cfg = _PROVIDERS[provider_name]

    # Resolve endpoint (Ollama reads URL at call time)
    endpoint = _ollama_endpoint() if provider_name == "ollama" else cfg.endpoint

    # Resolve API key
    api_key: Optional[str] = None
    if cfg.env_var:
        api_key = os.environ.get(cfg.env_var, "")
        if not api_key:
            return {
                "error": "provider_unavailable",
                "reason": (
                    f"Provider '{provider_name}' requires {cfg.env_var} "
                    "to be set. Add it to your .env file."
                ),
            }

    payload: dict = {
        "model": model or cfg.default_model,
        "messages": messages,
    }
    if temperature is not None:
        payload["temperature"] = temperature
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # Ollama is local — first request loads the model (~60s); use a longer timeout
    timeout = 90.0 if provider_name == "ollama" else 30.0

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(endpoint, json=payload, headers=headers)
    except httpx.ConnectError as exc:
        return {
            "error": "provider_unreachable",
            "reason": f"Could not connect to '{provider_name}' at {endpoint}: {exc}",
        }
    except httpx.TimeoutException:
        return {
            "error": "provider_timeout",
            "reason": f"Provider '{provider_name}' timed out after 30 seconds.",
        }

    if resp.status_code != 200:
        return {
            "error": "llm_error",
            "reason": f"{provider_name} returned {resp.status_code}: {resp.text[:300]}",
        }

    return resp.json()


def list_providers() -> list[dict]:
    """Return available providers and whether their API key is configured."""
    result = []
    for name, cfg in _PROVIDERS.items():
        if cfg.env_var is None:
            # Ollama — available if the host is reachable (we optimistically say yes)
            available = True
            note = "Local Ollama — no API key required"
        else:
            key = os.environ.get(cfg.env_var, "")
            available = bool(key)
            note = f"Set {cfg.env_var} to enable" if not available else "Configured"
        result.append({
            "provider": name,
            "default_model": cfg.default_model,
            "available": available,
            "note": note,
        })
    return result
