"""Multi-LLM provider router with ordered failover.

Providers, in default failover order (all usable on a free tier):
  gemini      generativelanguage.googleapis.com   GEMINI_API_KEY
  groq        api.groq.com                        GROQ_API_KEY
  openrouter  openrouter.ai                       OPENROUTER_API_KEY
  ollama      local, no key                       OLLAMA_URL

Selection: the request's ``provider`` field, else AGCMS_DEFAULT_PROVIDER,
else the first provider in AGCMS_PROVIDER_ORDER. When AGCMS_FAILOVER is on
(default), a provider-side failure (missing key, unreachable, timeout, any
non-200) moves to the next provider in the order; a ``model`` override is
sent only to the first provider tried, since model names are provider
specific. The governance decision is already made before this module runs,
so failover never changes what was scanned or redacted.

Every result carries ``agcms_routing``: the provider and model that
answered, and one entry per failed attempt. Callers strip it before
returning the OpenAI-format body and record it in the audit row.
"""

import os
from dataclasses import dataclass
from typing import Optional

import httpx

_ROUTING_KEY = "agcms_routing"


@dataclass(frozen=True)
class _ProviderConfig:
    env_var: Optional[str]   # env var holding the API key; None = no key needed
    endpoint: str
    default_model: str
    timeout: float = 60.0


def _ollama_endpoint() -> str:
    """Read Ollama URL at call time so OLLAMA_URL overrides work after import."""
    return os.environ.get("OLLAMA_URL", "http://ollama:11434") + "/v1/chat/completions"


_PROVIDERS: dict[str, _ProviderConfig] = {
    "gemini": _ProviderConfig(
        env_var="GEMINI_API_KEY",
        endpoint="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        default_model="gemini-3.8-flash",       # stable Flash model, AI Studio free tier
    ),
    "groq": _ProviderConfig(
        env_var="GROQ_API_KEY",
        endpoint="https://api.groq.com/openai/v1/chat/completions",
        default_model="openai/gpt-oss-120b",    # strongest model on Groq's free tier
    ),
    "openrouter": _ProviderConfig(
        env_var="OPENROUTER_API_KEY",
        endpoint="https://openrouter.ai/api/v1/chat/completions",
        # Newest general-purpose free model on OpenRouter as of 2026-09
        # (550B MoE, 1M context). Free models still need an OpenRouter key.
        default_model="nvidia/nemotron-3-ultra-550b-a55b:free",
    ),
    "ollama": _ProviderConfig(
        env_var=None,
        endpoint="",                            # resolved at call time
        default_model="llama3.2:3b",
        timeout=90.0,                           # first call loads the model
    ),
}


def provider_order() -> list[str]:
    """Failover order from AGCMS_PROVIDER_ORDER, unknown names dropped."""
    raw = os.environ.get("AGCMS_PROVIDER_ORDER", "gemini,groq,openrouter,ollama")
    order = [p.strip().lower() for p in raw.split(",") if p.strip().lower() in _PROVIDERS]
    return order or list(_PROVIDERS)


def default_provider() -> str:
    return os.environ.get("AGCMS_DEFAULT_PROVIDER", "").lower() or provider_order()[0]


def _failover_enabled() -> bool:
    return os.environ.get("AGCMS_FAILOVER", "true").lower() not in ("0", "false", "no", "off")


async def _call_provider(
    name: str, messages: list, model: Optional[str],
    temperature: Optional[float], max_tokens: Optional[int],
) -> dict:
    """One attempt against one provider. Returns the response or an error dict."""
    cfg = _PROVIDERS[name]
    endpoint = _ollama_endpoint() if name == "ollama" else cfg.endpoint

    api_key = None
    if cfg.env_var:
        api_key = os.environ.get(cfg.env_var, "")
        if not api_key:
            return {"error": "provider_unavailable",
                    "reason": f"Provider '{name}' requires {cfg.env_var} to be set. Add it to your .env file."}

    payload: dict = {"model": model or cfg.default_model, "messages": messages}
    if temperature is not None:
        payload["temperature"] = temperature
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        async with httpx.AsyncClient(timeout=cfg.timeout) as client:
            resp = await client.post(endpoint, json=payload, headers=headers)
    except httpx.ConnectError as exc:
        return {"error": "provider_unreachable",
                "reason": f"Could not connect to '{name}' at {endpoint}: {exc}"}
    except httpx.TimeoutException:
        return {"error": "provider_timeout",
                "reason": f"Provider '{name}' timed out after {cfg.timeout:.0f} seconds."}

    if resp.status_code != 200:
        return {"error": "llm_error", "reason": f"{name} returned {resp.status_code}: {resp.text[:300]}"}
    body = resp.json()
    body[_ROUTING_KEY] = {"provider": name, "model": payload["model"], "attempts": []}
    return body


async def forward_to_llm(
    messages: list,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    provider: Optional[str] = None,
) -> dict:
    """Forward a chat completion, failing over along ``provider_order()``.

    Returns an OpenAI-format response plus ``agcms_routing`` on success, or
    an error dict (with ``agcms_routing.attempts`` listing every failure).
    """
    first = (provider or default_provider()).lower()
    if first not in _PROVIDERS:
        return {"error": "provider_unknown",
                "reason": f"Unknown provider '{first}'. Supported: {', '.join(_PROVIDERS)}"}

    order = provider_order()
    chain = [first]
    if _failover_enabled():
        start = order.index(first) + 1 if first in order else 0
        chain += [p for p in order[start:] if p != first]

    attempts = []
    for i, name in enumerate(chain):
        result = await _call_provider(name, messages, model if i == 0 else None, temperature, max_tokens)
        if "error" not in result:
            result[_ROUTING_KEY]["attempts"] = attempts
            return result
        attempts.append({"provider": name, "error": result["error"], "reason": result["reason"]})

    last = attempts[-1]
    return {"error": last["error"], "reason": last["reason"],
            _ROUTING_KEY: {"provider": None, "model": None, "attempts": attempts}}


def pop_routing(llm_response: dict) -> dict:
    """Remove and return the routing record (empty dict if absent)."""
    return llm_response.pop(_ROUTING_KEY, {}) or {}


def list_providers() -> list[dict]:
    """Providers in failover order with key-configured status."""
    result = []
    for name in provider_order():
        cfg = _PROVIDERS[name]
        if cfg.env_var is None:
            available, note = True, "Local Ollama, no API key required"
        else:
            available = bool(os.environ.get(cfg.env_var, ""))
            note = "Configured" if available else f"Set {cfg.env_var} to enable"
        result.append({"provider": name, "default_model": cfg.default_model,
                       "available": available, "note": note})
    return result
