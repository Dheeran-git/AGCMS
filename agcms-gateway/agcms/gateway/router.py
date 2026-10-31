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
sent only to the requested provider, since model names are provider
specific. A transient failure (timeout, unreachable, 429, 5xx) also benches
that provider for AGCMS_PROVIDER_COOLDOWN seconds (default 60), so an outage
or an exhausted free-tier quota costs one failed call per cooldown instead
of one per request; when every provider is benched, all are tried anyway.
The governance decision is already made before this module runs, so
failover never changes what was scanned or redacted.

Every result carries ``agcms_routing``: the provider and model that
answered, and one entry per failed attempt. Callers strip it before
returning the OpenAI-format body and record it in the audit row.
"""

import os
import time
from dataclasses import dataclass
from typing import Optional

import httpx

_ROUTING_KEY = "agcms_routing"

# provider name -> monotonic time until which it is skipped
_benched_until: dict[str, float] = {}


@dataclass(frozen=True)
class _ProviderConfig:
    env_var: Optional[str]   # env var holding the API key; None = no key needed
    endpoint: str
    default_model: str
    # Short enough that a hung cloud provider still leaves time to fail over
    # within a typical 60 s client timeout.
    timeout: float = 25.0


def _ollama_endpoint() -> str:
    """Read Ollama URL at call time so OLLAMA_URL overrides work after import."""
    return os.environ.get("OLLAMA_URL", "http://ollama:11434") + "/v1/chat/completions"


_PROVIDERS: dict[str, _ProviderConfig] = {
    "gemini": _ProviderConfig(
        env_var="GEMINI_API_KEY",
        endpoint="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        # Pinned Flash-Lite: gemini-3.8-flash allows only 20 free-tier requests a day.
        default_model="gemini-3.5-flash-lite",
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


def _is_transient(result: dict) -> bool:
    """A failure worth benching the provider for: outage, overload or quota."""
    status = result.get("status", 0)
    return result["error"] in ("provider_timeout", "provider_unreachable") or status == 429 or status >= 500


def _bench(name: str) -> None:
    _benched_until[name] = time.monotonic() + float(os.environ.get("AGCMS_PROVIDER_COOLDOWN", "60"))


def _ready(chain: list[str]) -> list[str]:
    """Providers in ``chain`` not benched; all of them if every one is benched."""
    now = time.monotonic()
    return [p for p in chain if _benched_until.get(p, 0) <= now] or chain


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
    except httpx.HTTPError as exc:
        return {"error": "provider_unreachable", "reason": f"'{name}' request failed: {exc!r}"}

    if resp.status_code != 200:
        return {"error": "llm_error", "status": resp.status_code,
                "reason": f"{name} returned {resp.status_code}: {resp.text[:300]}"}
    try:
        body = resp.json()
    except ValueError:
        return {"error": "llm_error", "reason": f"{name} returned a non-JSON body: {resp.text[:300]}"}
    if not isinstance(body, dict):
        return {"error": "llm_error", "reason": f"{name} returned an unexpected body: {resp.text[:300]}"}
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
    for name in _ready(chain):
        result = await _call_provider(name, messages, model if name == first else None, temperature, max_tokens)
        if "error" not in result:
            result[_ROUTING_KEY]["attempts"] = attempts
            return result
        if _is_transient(result):
            _bench(name)
        # A provider may answer 200 with its own {"error": {...}} body.
        error = result["error"] if isinstance(result["error"], str) else "llm_error"
        attempts.append({"provider": name, "error": error, "reason": result.get("reason") or str(result["error"])})

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
