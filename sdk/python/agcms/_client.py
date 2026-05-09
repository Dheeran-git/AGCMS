"""AGCMSClient — the user-facing entrypoint.

Two flavors:
  * ``AGCMSClient``       — synchronous (uses httpx.Client)
  * ``AsyncAGCMSClient``  — async  (uses httpx.AsyncClient)

Both speak the OpenAI-compatible ``/v1/chat/completions`` shape that the AGCMS
gateway accepts and proxies upstream. The interaction ID returned by the
gateway is captured so callers can immediately link a request to its audit row.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx

from agcms._errors import from_response

_DEFAULT_TIMEOUT = httpx.Timeout(60.0, connect=10.0)
_USER_AGENT = "agcms-python/0.1.0"


def _headers(api_key: str, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
    }
    if extra:
        headers.update(extra)
    return headers


class _ChatCompletionsSync:
    def __init__(self, parent: "AGCMSClient") -> None:
        self._parent = parent

    def create(self, **kwargs: Any) -> dict[str, Any]:
        return self._parent._post("/v1/chat/completions", kwargs)


class _ChatSync:
    def __init__(self, parent: "AGCMSClient") -> None:
        self.completions = _ChatCompletionsSync(parent)


class _ChatCompletionsAsync:
    def __init__(self, parent: "AsyncAGCMSClient") -> None:
        self._parent = parent

    async def create(self, **kwargs: Any) -> dict[str, Any]:
        return await self._parent._post("/v1/chat/completions", kwargs)


class _ChatAsync:
    def __init__(self, parent: "AsyncAGCMSClient") -> None:
        self.completions = _ChatCompletionsAsync(parent)


class _BaseClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        timeout: Optional[httpx.Timeout] = None,
        user_id: Optional[str] = None,
        department: Optional[str] = None,
        default_headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._base_url = (base_url or os.environ.get("AGCMS_BASE_URL", "")).rstrip("/")
        self._api_key = api_key or os.environ.get("AGCMS_API_KEY", "")
        if not self._base_url:
            raise ValueError("AGCMS base_url required (or set AGCMS_BASE_URL env)")
        if not self._api_key:
            raise ValueError("AGCMS api_key required (or set AGCMS_API_KEY env)")
        self._timeout = timeout or _DEFAULT_TIMEOUT
        self._extra_headers: dict[str, str] = dict(default_headers or {})
        if user_id:
            self._extra_headers["X-AGCMS-User-ID"] = user_id
        if department:
            self._extra_headers["X-AGCMS-Department"] = department
        self.last_interaction_id: Optional[str] = None

    def _full_url(self, path: str) -> str:
        return self._base_url + path

    def _capture(self, resp: httpx.Response) -> dict[str, Any]:
        self.last_interaction_id = resp.headers.get("X-AGCMS-Interaction-ID")
        try:
            payload = resp.json() if resp.content else {}
        except ValueError:
            payload = {"raw": resp.text}
        if resp.status_code >= 400:
            raise from_response(payload if isinstance(payload, dict) else {}, resp.status_code)
        return payload


class AGCMSClient(_BaseClient):
    """Synchronous AGCMS client."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._http = httpx.Client(timeout=self._timeout)
        self.chat = _ChatSync(self)

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._http.post(
            self._full_url(path),
            headers=_headers(self._api_key, self._extra_headers),
            json=body,
        )
        return self._capture(resp)

    def list_models(self) -> dict[str, Any]:
        resp = self._http.get(
            self._full_url("/v1/models"),
            headers=_headers(self._api_key, self._extra_headers),
        )
        return self._capture(resp)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "AGCMSClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncAGCMSClient(_BaseClient):
    """Async AGCMS client."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._http = httpx.AsyncClient(timeout=self._timeout)
        self.chat = _ChatAsync(self)

    async def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = await self._http.post(
            self._full_url(path),
            headers=_headers(self._api_key, self._extra_headers),
            json=body,
        )
        return self._capture(resp)

    async def list_models(self) -> dict[str, Any]:
        resp = await self._http.get(
            self._full_url("/v1/models"),
            headers=_headers(self._api_key, self._extra_headers),
        )
        return self._capture(resp)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncAGCMSClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()
