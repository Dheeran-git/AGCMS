"""AGCMS SDK error hierarchy."""

from __future__ import annotations

from typing import Any, Optional


class AGCMSError(Exception):
    """Base class for every error raised by the SDK."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        interaction_id: Optional[str] = None,
        payload: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.interaction_id = interaction_id
        self.payload = payload or {}

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"{type(self).__name__}({self!s}, "
            f"status_code={self.status_code}, interaction_id={self.interaction_id!r})"
        )


class AuthError(AGCMSError):
    """Bad / missing API key, expired JWT, or wrong scope."""


class RateLimitedError(AGCMSError):
    """Tenant or per-IP rate limit hit on the gateway."""


class BlockedError(AGCMSError):
    """Request was blocked by an AGCMS policy (PII / prompt injection / custom)."""


class UpstreamError(AGCMSError):
    """LLM provider returned an error after AGCMS allowed the request through."""


def from_response(payload: dict[str, Any], status: int) -> AGCMSError:
    """Map an AGCMS-shaped error payload to the appropriate exception class.

    Accepts both the AGCMS-native shape ``{"error": "<code>", "reason": "..."}``
    and the OpenAI-style shape ``{"error": {"code": "...", "message": "..."}}``
    that may pass through from upstream providers.
    """
    payload = payload or {}
    raw_error = payload.get("error", "agcms_error")
    if isinstance(raw_error, dict):
        code = str(raw_error.get("code") or raw_error.get("type") or "agcms_error")
        nested_message = raw_error.get("message")
    else:
        code = str(raw_error)
        nested_message = None
    reason = payload.get("reason") or nested_message or code
    interaction_id = payload.get("interaction_id")

    cls: type[AGCMSError]
    if status == 401 or code in {"auth_failed", "forbidden"} and status in (401, 403):
        cls = AuthError
    elif status == 429 or code == "rate_limited":
        cls = RateLimitedError
    elif code == "request_blocked" or status == 403:
        cls = BlockedError
    elif status >= 500 or code in {"llm_error", "upstream_error"}:
        cls = UpstreamError
    else:
        cls = AGCMSError

    return cls(reason, status_code=status, interaction_id=interaction_id, payload=payload)
