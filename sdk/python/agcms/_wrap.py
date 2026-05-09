"""openai_wrap — drop in an AGCMS gateway in front of an existing OpenAI client.

Three-line integration:

    from openai import OpenAI
    from agcms import openai_wrap

    client = openai_wrap(
        OpenAI(api_key="..."),
        agcms_base_url="https://api.your-tenant.agcms.com",
        agcms_api_key="agc_live_...",
    )

The returned client behaves identically to ``openai.OpenAI``: every
``chat.completions.create(...)`` is rerouted through AGCMS, so the original
OpenAI key is only ever used by the AGCMS gateway upstream.
"""

from __future__ import annotations

from typing import Any, Optional

from agcms._client import AGCMSClient


class _OpenAICompletionsAdapter:
    def __init__(self, agcms_client: AGCMSClient) -> None:
        self._agcms = agcms_client

    def create(self, **kwargs: Any) -> Any:
        # AGCMS gateway returns the upstream provider's payload verbatim, so
        # we don't need to remap response shape.
        return self._agcms.chat.completions.create(**kwargs)


class _OpenAIChatAdapter:
    def __init__(self, agcms_client: AGCMSClient) -> None:
        self.completions = _OpenAICompletionsAdapter(agcms_client)


class OpenAIWrappedClient:
    """Quacks like ``openai.OpenAI`` but routes through AGCMS."""

    def __init__(
        self,
        original: Any,
        agcms_base_url: str,
        agcms_api_key: str,
        *,
        user_id: Optional[str] = None,
        department: Optional[str] = None,
    ) -> None:
        self._original = original
        self._agcms = AGCMSClient(
            base_url=agcms_base_url,
            api_key=agcms_api_key,
            user_id=user_id,
            department=department,
        )
        self.chat = _OpenAIChatAdapter(self._agcms)

    @property
    def last_interaction_id(self) -> Optional[str]:
        return self._agcms.last_interaction_id

    def __getattr__(self, name: str) -> Any:
        # Anything we don't shadow (e.g. embeddings, audio, files) falls through
        # to the wrapped OpenAI client unchanged.
        return getattr(self._original, name)


def openai_wrap(
    openai_client: Any,
    *,
    agcms_base_url: str,
    agcms_api_key: str,
    user_id: Optional[str] = None,
    department: Optional[str] = None,
) -> OpenAIWrappedClient:
    """Wrap an OpenAI client so all chat.completions.create() calls flow through AGCMS."""
    return OpenAIWrappedClient(
        openai_client,
        agcms_base_url=agcms_base_url,
        agcms_api_key=agcms_api_key,
        user_id=user_id,
        department=department,
    )
