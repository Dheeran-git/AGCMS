"""WorkOS-backed SSO integration.

WorkOS gives us a single integration that fronts Okta, Azure AD, Google
Workspace, Ping, OneLogin, JumpCloud, and ~40 other IdPs. Each AGCMS
tenant maps 1:1 to a WorkOS Organization; the tenant's admin configures
their IdP inside the WorkOS dashboard — AGCMS never sees raw IdP secrets.

Flow
----
1. Browser hits ``/v1/auth/sso/authorize?org=<workos_org_id>``.
2. This module asks WorkOS for an authorization URL bound to that org
   and returns a 302 → WorkOS → IdP → WorkOS.
3. WorkOS calls our ``/v1/auth/sso/callback?code=...&state=...``.
4. ``complete_authentication(code)`` exchanges the code for a profile.
5. We look up (or auto-provision) the tenant_user keyed on the WorkOS
   ``profile.id``, then issue an AGCMS JWT.

Env vars
--------
WORKOS_API_KEY       Server-side API secret (required in prod).
WORKOS_CLIENT_ID     WorkOS Client ID (required in prod).
WORKOS_REDIRECT_URI  Public URL of our ``/v1/auth/sso/callback`` endpoint.
DASHBOARD_URL        Where the dashboard lives; we redirect back here
                     after successful login, with the access + refresh
                     tokens in the URL fragment.

Dev fallback
------------
When any WorkOS env var is missing we skip real WorkOS calls and raise
``SSONotConfigured``. The endpoints surface this as a 503 so the
dashboard can hide the SSO button.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional


class SSONotConfigured(RuntimeError):
    """Raised when WorkOS env vars are unset — SSO is disabled."""


@dataclass(frozen=True)
class SSOProfile:
    sso_subject: str      # WorkOS profile.id — stable per (user, org)
    workos_org_id: str    # WorkOS organization_id
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    idp_connection_type: Optional[str]  # "OktaSAML", "GoogleOAuth", ...


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _cfg() -> dict[str, str]:
    api_key = os.environ.get("WORKOS_API_KEY")
    client_id = os.environ.get("WORKOS_CLIENT_ID")
    redirect_uri = os.environ.get("WORKOS_REDIRECT_URI")
    if not (api_key and client_id and redirect_uri):
        raise SSONotConfigured(
            "WORKOS_API_KEY, WORKOS_CLIENT_ID, and WORKOS_REDIRECT_URI must be set"
        )
    return {
        "api_key": api_key,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }


def is_configured() -> bool:
    try:
        _cfg()
        return True
    except SSONotConfigured:
        return False


# ---------------------------------------------------------------------------
# WorkOS client (lazy)
# ---------------------------------------------------------------------------

_client: Any = None


def _get_client() -> Any:
    """Return a configured WorkOS client, importing the SDK on first use."""
    global _client
    if _client is not None:
        return _client
    cfg = _cfg()
    try:
        import workos  # type: ignore[import]
    except ImportError as exc:
        raise SSONotConfigured(
            "`workos` package is not installed — add it to requirements.txt"
        ) from exc
    client = workos.WorkOSClient(
        api_key=cfg["api_key"], client_id=cfg["client_id"]
    )
    _client = client
    return client


def reset_client() -> None:
    """Test hook — clear the memoized client."""
    global _client
    _client = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_authorization_url(workos_org_id: str, *, state: str) -> str:
    """Return the URL to redirect the browser to for WorkOS authentication."""
    cfg = _cfg()
    client = _get_client()
    return client.sso.get_authorization_url(
        organization_id=workos_org_id,
        redirect_uri=cfg["redirect_uri"],
        state=state,
    )


def complete_authentication(code: str) -> SSOProfile:
    """Exchange an authorization code for a profile."""
    client = _get_client()
    # workos-python returns a typed ProfileAndToken — we extract only
    # what we need so we're not coupled to its generated Pydantic model.
    profile_and_token = client.sso.get_profile_and_token(code=code)
    p = profile_and_token.profile
    return SSOProfile(
        sso_subject=p.id,
        workos_org_id=p.organization_id or "",
        email=p.email,
        first_name=getattr(p, "first_name", None),
        last_name=getattr(p, "last_name", None),
        idp_connection_type=getattr(p, "connection_type", None),
    )


__all__ = [
    "SSONotConfigured",
    "SSOProfile",
    "get_authorization_url",
    "complete_authentication",
    "is_configured",
    "reset_client",
]
