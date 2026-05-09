"""AGCMS Authentication Service.

Endpoints:
  POST /v1/auth/token           — exchange API key for JWT access + refresh tokens
  POST /v1/auth/refresh         — exchange refresh token for new access token
  GET  /v1/auth/me              — return caller identity from access token
  GET  /v1/auth/sso/authorize   — redirect to WorkOS for SSO login
  GET  /v1/auth/sso/callback    — WorkOS redirects here after IdP login
  GET  /v1/auth/sso/status      — report whether SSO is configured on this deployment
  GET  /health                  — liveness probe
"""

import logging
import os
import time
from typing import Optional
from urllib.parse import urlencode

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from pydantic import BaseModel

from agcms.auth.db import (
    get_admin_user,
    get_tenant_by_api_key,
    get_tenant_by_workos_org,
    provision_or_fetch_sso_user,
)
from agcms.auth.sso import (
    SSONotConfigured,
    complete_authentication,
    get_authorization_url,
    is_configured as sso_is_configured,
)
from agcms.auth import mfa, mfa_db, sessions as session_store
from agcms.auth.tokens import (
    IssuedAccessToken,
    blacklist_access_jti,
    blacklist_jti,
    create_mfa_challenge_token,
    create_refresh_token,
    is_jti_blacklisted,
    issue_access_token,
    set_user_revoked_before,
    verify_access_token,
    verify_mfa_challenge_token,
    verify_refresh_token,
)
from agcms.common.observability import init_observability

_log = logging.getLogger("agcms.auth")

app = FastAPI(
    title="AGCMS Authentication Service",
    description="JWT issuance and token refresh for AGCMS tenants",
    version="2.0.0",
)

init_observability(app, "auth")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class TokenRequest(BaseModel):
    api_key: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes in seconds


class MFAChallengeResponse(BaseModel):
    """Returned by /v1/auth/token when the user has MFA enabled."""
    mfa_required: bool = True
    challenge_token: str
    expires_in: int = 300  # 5 minutes


class MFALoginRequest(BaseModel):
    challenge_token: str
    code: Optional[str] = None
    recovery_code: Optional[str] = None


class MFAEnrollResponse(BaseModel):
    provisioning_uri: str
    qr_png_data_url: str
    recovery_codes: list[str]  # plaintext — shown once


class MFAVerifyEnrollmentRequest(BaseModel):
    code: str


class MFAStatusResponse(BaseModel):
    enrolled: bool
    enabled: bool


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900


class MeResponse(BaseModel):
    tenant_id: str
    user_id: str
    role: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bearer(authorization: Optional[str]) -> str:
    """Extract token from 'Bearer <token>' header, raise 401 on failure."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return authorization[7:]


def _client_fingerprint(request: Optional[Request]) -> tuple[Optional[str], Optional[str]]:
    """Extract user-agent + client IP from a request. Safe if request is None (unit tests)."""
    if request is None:
        return None, None
    ua = request.headers.get("user-agent")
    # Honour x-forwarded-for (gateway sits behind ingress in k8s); first hop wins.
    xff = request.headers.get("x-forwarded-for")
    ip = (xff.split(",")[0].strip() if xff else None) or (
        request.client.host if request.client else None
    )
    return ua, ip


async def _record_new_access_session(
    access: IssuedAccessToken,
    *,
    tenant_user_id: str,
    tenant_id: str,
    issued_via: str,
    request: Optional[Request],
) -> None:
    """Best-effort: persist a session row for a freshly-issued access token."""
    ua, ip = _client_fingerprint(request)
    try:
        await session_store.record_session(
            jti=access.jti,
            tenant_user_id=tenant_user_id,
            tenant_id=tenant_id,
            issued_at=access.issued_at,
            expires_at=access.expires_at,
            issued_via=issued_via,
            user_agent=ua,
            ip_address=ip,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort; token itself remains valid
        _log.warning("failed to record auth_sessions row jti=%s: %s", access.jti, exc)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "auth"}


@app.post("/v1/auth/token")
async def issue_token(body: TokenRequest, request: Request):
    """Exchange an API key for JWT tokens.

    If the tenant's admin user has MFA enabled, this returns an
    ``MFAChallengeResponse`` instead — the caller then POSTs to
    ``/v1/auth/mfa/login`` with a TOTP code or recovery code to obtain
    the real access + refresh pair.
    """
    tenant = await get_tenant_by_api_key(body.api_key)
    if tenant is None:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    user = await get_admin_user(tenant["id"])
    if user is None:
        raise HTTPException(status_code=500, detail="No admin user configured for tenant")

    mfa_row = await mfa_db.fetch_mfa(user["id"])
    if mfa_row and mfa_row["enabled"]:
        challenge = create_mfa_challenge_token(
            tenant_id=tenant["id"],
            user_id=user["external_id"],
            tenant_user_id=str(user["id"]),
            role=user["role"],
        )
        return MFAChallengeResponse(challenge_token=challenge)

    access = issue_access_token(
        tenant_id=tenant["id"],
        role=user["role"],
        user_id=user["external_id"],
        tenant_user_id=str(user["id"]),
    )
    refresh = create_refresh_token(tenant_id=tenant["id"])

    await _record_new_access_session(
        access,
        tenant_user_id=str(user["id"]),
        tenant_id=tenant["id"],
        issued_via="api_key",
        request=request,
    )

    return TokenResponse(access_token=access.token, refresh_token=refresh)


@app.post("/v1/auth/refresh", response_model=AccessTokenResponse)
async def refresh_token(body: RefreshRequest, request: Request):
    """Exchange a refresh token for a new access token (single-use enforcement)."""
    payload = verify_refresh_token(body.refresh_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    jti = payload.get("jti")
    if jti is None:
        raise HTTPException(status_code=401, detail="Refresh token missing jti claim")

    if await is_jti_blacklisted(jti):
        raise HTTPException(status_code=401, detail="Refresh token already used")

    tenant_id = payload["sub"]
    user = await get_admin_user(tenant_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Tenant no longer active")

    access = issue_access_token(
        tenant_id=tenant_id,
        role=user["role"],
        user_id=user["external_id"],
        tenant_user_id=str(user["id"]),
    )

    # Blacklist this jti so the same refresh token cannot be reused
    await blacklist_jti(jti, payload["exp"])

    await _record_new_access_session(
        access,
        tenant_user_id=str(user["id"]),
        tenant_id=tenant_id,
        issued_via="refresh",
        request=request,
    )

    return AccessTokenResponse(access_token=access.token)


_DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://localhost:3000")
_SSO_STATE_SECRET = os.environ.get(
    "JWT_SECRET_KEY", "dev-jwt-secret-change-me"
)
_SSO_STATE_TTL = 600  # 10 minutes


def _encode_sso_state(workos_org_id: str) -> str:
    """Sign the state parameter so we can verify it on callback (CSRF guard)."""
    payload = {
        "org": workos_org_id,
        "exp": int(time.time()) + _SSO_STATE_TTL,
        "t": "sso_state",
    }
    return jwt.encode(payload, _SSO_STATE_SECRET, algorithm="HS256")


def _decode_sso_state(state: str) -> str:
    try:
        payload = jwt.decode(state, _SSO_STATE_SECRET, algorithms=["HS256"])
    except JWTError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid SSO state: {exc}")
    if payload.get("t") != "sso_state":
        raise HTTPException(status_code=400, detail="State is not an SSO state token")
    return payload["org"]


@app.get("/v1/auth/sso/status")
async def sso_status():
    """Report whether SSO is configured on this deployment."""
    return {"configured": sso_is_configured()}


@app.get("/v1/auth/sso/authorize")
async def sso_authorize(org: str = Query(..., description="WorkOS organization ID")):
    """Redirect the browser to WorkOS for IdP login."""
    try:
        state = _encode_sso_state(org)
        url = get_authorization_url(org, state=state)
    except SSONotConfigured as exc:
        raise HTTPException(
            status_code=503,
            detail=f"SSO is not configured on this deployment: {exc}",
        )
    return RedirectResponse(url=url, status_code=302)


@app.get("/v1/auth/sso/callback")
async def sso_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
):
    """Exchange the WorkOS authorization code for AGCMS JWT tokens.

    On success: redirects back to the dashboard with
    ``#access_token=...&refresh_token=...`` in the URL fragment so tokens
    never hit a backend log or URL-bar history.
    """
    workos_org_id = _decode_sso_state(state)

    try:
        profile = complete_authentication(code)
    except SSONotConfigured as exc:
        raise HTTPException(status_code=503, detail=f"SSO not configured: {exc}")
    except Exception as exc:  # WorkOS SDK raises a typed error we don't want to leak.
        raise HTTPException(status_code=401, detail="SSO authentication failed") from exc

    if profile.workos_org_id and profile.workos_org_id != workos_org_id:
        raise HTTPException(
            status_code=400,
            detail="Profile organization does not match requested organization",
        )

    tenant = await get_tenant_by_workos_org(workos_org_id)
    if tenant is None:
        raise HTTPException(
            status_code=403,
            detail=f"No active tenant linked to WorkOS org {workos_org_id}",
        )

    display_name = " ".join(
        part for part in [profile.first_name, profile.last_name] if part
    ) or None
    user = await provision_or_fetch_sso_user(
        tenant["id"],
        sso_subject=profile.sso_subject,
        email=profile.email,
        display_name=display_name,
    )
    if user is None:
        raise HTTPException(status_code=403, detail="User is deactivated for this tenant")

    access = issue_access_token(
        tenant_id=tenant["id"],
        role=user["role"],
        user_id=user["external_id"],
        tenant_user_id=str(user["id"]),
    )
    refresh = create_refresh_token(tenant_id=tenant["id"])

    await _record_new_access_session(
        access,
        tenant_user_id=str(user["id"]),
        tenant_id=tenant["id"],
        issued_via="sso",
        request=request,
    )

    fragment = urlencode(
        {"access_token": access.token, "refresh_token": refresh, "token_type": "bearer"}
    )
    return RedirectResponse(
        url=f"{_DASHBOARD_URL}/auth/sso/complete#{fragment}", status_code=302
    )


@app.get("/v1/auth/me", response_model=MeResponse)
async def me(authorization: Optional[str] = Header(default=None)):
    """Return the caller's identity decoded from the access token."""
    token = _bearer(authorization)
    payload = verify_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    return MeResponse(
        tenant_id=payload["sub"],
        user_id=payload["user_id"],
        role=payload["role"],
    )


# ---------------------------------------------------------------------------
# MFA (TOTP + recovery codes)
# ---------------------------------------------------------------------------


async def _require_access_payload(authorization: Optional[str]) -> dict:
    token = _bearer(authorization)
    payload = verify_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    return payload


async def _fetch_tenant_user(payload: dict) -> dict:
    """Resolve a JWT payload to a tenant_users row, 401 on miss."""
    user = await mfa_db.fetch_user_by_external_id(payload["sub"], payload["user_id"])
    if user is None or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Tenant user not found or inactive")
    return user


@app.get("/v1/auth/mfa/status", response_model=MFAStatusResponse)
async def mfa_status(authorization: Optional[str] = Header(default=None)):
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)
    row = await mfa_db.fetch_mfa(user["id"])
    enrolled = row is not None
    enabled = bool(row and row["enabled"])
    return MFAStatusResponse(enrolled=enrolled, enabled=enabled)


@app.post("/v1/auth/mfa/enroll", response_model=MFAEnrollResponse)
async def mfa_enroll(authorization: Optional[str] = Header(default=None)):
    """Begin MFA enrollment. Returns QR + recovery codes (shown ONCE).

    The enrollment is *pending* until the caller proves possession of
    the secret via ``/v1/auth/mfa/verify-enrollment``.
    """
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)

    email = user["email"] or user["external_id"]
    material = mfa.begin_enrollment(email=email)
    await mfa_db.upsert_pending_enrollment(
        user["id"],
        totp_secret=material.secret,
        recovery_hashes=list(material.recovery_hashes),
    )

    return MFAEnrollResponse(
        provisioning_uri=material.provisioning_uri,
        qr_png_data_url=mfa.qr_png_data_url(material.provisioning_uri),
        recovery_codes=list(material.recovery_codes),
    )


@app.post("/v1/auth/mfa/verify-enrollment")
async def mfa_verify_enrollment(
    body: MFAVerifyEnrollmentRequest,
    authorization: Optional[str] = Header(default=None),
):
    """Finalize enrollment by proving the authenticator app works."""
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)
    row = await mfa_db.fetch_mfa(user["id"])
    if row is None:
        raise HTTPException(status_code=400, detail="No pending MFA enrollment")
    if row["enabled"]:
        raise HTTPException(status_code=400, detail="MFA already enabled for this user")
    if not mfa.verify_totp(row["totp_secret"], body.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    await mfa_db.mark_verified(user["id"])
    return {"message": "MFA enabled"}


@app.post("/v1/auth/mfa/disable")
async def mfa_disable(authorization: Optional[str] = Header(default=None)):
    """Disable MFA for the caller. Access token required."""
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)
    ok = await mfa_db.disable_mfa(user["id"])
    if not ok:
        raise HTTPException(status_code=400, detail="MFA is not currently enabled")
    return {"message": "MFA disabled"}


@app.post("/v1/auth/mfa/login", response_model=TokenResponse)
async def mfa_login(body: MFALoginRequest, request: Request):
    """Exchange a challenge_token + (TOTP code OR recovery code) for real tokens."""
    payload = verify_mfa_challenge_token(body.challenge_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired challenge token")

    row = await mfa_db.fetch_mfa(payload["tenant_user_id"])
    if row is None or not row["enabled"]:
        raise HTTPException(status_code=401, detail="MFA is not enabled for this user")

    if body.code:
        if not mfa.verify_totp(row["totp_secret"], body.code):
            raise HTTPException(status_code=401, detail="Invalid TOTP code")
        await mfa_db.record_use(payload["tenant_user_id"])
    elif body.recovery_code:
        ok, remaining = mfa.consume_recovery_code(
            body.recovery_code, row["recovery_codes"]
        )
        if not ok:
            raise HTTPException(status_code=401, detail="Invalid recovery code")
        await mfa_db.replace_recovery_codes(
            payload["tenant_user_id"], list(remaining)
        )
        await mfa_db.record_use(payload["tenant_user_id"])
    else:
        raise HTTPException(
            status_code=400, detail="Either code or recovery_code is required"
        )

    access = issue_access_token(
        tenant_id=payload["sub"],
        role=payload["role"],
        user_id=payload["user_id"],
        tenant_user_id=payload["tenant_user_id"],
    )
    refresh = create_refresh_token(tenant_id=payload["sub"])

    await _record_new_access_session(
        access,
        tenant_user_id=payload["tenant_user_id"],
        tenant_id=payload["sub"],
        issued_via="mfa",
        request=request,
    )

    return TokenResponse(access_token=access.token, refresh_token=refresh)


# ---------------------------------------------------------------------------
# Sessions (listing + revocation)
# ---------------------------------------------------------------------------


class SessionSummary(BaseModel):
    jti: str
    issued_at: str
    expires_at: str
    last_seen_at: Optional[str] = None
    revoked_at: Optional[str] = None
    revoke_reason: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    issued_via: str
    current: bool = False


class TenantSessionSummary(SessionSummary):
    tenant_user_id: str
    email: Optional[str] = None
    external_id: str
    role: str


def _serialize_session(row: dict, *, current_jti: Optional[str] = None) -> dict:
    return {
        "jti": row["jti"],
        "issued_at": row["issued_at"].isoformat(),
        "expires_at": row["expires_at"].isoformat(),
        "last_seen_at": row["last_seen_at"].isoformat() if row.get("last_seen_at") else None,
        "revoked_at": row["revoked_at"].isoformat() if row.get("revoked_at") else None,
        "revoke_reason": row.get("revoke_reason"),
        "user_agent": row.get("user_agent"),
        "ip_address": row.get("ip_address"),
        "issued_via": row["issued_via"],
        "current": current_jti is not None and row["jti"] == current_jti,
    }


@app.get("/v1/auth/sessions")
async def list_my_sessions(authorization: Optional[str] = Header(default=None)):
    """Return the caller's own sessions (active + recent), newest first."""
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)
    rows = await session_store.list_sessions_for_user(str(user["id"]))
    return {"sessions": [_serialize_session(r, current_jti=payload.get("jti")) for r in rows]}


@app.delete("/v1/auth/sessions/{jti}")
async def revoke_my_session(
    jti: str, authorization: Optional[str] = Header(default=None)
):
    """Revoke a single session belonging to the caller."""
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)

    row = await session_store.fetch_session(jti)
    if row is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if row["tenant_user_id"] != user["id"]:
        # Don't reveal existence of sessions belonging to other users
        raise HTTPException(status_code=404, detail="Session not found")

    revoked = await session_store.revoke_session(
        jti=jti, revoked_by=str(user["id"]), reason="user_revoked"
    )
    if revoked is None:
        raise HTTPException(status_code=400, detail="Session is already revoked")
    # Propagate to the gateway's fast-path cache
    await blacklist_access_jti(jti, int(revoked["expires_at"].timestamp()))
    return {"revoked": True, "jti": jti}


@app.post("/v1/auth/sessions/revoke-all")
async def revoke_all_my_sessions(
    authorization: Optional[str] = Header(default=None),
):
    """Revoke every active session belonging to the caller.

    Also bumps ``tenant_users.revoked_before`` so any session row that somehow
    isn't explicitly marked revoked (e.g. a row that failed to insert on
    issuance) is still rejected on the next gateway check.
    """
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)
    revoked = await session_store.revoke_all_sessions_for_user(
        tenant_user_id=str(user["id"]),
        revoked_by=str(user["id"]),
        reason="user_revoked_all",
    )
    for row in revoked:
        await blacklist_access_jti(row["jti"], int(row["expires_at"].timestamp()))
    # Publish the bulk pivot — catches orphan sessions whose rows never wrote.
    await set_user_revoked_before(str(user["id"]), int(time.time()))
    return {"revoked_count": len(revoked)}


@app.get("/v1/auth/admin/sessions")
async def list_tenant_sessions(authorization: Optional[str] = Header(default=None)):
    """Admin-only view: every session in the caller's tenant."""
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    rows = await session_store.list_sessions_for_tenant(user["tenant_id"])
    return {
        "sessions": [
            {
                **_serialize_session(r, current_jti=payload.get("jti")),
                "tenant_user_id": str(r["tenant_user_id"]),
                "email": r.get("email"),
                "external_id": r["external_id"],
                "role": r["role"],
            }
            for r in rows
        ]
    }


@app.delete("/v1/auth/admin/sessions/{jti}")
async def admin_revoke_session(
    jti: str, authorization: Optional[str] = Header(default=None)
):
    """Admin: revoke any session in the tenant (e.g. suspicious activity, offboarding)."""
    payload = await _require_access_payload(authorization)
    user = await _fetch_tenant_user(payload)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    row = await session_store.fetch_session(jti)
    if row is None or row["tenant_id"] != user["tenant_id"]:
        raise HTTPException(status_code=404, detail="Session not found")

    revoked = await session_store.revoke_session(
        jti=jti, revoked_by=str(user["id"]), reason="admin_revoked"
    )
    if revoked is None:
        raise HTTPException(status_code=400, detail="Session is already revoked")
    await blacklist_access_jti(jti, int(revoked["expires_at"].timestamp()))
    return {"revoked": True, "jti": jti}
