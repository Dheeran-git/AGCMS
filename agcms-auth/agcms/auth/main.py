"""AGCMS Authentication Service.

Endpoints:
  POST /v1/auth/token   — exchange API key for JWT access + refresh tokens
  POST /v1/auth/refresh — exchange refresh token for new access token
  GET  /v1/auth/me      — return caller identity from access token
  GET  /health          — liveness probe
"""

from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from agcms.auth.db import get_admin_user, get_tenant_by_api_key
from agcms.auth.tokens import (
    blacklist_jti,
    create_access_token,
    create_refresh_token,
    is_jti_blacklisted,
    verify_access_token,
    verify_refresh_token,
)

app = FastAPI(
    title="AGCMS Authentication Service",
    description="JWT issuance and token refresh for AGCMS tenants",
    version="2.0.0",
)


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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "auth"}


@app.post("/v1/auth/token", response_model=TokenResponse)
async def issue_token(body: TokenRequest):
    """Exchange an API key for JWT access + refresh tokens."""
    tenant = await get_tenant_by_api_key(body.api_key)
    if tenant is None:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")

    user = await get_admin_user(tenant["id"])
    if user is None:
        raise HTTPException(status_code=500, detail="No admin user configured for tenant")

    access = create_access_token(
        tenant_id=tenant["id"],
        role=user["role"],
        user_id=user["external_id"],
    )
    refresh = create_refresh_token(tenant_id=tenant["id"])

    return TokenResponse(access_token=access, refresh_token=refresh)


@app.post("/v1/auth/refresh", response_model=AccessTokenResponse)
async def refresh_token(body: RefreshRequest):
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

    access = create_access_token(
        tenant_id=tenant_id,
        role=user["role"],
        user_id=user["external_id"],
    )

    # Blacklist this jti so the same refresh token cannot be reused
    await blacklist_jti(jti, payload["exp"])

    return AccessTokenResponse(access_token=access)


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
