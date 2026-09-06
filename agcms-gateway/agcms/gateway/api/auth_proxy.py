"""Auth-service proxies (no role gate)."""

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel

from agcms.gateway.api.common import AUTH_URL, passthrough

router = APIRouter()


class TokenRequest(BaseModel):
    api_key: str


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/auth/token")
async def auth_token(body: TokenRequest):
    """Proxy api_key → access+refresh tokens to the auth service."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{AUTH_URL}/v1/auth/token", json=body.model_dump())
    return passthrough(resp)


@router.post("/auth/refresh")
async def auth_refresh(body: RefreshRequest):
    """Proxy refresh_token → new access token."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{AUTH_URL}/v1/auth/refresh", json=body.model_dump())
    return passthrough(resp)


@router.get("/auth/me")
async def auth_me(request: Request):
    """Proxy the Authorization header to the auth service /v1/auth/me."""
    auth_header = request.headers.get("Authorization", "")
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(
            f"{AUTH_URL}/v1/auth/me",
            headers={"Authorization": auth_header},
        )
    return passthrough(resp)
