"""Tenant-service admin proxies."""

import httpx
from fastapi import APIRouter, Body, Depends

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_admin
from agcms.gateway.api.common import TENANT_URL, passthrough

router = APIRouter()


@router.post("/tenant/provision")
async def tenant_provision(
    body: dict = Body(...),
    ctx: AuthContext = Depends(require_admin),
):
    """Proxy tenant provisioning to the tenant service."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{TENANT_URL}/provision", json=body)
    return passthrough(resp)


@router.get("/tenant/usage")
async def tenant_usage(ctx: AuthContext = Depends(require_admin)):
    """Proxy usage stats request to the tenant service (for the caller's tenant)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{TENANT_URL}/tenants/{ctx.tenant_id}/usage")
    return passthrough(resp)


@router.put("/tenant/settings")
async def tenant_settings(
    body: dict = Body(...),
    ctx: AuthContext = Depends(require_admin),
):
    """Proxy settings update to the tenant service (for the caller's tenant)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.put(
            f"{TENANT_URL}/tenants/{ctx.tenant_id}/settings",
            json=body,
        )
    return passthrough(resp)
