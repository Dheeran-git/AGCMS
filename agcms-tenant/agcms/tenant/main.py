"""AGCMS Tenant Management Service.

Endpoints:
  POST /provision                 — Create a new tenant + API key + default policy
  GET  /tenants/{tenant_id}       — Fetch tenant details
  GET  /tenants/{tenant_id}/usage — Aggregated usage statistics
  PUT  /tenants/{tenant_id}/settings — Merge settings update
  GET  /health                    — Liveness check
"""

import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from agcms.common import tenant_keys as common_tenant_keys
from agcms.common.observability import init_observability
from agcms.tenant import db, service
from agcms.tenant.schemas import (
    ProvisionRequest,
    UpdateByokRequest,
    UpdateSSORequest,
    UpdateSettingsRequest,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AGCMS Tenant Management Service",
    description="Tenant provisioning and management service",
    version="1.0.0",
)

init_observability(app, "tenant")


@app.on_event("startup")
async def _hydrate_tenant_keys() -> None:
    """Load every active tenant DEK into the in-process cache and
    ensure pre-6.3 tenants get a freshly-minted DEK on first start."""
    try:
        async with db.connection() as conn:
            loaded = await common_tenant_keys.hydrate(conn)
            rows = await conn.fetch(
                "SELECT t.id FROM tenants t "
                "LEFT JOIN tenant_keys tk "
                "  ON tk.tenant_id = t.id AND tk.is_active = TRUE "
                "WHERE tk.id IS NULL AND t.is_active = TRUE"
            )
            for row in rows:
                await common_tenant_keys.mint_and_store(conn, row["id"])
        logger.info(
            "tenant-keys hydrated: %d existing + %d backfilled",
            len(loaded), len(rows),
        )
    except Exception:
        logger.exception("tenant-keys hydration failed")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "tenant"}


@app.post("/provision", status_code=201)
async def provision(req: ProvisionRequest):
    """Provision a new tenant. Returns the API key — store it securely."""
    try:
        result = await service.provision_tenant(
            name=req.name,
            admin_email=req.admin_email,
            plan=req.plan,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Provisioning failed: {exc}")
    return result


@app.get("/tenants/{tenant_id}")
async def get_tenant(tenant_id: str):
    """Fetch tenant details by ID."""
    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant


@app.get("/tenants/{tenant_id}/usage")
async def get_usage(tenant_id: str):
    """Return today's and month-to-date usage statistics for the tenant."""
    tenant = await service.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        stats = await service.get_usage(tenant_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch usage: {exc}")
    return stats


@app.put("/tenants/{tenant_id}/settings")
async def update_settings(tenant_id: str, req: UpdateSettingsRequest):
    """Merge settings update into the tenant's settings JSONB."""
    settings_dict = req.settings.model_dump(exclude_none=True)
    if req.settings.extra:
        settings_dict.update(req.settings.extra)
        del settings_dict["extra"]

    updated = await service.update_settings(tenant_id, settings_dict)
    if not updated:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant = await service.get_tenant(tenant_id)
    return {"message": "Settings updated", "settings": tenant.settings}


@app.get("/tenants/{tenant_id}/sso")
async def get_sso(tenant_id: str):
    """Return the tenant's SSO configuration (workos_org_id + sso_enforced)."""
    config = await service.get_sso_config(tenant_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return config


@app.put("/tenants/{tenant_id}/sso")
async def update_sso(tenant_id: str, req: UpdateSSORequest):
    """Update the tenant's SSO configuration.

    ``workos_org_id = ""`` clears it. Fields set to None are left unchanged.
    """
    config = await service.update_sso_config(
        tenant_id,
        workos_org_id=req.workos_org_id,
        sso_enforced=req.sso_enforced,
    )
    if config is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"message": "SSO configuration updated", "sso": config}


@app.get("/tenants/{tenant_id}/byok")
async def get_byok(tenant_id: str):
    """Return the tenant's Bring-Your-Own-Key configuration."""
    config = await service.get_byok_config(tenant_id)
    if config is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return config


@app.put("/tenants/{tenant_id}/byok")
async def update_byok(tenant_id: str, req: UpdateByokRequest):
    """Set or clear the tenant's customer-managed KMS key.

    By default the DEK is rotated immediately so a misconfigured ARN
    surfaces as a 400 here instead of at the first encrypt call.
    """
    try:
        config = await service.update_byok_config(
            tenant_id,
            provider=req.provider,
            key_arn=req.key_arn,
            rotate_now=req.rotate_now,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"BYOK update failed (key unreachable?): {exc}",
        )
    if config is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"message": "BYOK configuration updated", "byok": config}
