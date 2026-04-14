"""AGCMS Tenant Management Service.

Endpoints:
  POST /provision                 — Create a new tenant + API key + default policy
  GET  /tenants/{tenant_id}       — Fetch tenant details
  GET  /tenants/{tenant_id}/usage — Aggregated usage statistics
  PUT  /tenants/{tenant_id}/settings — Merge settings update
  GET  /health                    — Liveness check
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from agcms.tenant import service
from agcms.tenant.schemas import ProvisionRequest, UpdateSettingsRequest

app = FastAPI(
    title="AGCMS Tenant Management Service",
    description="Tenant provisioning and management service",
    version="1.0.0",
)


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
