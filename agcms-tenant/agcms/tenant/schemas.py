"""Pydantic schemas for the AGCMS Tenant Management Service."""

from typing import Any, Optional
from pydantic import BaseModel, EmailStr, Field


class ProvisionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    admin_email: str = Field(..., min_length=1, max_length=256)
    plan: str = Field(default="starter")

    model_config = {"json_schema_extra": {"example": {
        "name": "Acme Corp",
        "admin_email": "admin@acme.com",
        "plan": "starter",
    }}}


class ProvisionResponse(BaseModel):
    tenant_id: str
    api_key: str
    name: str
    plan: str
    admin_email: str
    message: str


class TenantSettings(BaseModel):
    requests_per_minute: Optional[int] = None
    requests_per_day: Optional[int] = None
    pii_action: Optional[str] = None          # REDACT | BLOCK | ALLOW
    injection_threshold: Optional[float] = None
    extra: Optional[dict[str, Any]] = None


class UpdateSettingsRequest(BaseModel):
    settings: TenantSettings


class TenantDetail(BaseModel):
    id: str
    name: str
    plan: str
    admin_email: str
    is_active: bool
    settings: dict[str, Any]
    created_at: str


class UsageStats(BaseModel):
    tenant_id: str
    requests_today: int
    requests_this_month: int
    blocked_today: int
    pii_detections_today: int
    injection_detections_today: int
