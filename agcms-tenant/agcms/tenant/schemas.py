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


class SSOConfig(BaseModel):
    workos_org_id: Optional[str] = Field(default=None, max_length=100)
    sso_enforced: bool = False


class UpdateSSORequest(BaseModel):
    workos_org_id: Optional[str] = Field(default=None, max_length=100)
    sso_enforced: Optional[bool] = None


class ByokConfig(BaseModel):
    """Customer-managed KMS key reference. Returned by GET /byok."""

    enabled: bool
    provider: Optional[str] = Field(default=None, description="aws | gcp | azure")
    key_arn: Optional[str] = None
    kek_fingerprint: Optional[str] = Field(
        default=None,
        description="kek_id stored on the tenant's active DEK row "
                    "(useful for rotation evidence in audit reports).",
    )


class UpdateByokRequest(BaseModel):
    """PUT /tenants/{id}/byok payload.

    Send ``key_arn = ""`` (empty string) to disable BYOK and revert to the
    AGCMS-platform KEK on the next DEK rotation.
    """

    provider: Optional[str] = Field(default="aws", description="aws | gcp | azure")
    key_arn: Optional[str] = Field(default=None, max_length=512)
    rotate_now: bool = Field(
        default=True,
        description="If True, immediately rotate the DEK using the new KMS so "
                    "the change is verified end-to-end before the response is "
                    "returned. Set False to defer rotation to a maintenance window.",
    )
