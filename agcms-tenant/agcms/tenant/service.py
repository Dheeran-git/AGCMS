"""Business logic for the AGCMS Tenant Management Service.

Handles tenant provisioning, retrieval, usage stats, and settings updates.
All DB interactions go through agcms.tenant.db helpers.
"""

import hashlib
import json
import os
import secrets
import string
from typing import Optional

from agcms.common import byok as common_byok
from agcms.common import tenant_keys as common_tenant_keys
from agcms.tenant import db
from agcms.tenant.schemas import (
    ByokConfig,
    ProvisionResponse,
    SSOConfig,
    TenantDetail,
    UsageStats,
)

_VALID_BYOK_PROVIDERS = {"aws"}  # 'gcp' / 'azure' added when implemented

_VALID_PLANS = {"starter", "business", "enterprise"}

_DEFAULT_POLICY = {
    "pii": {
        "enabled": True,
        "action_on_detection": "REDACT",
        "critical_action": "BLOCK",
        "risk_threshold": "MEDIUM",
        "custom_patterns": {},
    },
    "injection": {
        "enabled": True,
        "block_threshold": 0.65,
        "action_on_detection": "BLOCK",
        "log_all_attempts": True,
    },
    "response_compliance": {
        "enabled": True,
        "restricted_topics": [],
        "system_prompt_keywords": [],
        "action_on_violation": "REDACT",
    },
    "rate_limits": {
        "requests_per_minute": 60,
        "requests_per_day": 10000,
    },
    "audit": {
        "retention_days": 365,
        "export_formats": ["json", "csv"],
        "pii_in_logs": False,
    },
}


def _generate_api_key(tenant_id: str) -> str:
    """Generate a secure 32-character random API key prefixed with agcms_."""
    alphabet = string.ascii_letters + string.digits
    random_part = "".join(secrets.choice(alphabet) for _ in range(32))
    return f"agcms_{tenant_id[:8]}_{random_part}"


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _slugify(name: str) -> str:
    """Convert a tenant name to a safe lowercase ID (max 32 chars)."""
    slug = "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-")
    # Collapse consecutive dashes
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug[:28]


async def provision_tenant(
    name: str, admin_email: str, plan: str
) -> ProvisionResponse:
    """Create a new tenant with API key, admin user, and default policy.

    Raises ValueError for invalid plan or duplicate tenant ID.
    """
    if plan not in _VALID_PLANS:
        raise ValueError(f"Invalid plan '{plan}'. Must be one of {sorted(_VALID_PLANS)}")

    base_id = _slugify(name)
    if not base_id:
        base_id = "tenant"

    # Find a unique tenant ID by appending a suffix if needed
    tenant_id = base_id
    suffix = 2
    while await db.fetch_one("SELECT id FROM tenants WHERE id = $1", tenant_id):
        tenant_id = f"{base_id}-{suffix}"
        suffix += 1

    api_key = _generate_api_key(tenant_id)
    key_hash = _hash_key(api_key)

    async with db.connection() as conn:
        async with conn.transaction():
            await conn.execute(
                "INSERT INTO tenants (id, name, plan, admin_email, api_key_hash, is_active) "
                "VALUES ($1, $2, $3, $4, $5, TRUE)",
                tenant_id, name, plan, admin_email, key_hash,
            )
            await conn.execute(
                "INSERT INTO tenant_users (tenant_id, external_id, email, department, role) "
                "VALUES ($1, $2, $3, $4, $5)",
                tenant_id, "admin", admin_email, "Admin", "admin",
            )
            await conn.execute(
                "INSERT INTO policies (tenant_id, config, version, is_active, notes) "
                "VALUES ($1, $2::jsonb, $3, TRUE, $4)",
                tenant_id, json.dumps(_DEFAULT_POLICY), "1.0.0",
                "Auto-provisioned default policy",
            )
            # Mint + persist the tenant's DEK in the same transaction so a
            # half-provisioned tenant can never exist without crypto keys.
            await common_tenant_keys.mint_and_store(conn, tenant_id)

    return ProvisionResponse(
        tenant_id=tenant_id,
        api_key=api_key,
        name=name,
        plan=plan,
        admin_email=admin_email,
        message="Tenant provisioned successfully. Store the api_key securely — it will not be shown again.",
    )


async def get_tenant(tenant_id: str) -> Optional[TenantDetail]:
    """Fetch tenant details. Returns None if not found."""
    row = await db.fetch_one(
        "SELECT id, name, plan, admin_email, is_active, settings, created_at "
        "FROM tenants WHERE id = $1",
        tenant_id,
    )
    if not row:
        return None
    settings = row["settings"]
    if isinstance(settings, str):
        settings = json.loads(settings) if settings else {}
    elif settings is None:
        settings = {}
    return TenantDetail(
        id=row["id"],
        name=row["name"],
        plan=row["plan"],
        admin_email=row["admin_email"],
        is_active=row["is_active"],
        settings=settings,
        created_at=row["created_at"].isoformat(),
    )


async def get_usage(tenant_id: str) -> UsageStats:
    """Return aggregated usage counts from audit_logs for the tenant."""
    today_start = "CURRENT_DATE"

    requests_today = await db.fetch_val(
        "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND created_at >= CURRENT_DATE",
        tenant_id,
    ) or 0

    requests_this_month = await db.fetch_val(
        "SELECT COUNT(*) FROM audit_logs "
        "WHERE tenant_id = $1 AND created_at >= date_trunc('month', NOW())",
        tenant_id,
    ) or 0

    blocked_today = await db.fetch_val(
        "SELECT COUNT(*) FROM audit_logs "
        "WHERE tenant_id = $1 AND created_at >= CURRENT_DATE "
        "AND enforcement_action = 'BLOCK'",
        tenant_id,
    ) or 0

    pii_today = await db.fetch_val(
        "SELECT COUNT(*) FROM audit_logs "
        "WHERE tenant_id = $1 AND created_at >= CURRENT_DATE AND pii_detected = TRUE",
        tenant_id,
    ) or 0

    injection_today = await db.fetch_val(
        "SELECT COUNT(*) FROM audit_logs "
        "WHERE tenant_id = $1 AND created_at >= CURRENT_DATE AND injection_score > 0.5",
        tenant_id,
    ) or 0

    return UsageStats(
        tenant_id=tenant_id,
        requests_today=int(requests_today),
        requests_this_month=int(requests_this_month),
        blocked_today=int(blocked_today),
        pii_detections_today=int(pii_today),
        injection_detections_today=int(injection_today),
    )


async def get_sso_config(tenant_id: str) -> Optional[SSOConfig]:
    """Fetch SSO configuration for a tenant. Returns None if tenant not found."""
    row = await db.fetch_one(
        "SELECT workos_org_id, sso_enforced FROM tenants WHERE id = $1",
        tenant_id,
    )
    if not row:
        return None
    return SSOConfig(
        workos_org_id=row["workos_org_id"],
        sso_enforced=bool(row["sso_enforced"]),
    )


async def update_sso_config(
    tenant_id: str,
    *,
    workos_org_id: Optional[str] = None,
    sso_enforced: Optional[bool] = None,
) -> Optional[SSOConfig]:
    """Update SSO configuration. Returns the new config, or None if tenant not found.

    Passing an empty string for ``workos_org_id`` clears it. ``None`` leaves
    each field unchanged.
    """
    row = await db.fetch_one("SELECT id FROM tenants WHERE id = $1", tenant_id)
    if not row:
        return None

    sets = []
    args: list = [tenant_id]
    if workos_org_id is not None:
        args.append(workos_org_id or None)  # empty string → NULL
        sets.append(f"workos_org_id = ${len(args)}")
    if sso_enforced is not None:
        args.append(sso_enforced)
        sets.append(f"sso_enforced = ${len(args)}")

    if sets:
        await db.execute(
            f"UPDATE tenants SET {', '.join(sets)} WHERE id = $1",
            *args,
        )
    return await get_sso_config(tenant_id)


async def get_byok_config(tenant_id: str) -> Optional[ByokConfig]:
    """Return the tenant's BYOK config (None when tenant not found)."""
    row = await db.fetch_one(
        "SELECT t.kms_key_arn, t.kms_key_provider, "
        "       (SELECT kek_id FROM tenant_keys "
        "        WHERE tenant_id = t.id AND is_active = TRUE LIMIT 1) AS kek_fingerprint "
        "FROM tenants t WHERE t.id = $1",
        tenant_id,
    )
    if not row:
        return None
    arn = row["kms_key_arn"]
    return ByokConfig(
        enabled=bool(arn),
        provider=row["kms_key_provider"] if arn else None,
        key_arn=arn,
        kek_fingerprint=row["kek_fingerprint"],
    )


async def update_byok_config(
    tenant_id: str,
    *,
    provider: Optional[str],
    key_arn: Optional[str],
    rotate_now: bool,
) -> Optional[ByokConfig]:
    """Set or clear the tenant's BYOK key and (optionally) rotate the DEK.

    ``key_arn = ""`` disables BYOK and reverts to the platform KEK.
    ``key_arn = None`` leaves the ARN unchanged (useful when the caller
    only wants to flip ``rotate_now``).
    """
    row = await db.fetch_one("SELECT id FROM tenants WHERE id = $1", tenant_id)
    if not row:
        return None

    if key_arn is not None:
        normalized_arn = key_arn.strip() or None
        normalized_provider = (provider or "aws").lower() if normalized_arn else None
        if normalized_arn and normalized_provider not in _VALID_BYOK_PROVIDERS:
            raise ValueError(
                f"BYOK provider '{normalized_provider}' is not supported "
                f"(supported: {sorted(_VALID_BYOK_PROVIDERS)})"
            )
        await db.execute(
            "UPDATE tenants SET kms_key_arn = $2, kms_key_provider = $3 "
            "WHERE id = $1",
            tenant_id, normalized_arn, normalized_provider,
        )
        # Drop the stale per-tenant pin so the next encrypt re-resolves it.
        common_byok.register_tenant_kms(tenant_id, None)

    if rotate_now:
        async with db.connection() as conn:
            await common_tenant_keys.rotate(conn, tenant_id)

    return await get_byok_config(tenant_id)


async def update_settings(tenant_id: str, settings: dict) -> bool:
    """Merge new settings into the tenant's settings JSONB. Returns False if not found."""
    row = await db.fetch_one("SELECT id FROM tenants WHERE id = $1", tenant_id)
    if not row:
        return False

    await db.execute(
        "UPDATE tenants SET settings = settings || $2::jsonb WHERE id = $1",
        tenant_id, json.dumps(settings),
    )
    return True
