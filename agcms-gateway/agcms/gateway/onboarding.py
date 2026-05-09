"""First-login onboarding wizard — REST API.

Four steps, each of which patches the ``tenants.onboarding_state``
JSONB column:

  1. ``tenant_profile`` — industry, company size, region
  2. ``frameworks``      — compliance frameworks the tenant must satisfy
  3. ``policy_packs``    — which prefab packs to load (auto-suggested)
  4. ``first_call``      — marks a successful first /v1/chat/completions

``completed=true`` is set when step 4 lands. The dashboard reads
``GET /api/v1/onboarding/state`` on every first-mount and routes the
user to the wizard if ``completed`` is not set.

Framework → suggested-pack mapping lives here (single source of truth,
used by the dashboard via ``GET /frameworks``). Adding a new framework
is a two-line change: extend ``FRAMEWORKS`` and the suggested pack id.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import get_current_auth, require_admin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/onboarding", tags=["onboarding"])

_DB_URL = os.environ.get("DATABASE_URL", "")


def _dsn() -> str:
    return _DB_URL.replace("+asyncpg", "")


# ---------------------------------------------------------------------------
# Framework vocabulary. Each entry drives the wizard's "compliance
# frameworks" step AND the suggested pack list on the "policy packs" step.
# Citation URLs are the authoritative regulation sources the dashboard
# links to from violation / report rows (Phase 7.4).
# ---------------------------------------------------------------------------

FRAMEWORKS: dict[str, dict[str, Any]] = {
    "HIPAA": {
        "label": "HIPAA (US healthcare)",
        "suggested_pack": "hipaa",
        "citation_root": "https://www.hhs.gov/hipaa/for-professionals/index.html",
    },
    "GDPR": {
        "label": "GDPR (EU data protection)",
        "suggested_pack": "gdpr",
        "citation_root": "https://gdpr-info.eu/",
    },
    "EU_AI_ACT": {
        "label": "EU AI Act (high-risk systems)",
        "suggested_pack": "eu-ai-act-high-risk",
        "citation_root": "https://artificialintelligenceact.eu/",
    },
    "NIST_AI_RMF": {
        "label": "NIST AI Risk Management Framework",
        "suggested_pack": "nist-ai-rmf",
        "citation_root": "https://www.nist.gov/itl/ai-risk-management-framework",
    },
    "SOC_2": {
        "label": "SOC 2 (Trust Services Criteria)",
        "suggested_pack": "soc2-cc",
        "citation_root": "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
    },
    "PCI_DSS": {
        "label": "PCI DSS (payment card)",
        "suggested_pack": "pci-dss",
        "citation_root": "https://www.pcisecuritystandards.org/",
    },
}

INDUSTRIES = [
    "banking", "healthcare", "legal", "insurance", "government",
    "retail", "tech", "education", "manufacturing", "other",
]
COMPANY_SIZES = ["1-10", "11-50", "51-200", "201-1000", "1001-5000", "5000+"]
REGIONS = ["us", "eu", "uk", "apac", "latam", "mea"]


# ---------------------------------------------------------------------------
# Wire-level models
# ---------------------------------------------------------------------------


class TenantProfileStep(BaseModel):
    industry: str
    company_size: str
    region: str

    @field_validator("industry")
    @classmethod
    def _industry_in_vocab(cls, v: str) -> str:
        if v not in INDUSTRIES:
            raise ValueError(f"industry must be one of {INDUSTRIES}")
        return v

    @field_validator("company_size")
    @classmethod
    def _size_in_vocab(cls, v: str) -> str:
        if v not in COMPANY_SIZES:
            raise ValueError(f"company_size must be one of {COMPANY_SIZES}")
        return v

    @field_validator("region")
    @classmethod
    def _region_in_vocab(cls, v: str) -> str:
        if v not in REGIONS:
            raise ValueError(f"region must be one of {REGIONS}")
        return v


class FrameworksStep(BaseModel):
    selected: list[str] = Field(..., min_length=1)

    def validate_all(self) -> None:
        unknown = [f for f in self.selected if f not in FRAMEWORKS]
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown framework(s): {', '.join(unknown)}",
            )


class PolicyPacksStep(BaseModel):
    packs: list[str] = Field(..., min_length=1)


class FirstCallStep(BaseModel):
    interaction_id: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _load_state(conn: asyncpg.Connection, tenant_id: str) -> dict[str, Any]:
    row = await conn.fetchrow(
        "SELECT onboarding_state FROM tenants WHERE id = $1",
        tenant_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    raw = row["onboarding_state"]
    # asyncpg returns JSONB as str or dict depending on codec registration.
    return json.loads(raw) if isinstance(raw, str) else (raw or {})


async def _save_state(
    conn: asyncpg.Connection,
    tenant_id: str,
    state: dict[str, Any],
) -> None:
    await conn.execute(
        "UPDATE tenants SET onboarding_state = $2::jsonb WHERE id = $1",
        tenant_id,
        json.dumps(state),
    )


def _mark_completed(state: dict[str, Any]) -> dict[str, Any]:
    """Flip ``completed`` once every required step is present."""
    required = {"tenant_profile", "frameworks", "policy_packs", "first_call"}
    state["completed"] = required.issubset(state.keys())
    return state


def _suggested_packs(frameworks: list[str]) -> list[str]:
    out: list[str] = []
    for f in frameworks:
        pack = FRAMEWORKS.get(f, {}).get("suggested_pack")
        if pack and pack not in out:
            out.append(pack)
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/catalog")
async def get_catalog() -> dict[str, Any]:
    """Static catalog the wizard renders. Unauthenticated — it's static."""
    return {
        "industries": INDUSTRIES,
        "company_sizes": COMPANY_SIZES,
        "regions": REGIONS,
        "frameworks": [
            {"id": k, **v} for k, v in FRAMEWORKS.items()
        ],
    }


@router.get("/state")
async def get_state(ctx: AuthContext = Depends(get_current_auth)) -> dict[str, Any]:
    conn = await asyncpg.connect(_dsn())
    try:
        state = await _load_state(conn, ctx.tenant_id)
    finally:
        await conn.close()
    return {"state": state, "completed": bool(state.get("completed"))}


@router.post("/tenant-profile", dependencies=[Depends(require_admin)])
async def set_tenant_profile(
    step: TenantProfileStep,
    ctx: AuthContext = Depends(get_current_auth),
) -> dict[str, Any]:
    conn = await asyncpg.connect(_dsn())
    try:
        state = await _load_state(conn, ctx.tenant_id)
        state["tenant_profile"] = step.model_dump()
        state = _mark_completed(state)
        await _save_state(conn, ctx.tenant_id, state)
    finally:
        await conn.close()
    return {"state": state}


@router.post("/frameworks", dependencies=[Depends(require_admin)])
async def set_frameworks(
    step: FrameworksStep,
    ctx: AuthContext = Depends(get_current_auth),
) -> dict[str, Any]:
    step.validate_all()
    conn = await asyncpg.connect(_dsn())
    try:
        state = await _load_state(conn, ctx.tenant_id)
        state["frameworks"] = step.selected
        # Recompute suggested packs whenever frameworks change so the UI
        # step-3 default is always consistent with step 2.
        state["suggested_packs"] = _suggested_packs(step.selected)
        state = _mark_completed(state)
        await _save_state(conn, ctx.tenant_id, state)
    finally:
        await conn.close()
    return {"state": state, "suggested_packs": state["suggested_packs"]}


@router.post("/policy-packs", dependencies=[Depends(require_admin)])
async def set_policy_packs(
    step: PolicyPacksStep,
    ctx: AuthContext = Depends(get_current_auth),
) -> dict[str, Any]:
    conn = await asyncpg.connect(_dsn())
    try:
        state = await _load_state(conn, ctx.tenant_id)
        state["policy_packs"] = step.packs
        state = _mark_completed(state)
        await _save_state(conn, ctx.tenant_id, state)
    finally:
        await conn.close()
    return {"state": state}


@router.post("/first-call", dependencies=[Depends(require_admin)])
async def record_first_call(
    step: FirstCallStep,
    ctx: AuthContext = Depends(get_current_auth),
) -> dict[str, Any]:
    conn = await asyncpg.connect(_dsn())
    try:
        state = await _load_state(conn, ctx.tenant_id)
        state["first_call"] = {"interaction_id": step.interaction_id}
        state = _mark_completed(state)
        await _save_state(conn, ctx.tenant_id, state)
    finally:
        await conn.close()
    return {"state": state}


@router.post("/reset", dependencies=[Depends(require_admin)])
async def reset_state(ctx: AuthContext = Depends(get_current_auth)) -> dict[str, Any]:
    """Escape hatch for dev/demo — clear everything and re-run the wizard."""
    conn = await asyncpg.connect(_dsn())
    try:
        await _save_state(conn, ctx.tenant_id, {})
    finally:
        await conn.close()
    return {"state": {}}
