"""AGCMS Management REST API — /api/v1 aggregator.

Endpoint groups live in ``agcms.gateway.api`` (one module each) and are
mounted here under a single prefix. All DB queries filter by
``ctx.tenant_id`` for tenant isolation.
"""

import asyncio  # noqa: F401  (tests patch agcms.gateway.management_api.asyncio.sleep)
import asyncpg  # noqa: F401  (tests patch ...management_api.asyncpg.connect)
import httpx  # noqa: F401  (tests patch ...management_api.httpx.AsyncClient)
from fastapi import APIRouter

from agcms.gateway.api import (
    audit,
    auth_proxy,
    escalations,
    policy,
    reports,
    stats,
    stream,
    tenant_proxy,
    users,
)

router = APIRouter(prefix="/api/v1", tags=["management"])
for module in (auth_proxy, audit, policy, users, escalations, stats, tenant_proxy, reports, stream):
    router.include_router(module.router)
