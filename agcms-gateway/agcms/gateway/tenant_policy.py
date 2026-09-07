"""Active tenant policy for the request path.

The policy service resolves against whatever ``policy`` dict it is given,
falling back to its built-in default when none is supplied. The gateway
therefore has to send the tenant's active policy row on every request, or
policies deployed from the dashboard would never be enforced. Rows are
cached per tenant for a few seconds; ``PUT /api/v1/policy`` invalidates.
"""

import json
import os
import time
from typing import Optional

import asyncpg

from agcms.gateway.api.common import db_dsn

_TTL = float(os.environ.get("AGCMS_POLICY_CACHE_SECONDS", "10"))
_cache: dict[str, tuple[float, Optional[dict]]] = {}


async def active_policy(tenant_id: str) -> Optional[dict]:
    """Return the tenant's active policy config, or None if it has none."""
    now = time.monotonic()
    hit = _cache.get(tenant_id)
    if hit and hit[0] > now:
        return hit[1]
    conn = await asyncpg.connect(db_dsn())
    try:
        row = await conn.fetchrow(
            "SELECT config FROM policies WHERE tenant_id = $1 AND is_active = TRUE "
            "ORDER BY created_at DESC LIMIT 1",
            tenant_id,
        )
    finally:
        await conn.close()
    config = row["config"] if row else None
    if isinstance(config, str):
        config = json.loads(config)
    _cache[tenant_id] = (now + _TTL, config)
    return config


def invalidate(tenant_id: str) -> None:
    _cache.pop(tenant_id, None)
