"""Connections and background tasks the request hot path shares (opened in the lifespan).

Building an ``httpx.AsyncClient`` per call loads a fresh TLS context (about
20 ms of event-loop CPU) and an ``asyncpg.connect`` per API-key lookup pays a
TCP and SCRAM handshake; done per request, the two capped a single gateway
worker at about 5 governed requests per second.
"""

import asyncio
from typing import Optional

import asyncpg
import httpx

from agcms.gateway.api.common import db_dsn

http: Optional[httpx.AsyncClient] = None
pool: Optional[asyncpg.Pool] = None


async def open_all() -> None:
    """Open the shared HTTP client (internal services) and the Postgres pool."""
    global http, pool
    http = httpx.AsyncClient(timeout=10.0)
    pool = await asyncpg.create_pool(db_dsn(), min_size=1, max_size=10)


async def close_all() -> None:
    global http, pool
    if http is not None:
        await http.aclose()
    if pool is not None:
        await pool.close()
    http, pool = None, None


# The event loop keeps only weak references to tasks, so a fire-and-forget
# task with no other reference can be garbage-collected before it finishes.
_background: set[asyncio.Task] = set()


def fire_and_forget(coro) -> None:
    """Run ``coro`` in the background, holding a reference until it is done."""
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)
