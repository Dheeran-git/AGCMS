"""Database helpers for the AGCMS Tenant Management Service."""

import os
from typing import Optional

import asyncpg


def _database_url() -> str:
    return os.environ.get("DATABASE_URL", "")


async def fetch_one(query: str, *args) -> Optional[dict]:
    """Execute a query and return the first row as a dict, or None."""
    conn = await asyncpg.connect(_database_url())
    try:
        row = await conn.fetchrow(query, *args)
        return dict(row) if row else None
    finally:
        await conn.close()


async def execute(query: str, *args) -> str:
    """Execute a write query (INSERT/UPDATE/DELETE). Returns status string."""
    conn = await asyncpg.connect(_database_url())
    try:
        return await conn.execute(query, *args)
    finally:
        await conn.close()


async def fetch_val(query: str, *args):
    """Execute a query and return a single scalar value."""
    conn = await asyncpg.connect(_database_url())
    try:
        return await conn.fetchval(query, *args)
    finally:
        await conn.close()
