"""Shared helpers for the management API routers."""

import json
import os
from datetime import datetime
from typing import Any

import httpx
from fastapi import HTTPException

_DB_URL = os.environ.get("DATABASE_URL", "")
AUTH_URL = os.environ.get("AUTH_SERVICE_URL", "http://auth:8006")
TENANT_URL = os.environ.get("TENANT_SERVICE_URL", "http://tenant:8007")
AUDIT_URL = os.environ.get("AUDIT_SERVICE_URL", "http://audit:8005")
POLICY_URL = os.environ.get("POLICY_SERVICE_URL", "http://policy:8004")


def db_dsn() -> str:
    return _DB_URL.replace("+asyncpg", "")


def passthrough(resp: httpx.Response):
    """Return upstream response as JSON, preserving status code."""
    try:
        data = resp.json()
    except Exception:
        data = {"detail": resp.text}
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=data.get("detail", data))
    return data


def csv_safe(value: Any) -> str:
    """Flatten lists/dicts/None for CSV."""
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def parse_ts(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid timestamp: {s}")
