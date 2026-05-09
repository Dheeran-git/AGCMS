"""Stable OpenAPI 3.1 export for the AGCMS gateway.

FastAPI auto-generates a spec at ``/openapi.json``. This module:
  * Normalizes the spec (stable title, version pin, server URL from env)
  * Exposes ``/openapi.yaml`` (the canonical artifact for SDK codegen + docs)
  * Exposes ``/.well-known/openapi`` for discovery

Env knobs:
  AGCMS_PUBLIC_URL    Server URL advertised in the spec (default: http://localhost:8000)
  AGCMS_API_VERSION   Override version string (default: app.version)
"""

from __future__ import annotations

import os
from typing import Any

import yaml
from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse, Response

router = APIRouter(tags=["spec"])

_PUBLIC_URL = os.environ.get("AGCMS_PUBLIC_URL", "http://localhost:8000")
_API_VERSION = os.environ.get("AGCMS_API_VERSION")


def _spec(app: FastAPI) -> dict[str, Any]:
    spec = app.openapi()
    spec["info"] = {
        **spec.get("info", {}),
        "title": "AGCMS Gateway API",
        "version": _API_VERSION or app.version,
        "description": (
            "AI Governance & Compliance Monitoring System — public API surface. "
            "Cryptographically signed audit, multi-tenant RBAC, OpenAI-compatible "
            "ingest at /v1/chat/completions."
        ),
        "contact": {
            "name": "AGCMS",
            "url": "https://agcms.com",
            "email": "support@agcms.com",
        },
        "license": {"name": "Commercial", "url": "https://agcms.com/legal"},
    }
    spec["servers"] = [{"url": _PUBLIC_URL, "description": "AGCMS gateway"}]
    return spec


def install(app: FastAPI) -> None:
    """Mount the OpenAPI export endpoints onto a FastAPI app."""

    @router.get(
        "/openapi.yaml",
        summary="OpenAPI 3.1 spec (YAML)",
        response_class=Response,
        responses={200: {"content": {"application/yaml": {}}}},
    )
    async def openapi_yaml() -> Response:
        text = yaml.safe_dump(_spec(app), sort_keys=False)
        return Response(content=text, media_type="application/yaml")

    @router.get(
        "/.well-known/openapi",
        summary="OpenAPI discovery (JSON)",
        response_class=JSONResponse,
    )
    async def openapi_discovery() -> JSONResponse:
        return JSONResponse(_spec(app))

    app.include_router(router)
