"""Tests for the OpenAPI export endpoints (Phase 8.1).

Verifies:
  - /openapi.yaml returns valid YAML with the AGCMS-specific normalisation
  - /.well-known/openapi returns the same spec as JSON
  - Server URL is honoured from AGCMS_PUBLIC_URL
  - Spec contains the public ingest path /v1/chat/completions

The spec generator is exercised against a mini FastAPI app to keep the
test hermetic — wiring the full gateway would pull in DB/Redis init.
"""

from __future__ import annotations

import importlib

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app(monkeypatch) -> FastAPI:
    monkeypatch.setenv("AGCMS_PUBLIC_URL", "https://api.example.com")
    monkeypatch.setenv("AGCMS_API_VERSION", "1.2.3")

    # Reload to pick up env at import time.
    import agcms.gateway.openapi_export as oe
    importlib.reload(oe)

    app = FastAPI(title="placeholder", version="0.0.0")

    @app.post("/v1/chat/completions")
    async def chat() -> dict:  # pragma: no cover - signature-only
        return {}

    oe.install(app)
    return app


def test_openapi_yaml_returns_valid_yaml(monkeypatch):
    app = _build_app(monkeypatch)
    client = TestClient(app)

    resp = client.get("/openapi.yaml")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/yaml")

    spec = yaml.safe_load(resp.text)
    assert spec["info"]["title"] == "AGCMS Gateway API"
    assert spec["info"]["version"] == "1.2.3"
    assert spec["servers"][0]["url"] == "https://api.example.com"
    assert "/v1/chat/completions" in spec["paths"]


def test_openapi_discovery_returns_json(monkeypatch):
    app = _build_app(monkeypatch)
    client = TestClient(app)

    resp = client.get("/.well-known/openapi")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")

    spec = resp.json()
    assert spec["info"]["title"] == "AGCMS Gateway API"
    assert spec["servers"][0]["url"] == "https://api.example.com"
