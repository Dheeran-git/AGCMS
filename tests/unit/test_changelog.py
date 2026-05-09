"""Tests for the public changelog API."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def changelog_file(tmp_path: Path, monkeypatch) -> Path:
    p = tmp_path / "CHANGELOG.md"
    p.write_text(
        "# AGCMS Changelog\n\n"
        "## [1.1.0] — 2026-04-22\n\n"
        "### Added\n"
        "- Trust Center page at `/trust`.\n"
        "- Real-time SSE feed.\n"
        "\n"
        "### Fixed\n"
        "- Onboarding redirect loop on first login.\n"
        "\n"
        "## [1.0.0] — 2026-04-01\n\n"
        "Initial public release.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGCMS_CHANGELOG_PATH", str(p))
    return p


@pytest.fixture
def client(changelog_file: Path) -> TestClient:
    # Reload to pick up the env var.
    import importlib

    import agcms.gateway.changelog as cl
    importlib.reload(cl)
    app = FastAPI()
    app.include_router(cl.router)
    return TestClient(app)


def test_changelog_returns_parsed_entries(client: TestClient) -> None:
    resp = client.get("/api/v1/changelog")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["version"] == "1.1.0"
    assert data[0]["date"] == "2026-04-22"
    labels = [s["label"] for s in data[0]["sections"]]
    assert labels == ["Added", "Fixed"]
    added_items = data[0]["sections"][0]["items"]
    assert "Trust Center page at `/trust`." in added_items
    assert "Real-time SSE feed." in added_items


def test_changelog_latest_returns_top_entry(client: TestClient) -> None:
    resp = client.get("/api/v1/changelog/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == "1.1.0"


def test_changelog_missing_file_returns_empty(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AGCMS_CHANGELOG_PATH", str(tmp_path / "does-not-exist.md"))
    import importlib

    import agcms.gateway.changelog as cl
    importlib.reload(cl)
    app = FastAPI()
    app.include_router(cl.router)
    c = TestClient(app)
    assert c.get("/api/v1/changelog").json() == []
    assert c.get("/api/v1/changelog/latest").json() is None
