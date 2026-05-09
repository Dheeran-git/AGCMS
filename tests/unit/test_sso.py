"""Unit tests for the WorkOS SSO wrapper.

We don't hit WorkOS — we monkeypatch the SDK import so tests are
deterministic and don't require a sandbox org.
"""
from __future__ import annotations

import types

import pytest

from agcms.auth import sso


@pytest.fixture(autouse=True)
def _reset_sso_state(monkeypatch):
    """Clear env + memoized client before each test."""
    for k in ("WORKOS_API_KEY", "WORKOS_CLIENT_ID", "WORKOS_REDIRECT_URI"):
        monkeypatch.delenv(k, raising=False)
    sso.reset_client()
    yield
    sso.reset_client()


class TestIsConfigured:
    def test_unconfigured_when_any_env_missing(self, monkeypatch):
        monkeypatch.setenv("WORKOS_API_KEY", "sk_test")
        # Other two still missing.
        assert sso.is_configured() is False

    def test_configured_when_all_present(self, monkeypatch):
        monkeypatch.setenv("WORKOS_API_KEY", "sk_test")
        monkeypatch.setenv("WORKOS_CLIENT_ID", "client_01")
        monkeypatch.setenv("WORKOS_REDIRECT_URI", "https://agcms.test/v1/auth/sso/callback")
        assert sso.is_configured() is True


class TestAuthorizationUrl:
    def test_unconfigured_raises(self):
        with pytest.raises(sso.SSONotConfigured):
            sso.get_authorization_url("org_01", state="s")

    def test_happy_path_uses_sdk(self, monkeypatch):
        monkeypatch.setenv("WORKOS_API_KEY", "sk_test")
        monkeypatch.setenv("WORKOS_CLIENT_ID", "client_01")
        monkeypatch.setenv("WORKOS_REDIRECT_URI", "https://agcms.test/v1/auth/sso/callback")

        captured: dict = {}

        class _FakeSSO:
            def get_authorization_url(self, *, organization_id, redirect_uri, state):
                captured["organization_id"] = organization_id
                captured["redirect_uri"] = redirect_uri
                captured["state"] = state
                return f"https://api.workos.com/sso/authorize?state={state}"

        class _FakeClient:
            def __init__(self, **kwargs):
                self.sso = _FakeSSO()

        fake_workos = types.ModuleType("workos")
        fake_workos.WorkOSClient = _FakeClient
        monkeypatch.setitem(__import__("sys").modules, "workos", fake_workos)

        url = sso.get_authorization_url("org_01", state="xyz")
        assert url.endswith("state=xyz")
        assert captured["organization_id"] == "org_01"
        assert captured["redirect_uri"] == "https://agcms.test/v1/auth/sso/callback"


class TestCompleteAuthentication:
    def test_profile_is_mapped(self, monkeypatch):
        monkeypatch.setenv("WORKOS_API_KEY", "sk_test")
        monkeypatch.setenv("WORKOS_CLIENT_ID", "client_01")
        monkeypatch.setenv("WORKOS_REDIRECT_URI", "https://agcms.test/callback")

        class _Profile:
            id = "prof_0001"
            organization_id = "org_01"
            email = "alice@hospital.example"
            first_name = "Alice"
            last_name = "Hsu"
            connection_type = "OktaSAML"

        class _ProfileAndToken:
            profile = _Profile()

        class _FakeSSO:
            def get_profile_and_token(self, *, code):
                assert code == "abc123"
                return _ProfileAndToken()

        class _FakeClient:
            def __init__(self, **kwargs):
                self.sso = _FakeSSO()

        fake_workos = types.ModuleType("workos")
        fake_workos.WorkOSClient = _FakeClient
        monkeypatch.setitem(__import__("sys").modules, "workos", fake_workos)

        p = sso.complete_authentication("abc123")
        assert p.sso_subject == "prof_0001"
        assert p.workos_org_id == "org_01"
        assert p.email == "alice@hospital.example"
        assert p.first_name == "Alice"
        assert p.idp_connection_type == "OktaSAML"
