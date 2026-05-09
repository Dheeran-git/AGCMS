"""Unit tests for agcms.common.observability.

Verifies the shared init_observability() helper exposes /metrics,
labels request counters with the mounted route + status, picks up
tenant context from request.state, and leaves business metrics in
a working state (no _NoopMetric for prometheus_client-equipped envs).
"""

from __future__ import annotations

import importlib

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


@pytest.fixture
def fresh_module(monkeypatch):
    """Reload the module so each test gets a fresh Counter/Histogram registry."""
    import prometheus_client

    # Clear the default registry so re-initialising doesn't double-register.
    for collector in list(prometheus_client.REGISTRY._collector_to_names.keys()):
        try:
            prometheus_client.REGISTRY.unregister(collector)
        except KeyError:
            pass

    mod = importlib.import_module("agcms.common.observability")
    importlib.reload(mod)
    return mod


def _make_app(mod, service_name="test-svc"):
    app = FastAPI()

    @app.get("/hello/{name}")
    async def _hello(name: str, request: Request):
        # Simulate auth middleware stashing tenant on the request.
        request.state.tenant_id = "tenant-xyz"
        return {"msg": f"hi {name}"}

    @app.get("/boom")
    async def _boom(request: Request):
        request.state.tenant_id = "tenant-xyz"
        raise RuntimeError("kaboom")

    mod.init_observability(app, service_name)
    return app


class TestMetricsEndpoint:
    def test_metrics_endpoint_exposed(self, fresh_module):
        app = _make_app(fresh_module)
        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "agcms_request_count" in resp.text

    def test_metrics_endpoint_has_content_type(self, fresh_module):
        app = _make_app(fresh_module)
        client = TestClient(app)
        resp = client.get("/metrics")
        # Prometheus exposition format content-type.
        assert resp.headers["content-type"].startswith("text/plain")


class TestRequestCounters:
    def test_successful_request_is_counted_with_tenant(self, fresh_module):
        app = _make_app(fresh_module)
        client = TestClient(app)

        r = client.get("/hello/alice")
        assert r.status_code == 200

        metrics_text = client.get("/metrics").text
        # The counter line contains route, method, status, tenant labels.
        assert 'route="/hello/{name}"' in metrics_text
        assert 'method="GET"' in metrics_text
        assert 'status="200"' in metrics_text
        assert 'tenant="tenant-xyz"' in metrics_text
        assert 'service="test-svc"' in metrics_text

    def test_failed_request_records_500(self, fresh_module):
        app = _make_app(fresh_module)
        client = TestClient(app, raise_server_exceptions=False)

        r = client.get("/boom")
        assert r.status_code == 500

        metrics_text = client.get("/metrics").text
        # The failing route should be counted under status=500.
        assert 'route="/boom"' in metrics_text
        assert 'status="500"' in metrics_text

    def test_unmatched_path_is_counted_as_raw_path(self, fresh_module):
        app = _make_app(fresh_module)
        client = TestClient(app)

        r = client.get("/does/not/exist")
        assert r.status_code == 404

        metrics_text = client.get("/metrics").text
        # No matched route, so we fall back to the raw URL path.
        assert 'route="/does/not/exist"' in metrics_text


class TestLatencyHistogram:
    def test_latency_histogram_observes_request(self, fresh_module):
        app = _make_app(fresh_module)
        client = TestClient(app)

        client.get("/hello/bob")
        metrics_text = client.get("/metrics").text
        assert "agcms_request_latency_seconds_bucket" in metrics_text
        assert "agcms_request_latency_seconds_count" in metrics_text
        assert "agcms_request_latency_seconds_sum" in metrics_text


class TestBusinessMetrics:
    def test_enforcement_counter_can_be_incremented(self, fresh_module):
        # Ensure metrics were enabled so this is a real Counter, not _NoopMetric.
        fresh_module.metrics.enable()
        fresh_module.metrics.enforcement_action.labels(
            tenant="t1",
            action="BLOCK",
        ).inc()
        # The real prometheus_client Counter exposes a `._value` Value proxy.
        samples = list(
            fresh_module.metrics.enforcement_action.collect()[0].samples,
        )
        assert any(
            s.labels == {"tenant": "t1", "action": "BLOCK"}
            and s.value == 1.0
            and s.name == "agcms_enforcement_action_count_total"
            for s in samples
        )

    def test_rate_limit_rejected_counter(self, fresh_module):
        fresh_module.metrics.enable()
        fresh_module.metrics.rate_limit_rejected.labels(tier="tenant").inc()
        fresh_module.metrics.rate_limit_rejected.labels(tier="ip").inc(3)
        samples = list(fresh_module.metrics.rate_limit_rejected.collect()[0].samples)
        by_tier = {
            s.labels["tier"]: s.value
            for s in samples
            if s.name.endswith("_total")
        }
        assert by_tier["tenant"] == 1.0
        assert by_tier["ip"] == 3.0

    def test_audit_chain_write_histogram(self, fresh_module):
        fresh_module.metrics.enable()
        fresh_module.metrics.audit_chain_write.labels(tenant="t1").observe(0.005)
        fresh_module.metrics.audit_chain_write.labels(tenant="t1").observe(0.02)
        samples = list(fresh_module.metrics.audit_chain_write.collect()[0].samples)
        # Count sample must record the two observations.
        count_samples = [s for s in samples if s.name.endswith("_count")]
        assert count_samples
        assert count_samples[0].value == 2.0


class TestDisableFlag:
    def test_disabled_env_short_circuits(self, fresh_module, monkeypatch):
        monkeypatch.setenv("AGCMS_OBSERVABILITY_DISABLED", "1")
        app = FastAPI()
        fresh_module.init_observability(app, "skipme")
        client = TestClient(app)
        # No /metrics endpoint registered when disabled.
        assert client.get("/metrics").status_code == 404
