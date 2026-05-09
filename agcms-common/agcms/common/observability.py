"""Shared observability wiring for every AGCMS service.

A single helper, :func:`init_observability`, is called once per service
in its ``main.py`` after ``app = FastAPI(...)``. It gives us:

* Prometheus exposition at ``/metrics``
* Per-request counters + latency histogram, labelled by service, route,
  method, status and tenant when available
* Business metrics that the gateway/audit/pii/injection services
  increment directly via the ``metrics`` registry exported below
* OpenTelemetry tracing via OTLP when ``OTEL_EXPORTER_OTLP_ENDPOINT``
  is set; auto-instruments FastAPI, httpx and asyncpg

All external dependencies (prometheus_client, opentelemetry-*) are
optional — if the import fails we log once and no-op. This keeps the
observability layer from ever becoming a hard requirement for dev.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prometheus metrics registry — imported lazily so that services which have
# not yet installed ``prometheus_client`` still start. We expose a small
# facade the rest of the codebase talks to; if the dependency is missing the
# facade methods are no-ops.
# ---------------------------------------------------------------------------

class _NoopMetric:
    def labels(self, *_a, **_kw):
        return self

    def inc(self, *_a, **_kw):
        return None

    def observe(self, *_a, **_kw):
        return None

    def set(self, *_a, **_kw):
        return None


class _Metrics:
    """Facade around prometheus_client; falls back to no-ops if missing."""

    def __init__(self) -> None:
        self._enabled = False
        self.request_count = _NoopMetric()
        self.request_latency = _NoopMetric()
        self.enforcement_action = _NoopMetric()
        self.pii_detected = _NoopMetric()
        self.injection_detected = _NoopMetric()
        self.rate_limit_rejected = _NoopMetric()
        self.audit_chain_write = _NoopMetric()

    def enable(self) -> None:
        if self._enabled:
            return
        try:
            from prometheus_client import Counter, Histogram
        except ImportError:
            log.info("prometheus_client not installed — metrics disabled")
            return

        self.request_count = Counter(
            "agcms_request_count",
            "Total HTTP requests handled",
            ["service", "route", "method", "status", "tenant"],
        )
        self.request_latency = Histogram(
            "agcms_request_latency_seconds",
            "HTTP request latency",
            ["service", "route", "method"],
            buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )
        self.enforcement_action = Counter(
            "agcms_enforcement_action_count",
            "Policy enforcement actions taken",
            ["tenant", "action"],
        )
        self.pii_detected = Counter(
            "agcms_pii_detected_count",
            "Prompts flagged as containing PII",
            ["tenant", "category"],
        )
        self.injection_detected = Counter(
            "agcms_injection_detected_count",
            "Prompts flagged as injection attempts",
            ["tenant", "technique"],
        )
        self.rate_limit_rejected = Counter(
            "agcms_rate_limit_rejected_count",
            "Requests rejected by rate-limit tier",
            ["tier"],  # "tenant" or "ip"
        )
        self.audit_chain_write = Histogram(
            "agcms_audit_chain_write_seconds",
            "Time spent appending to the per-tenant audit hash chain",
            ["tenant"],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        )
        self._enabled = True


metrics = _Metrics()


# ---------------------------------------------------------------------------
# Middleware — counts requests + records latency. Extracts tenant id from
# request.state when authentication middleware has set it.
# ---------------------------------------------------------------------------

def _install_request_middleware(app, service_name: str) -> None:
    @app.middleware("http")
    async def _agcms_metrics_mw(request, call_next):  # type: ignore[misc]
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed = time.perf_counter() - start
            # FastAPI stores the matched route on the scope; fall back to
            # the raw path if no route matched (404s, 401 middleware exits).
            route = request.scope.get("route")
            route_path = getattr(route, "path", None) or request.url.path
            tenant_id = getattr(request.state, "tenant_id", "unknown") or "unknown"
            metrics.request_count.labels(
                service=service_name,
                route=route_path,
                method=request.method,
                status=str(status_code),
                tenant=tenant_id,
            ).inc()
            metrics.request_latency.labels(
                service=service_name,
                route=route_path,
                method=request.method,
            ).observe(elapsed)


def _install_metrics_endpoint(app) -> None:
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    except ImportError:
        return

    from fastapi import Response

    @app.get("/metrics", include_in_schema=False)
    async def _metrics_endpoint() -> Response:
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )


def _install_tracing(app, service_name: str) -> None:
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.info("opentelemetry packages not installed — tracing disabled")
        return

    provider = TracerProvider(
        resource=Resource.create({SERVICE_NAME: f"agcms-{service_name}"}),
    )
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True)),
    )
    trace.set_tracer_provider(provider)

    FastAPIInstrumentor.instrument_app(app)
    # httpx + asyncpg instrumentation is process-wide; safe to call multiple
    # times because the libraries guard against double-instrumentation.
    try:
        HTTPXClientInstrumentor().instrument()
    except Exception:  # noqa: BLE001 — never break startup on instrument fail
        log.exception("httpx instrumentation failed")
    try:
        AsyncPGInstrumentor().instrument()
    except Exception:  # noqa: BLE001
        log.exception("asyncpg instrumentation failed")


def init_observability(app, service_name: str) -> None:
    """Wire /metrics, per-request Prometheus counters, and OTel tracing.

    Call once after ``app = FastAPI(...)``. Safe to call when the optional
    dependencies are missing — the corresponding features just no-op.
    """
    if os.environ.get("AGCMS_OBSERVABILITY_DISABLED") == "1":
        return

    metrics.enable()
    _install_metrics_endpoint(app)
    _install_request_middleware(app, service_name)
    _install_tracing(app, service_name)


__all__ = ["init_observability", "metrics"]
