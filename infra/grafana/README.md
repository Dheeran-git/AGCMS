# AGCMS observability stack

This directory ships Prometheus + Grafana configuration for the AGCMS
platform. Every AGCMS service exposes `/metrics` via
`agcms.common.observability.init_observability()`, so any
Prometheus-compatible scraper will pick them up.

## Dashboards

Three provisioned dashboards land in the `AGCMS` folder on first boot:

- **Ops Health** — per-service request rate, latency percentiles,
  error rate, rate-limit rejections. First stop during an incident.
- **Enforcement Overview** — BLOCK / REDACT / ESCALATE / ALLOW mix,
  PII categories, injection techniques, per tenant.
- **Audit Integrity** — per-tenant chain-write throughput + latency
  percentiles + heatmap. A bump here is the earliest warning that a
  hot tenant is contending on the chain-extend row lock.

## Local bring-up

Add the following to `docker-compose.yml` (or a dev override file) to
run Prometheus + Grafana alongside the AGCMS services:

```yaml
  prometheus:
    image: prom/prometheus:v2.54.1
    volumes:
      - ./infra/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:11.2.0
    environment:
      GF_AUTH_ANONYMOUS_ENABLED: "true"
      GF_AUTH_ANONYMOUS_ORG_ROLE: Viewer
    volumes:
      - ./infra/grafana/provisioning:/etc/grafana/provisioning:ro
      - ./infra/grafana/dashboards:/etc/grafana/dashboards:ro
    ports:
      - "3001:3000"
```

Then browse to `http://localhost:3001` and look for the AGCMS folder.

## Tracing

Set `OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317` on any service to
ship spans to a local Jaeger. The helper auto-instruments FastAPI,
httpx, and asyncpg — no per-call code changes required.
