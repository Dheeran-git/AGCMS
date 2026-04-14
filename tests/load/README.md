# AGCMS Load Testing

Framework: [Locust](https://locust.io)  
Target: 500 req/s sustained, p95 < 2s, error rate < 1%

---

## Prerequisites

```bash
pip install locust==2.24.0
# Docker stack must be running:
docker compose up -d --wait
```

---

## Quick Run (50 users, 30 seconds — local validation)

```bash
locust -f tests/load/locustfile.py \
  --host=http://localhost:8000 \
  --users=50 \
  --spawn-rate=5 \
  --run-time=30s \
  --headless
```

Expected output:
```
Type     Name                      # reqs  # fails  Avg  Min  Max  RPS
POST     /v1/chat/completions       1500      0     310   95  890  50.0
...
Failures: 0 (0.00%)
```

---

## Full Load Test (200 users, 2 minutes)

```bash
locust -f tests/load/locustfile.py \
  --host=http://localhost:8000 \
  --users=200 \
  --spawn-rate=20 \
  --run-time=120s \
  --headless \
  --csv=tests/load/results/$(date +%Y%m%d_%H%M%S)
```

Results written to `tests/load/results/` as CSV files.

---

## Web UI Mode (interactive)

```bash
locust -f tests/load/locustfile.py --host=http://localhost:8000
# Open http://localhost:8089 in browser
# Set: Number of users = 200, Spawn rate = 20
```

---

## Task Distribution

| Task | Weight | Description |
|------|--------|-------------|
| Clean prompt | 60% | Benign messages — expect ALLOW + 200 |
| PII prompt | 20% | Prompts containing SSN/email — expect REDACT or BLOCK |
| Injection prompt | 20% | Canonical jailbreak phrases — expect BLOCK (403) or ESCALATE |

---

## Performance Targets

| Metric | Target | Acceptable |
|--------|--------|------------|
| p50 response time | < 500ms | < 800ms |
| p95 response time | < 2000ms | < 3500ms |
| p99 response time | < 5000ms | — |
| Error rate (5xx) | < 0.1% | < 1% |
| Throughput | 500 req/s | 200 req/s |

> Groq API latency dominates the total. LLM calls add ~800ms p50. Local Ollama can be used as a zero-latency mock for pure gateway throughput benchmarking.

---

## Interpreting Results

**If error rate > 1%:** Check gateway logs (`docker compose logs gateway`) for:
- `asyncpg.TooManyConnectionsError` — increase `asyncpg.create_pool` max_size
- `httpx.ConnectTimeout` — injection or PII service overloaded; scale replicas
- `429` from Groq — rate limit hit; add exponential backoff or reduce users

**If p95 > 2s:** Profile which service is the bottleneck:
- PII service: `docker compose stats pii` — if CPU > 80%, scale or switch to `en_core_web_sm`
- Injection service: DeBERTa inference is CPU-bound; scale horizontally or set `AGCMS_ML_ENABLED=false`
- Database: Check `pg_stat_activity` for long-running queries

---

## CPU Expectations at 200 Concurrent Users

| Service | Expected CPU |
|---------|-------------|
| gateway | ~30–40% (1 core) |
| pii (sm model) | ~50–60% (1 core) |
| injection (ONNX) | ~70–85% (1 core) |
| response | ~15% |
| policy | ~10% |
| audit | ~20% |
| postgres | ~25% |
