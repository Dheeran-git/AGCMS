# AGCMS load test

Locust script that drives the gateway with a 60/20/20 mix of clean, PII and
injection prompts plus health and stats calls. Clean prompts reach the real
LLM provider, so throughput is bounded by the provider's free-tier rate limit
and 429/502 from the provider count as success (the gateway handled them).
Injection prompts must return 403.

```bash
pip install locust
docker compose up -d --wait
locust -f tests/load/locustfile.py --host=http://localhost:8000   --users=10 --spawn-rate=2 --run-time=60s --headless
```

Governance-only mode sends prompts that are blocked before the LLM call
(critical PII, injections), so latency reflects the scan pipeline and the
signed audit write, not a provider's quota. Raise the limiter first:

```bash
AGCMS_TENANT_RPM=100000 AGCMS_GLOBAL_IP_RPM=100000 docker compose up -d gateway
AGCMS_LOAD_MIX=governance locust -f tests/load/locustfile.py --host=http://localhost:8000   --users=25 --spawn-rate=5 --run-time=60s --headless
docker compose up -d gateway      # restores the default limits
```

Add `--csv=tests/load/results/<stamp>` to keep the raw numbers. Measured
results, with the machine used, are recorded in `docs/evaluation.md`; do not
quote numbers that are not in that file.
