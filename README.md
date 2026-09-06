# AGCMS — AI Governance and Compliance Monitoring System

A governance proxy for enterprise LLM use. AGCMS sits between client
applications and any OpenAI-compatible LLM provider. On every request it
detects PII, scores prompt-injection risk, resolves a per-tenant policy
(allow / redact / block / escalate), checks the LLM response, and writes a
tamper-evident, hash-chained audit record. A React dashboard gives
compliance teams live visibility.

RV College of Engineering, Centre for Healthcare Technology and Research.
Unisys Innovation Program Y17.

## Architecture

```
Client -> Gateway (:8000) -> PII (:8001) + Injection (:8002) in parallel
                          -> Policy (:8004) -> LLM provider
                          -> Response check (:8003)
                          -> Audit (:8005, HMAC-SHA256 hash chain per tenant)
Dashboard (:3000) <- Gateway management API <- PostgreSQL (RLS) + Redis
Auth (:8006) issues JWTs; Tenant (:8007) provisions tenants + API keys.
```

| Service | Role |
|---|---|
| `agcms-gateway` | OpenAI-compatible proxy, auth, rate limits, management API, SSE feed |
| `agcms-pii` | 20 regex patterns + spaCy NER, masking, risk level |
| `agcms-injection` | 20 heuristic rules across 6 attack classes + DeBERTa ONNX classifier |
| `agcms-response` | PII echo, system-prompt leak and restricted-topic checks on LLM output |
| `agcms-policy` | YAML policy DSL, validator, enforcement resolver |
| `agcms-audit` | Hash-chained HMAC audit log, per-row and whole-chain verification |
| `agcms-auth` / `agcms-tenant` | JWT issuance, tenant provisioning, RBAC roles |
| `agcms-dashboard` | Overview, Violations, Playground, Policy, Audit, Alerts, Users, Reports, Settings |

## Quickstart

```bash
cp .env.example .env            # set AGCMS_SIGNING_KEY, JWT_SECRET_KEY, GROQ_API_KEY
docker compose up --build --wait

curl -s -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer agcms_test_key_for_development" \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"My SSN is 123-45-6789, draft an email."}]}'
# SSN is redacted before the prompt reaches the LLM; the audit row records REDACT.

open http://localhost:3000
```

Providers: Groq (default), Gemini, Mistral, Ollama. All speak the OpenAI
chat-completions format; set the matching API key in `.env`.

## Testing

```bash
pytest tests/unit/                 # no services needed
pytest tests/integration/          # needs `docker compose up`
locust -f tests/load/locustfile.py --host=http://localhost:8000
```

On Windows the injection tests load ONNX Runtime, which can crash a shared
interpreter. Run `tests/unit/test_injection_agent.py` in its own process if
the full run errors.

## Evaluation

Detection accuracy, false-positive rate, latency, ablation and baseline
comparison are produced by the harness under `tests/eval/` (see
`docs/evaluation.md`). Numbers in the paper come only from that harness.

## Repository layout

```
agcms-{gateway,pii,injection,response,policy,audit,auth,tenant}/   Python services
agcms-common/          shared scope vocabulary
agcms-dashboard/       React 18 / Vite admin UI
database/init.sql      PostgreSQL schema with row-level security
policies/default.yaml  default tenant policy
k8s/                   plain Kubernetes manifests
tests/{unit,integration,load,eval}/
docs/                  cURL quickstart, security checklist, evaluation notes
AGCMS_Complete_Build_Guide.md   original design document ("RULE N" references)
```

## Team

S Dheeran, Mohith S D Gowda, Tentan M S.
Faculty mentors: Dr. Sudarshan B. G, Dr. Mohana.

## License

Apache 2.0. See `LICENSE`.
