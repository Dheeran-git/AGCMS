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
Dashboard (:4173) <- Gateway management API <- PostgreSQL (RLS) + Redis
Auth (:8006) issues JWTs; Tenant (:8007) provisions tenants + API keys.
```

| Service | Role |
|---|---|
| `agcms-gateway` | OpenAI-compatible proxy, auth, rate limits, management API, SSE feed |
| `agcms-pii` | 20 regex patterns + spaCy NER, masking, risk level |
| `agcms-injection` | fine-tuned DistilBERT (ONNX) + 20 heuristic rules across 6 attack classes (ROLEPLAY rules advisory) |
| `agcms-response` | PII echo, system-prompt leak and restricted-topic checks on LLM output |
| `agcms-policy` | YAML policy DSL, validator, enforcement resolver |
| `agcms-audit` | Hash-chained HMAC audit log, per-row and whole-chain verification |
| `agcms-auth` / `agcms-tenant` | JWT issuance, tenant provisioning, RBAC roles |
| `agcms-dashboard` | Overview, Violations, Playground, Policy, Audit, Alerts, Users, Reports, Settings |

## Quickstart

```bash
cp .env.example .env            # set AGCMS_SIGNING_KEY, JWT_SECRET_KEY, GROQ_API_KEY
docker compose up --build --wait

# Critical PII (an SSN) is blocked by the default policy: HTTP 403, audit row records BLOCK
curl -s -X POST http://localhost:8000/v1/chat/completions   -H "Authorization: Bearer agcms_test_key_for_development"   -H "Content-Type: application/json"   -d '{"messages":[{"role":"user","content":"My SSN is 123-45-6789, draft an email."}]}'

# Medium-risk PII (an email address) is redacted before the prompt reaches the LLM
curl -s -X POST http://localhost:8000/v1/chat/completions   -H "Authorization: Bearer agcms_test_key_for_development"   -H "Content-Type: application/json"   -d '{"messages":[{"role":"user","content":"Reply to jane.doe@example.com about the invoice."}]}'

open http://localhost:4173        # dashboard (host port set by AGCMS_DASHBOARD_PORT)
```

Providers: Groq (default), Gemini, Mistral, Ollama. All speak the OpenAI
chat-completions format; set the matching API key in `.env`.

The injection classifier is trained and exported locally before the first
build (weights are not committed):

```bash
python tests/eval/prepare_datasets.py          # corpora, incl. training rows
python agcms-injection/ml/train.py --hard-negatives --out agcms-injection/ml/model/seed2-hn --seed 2   # ~2 h on a laptop CPU
python agcms-injection/ml/export_onnx.py --src agcms-injection/ml/model/seed2-hn --dst agcms-injection/ml/model/onnx
```

Without the export the injection service starts in heuristic-only mode.

Failure mode: by default (`AGCMS_FAIL_MODE=closed`) the gateway rejects a
request with 503 when the PII scan, injection scan or policy service is
unavailable, so an outage cannot let unscreened prompts through. Set
`AGCMS_FAIL_MODE=open` to prefer availability.

## Testing

```bash
pytest tests/unit/                 # no services needed
pytest tests/integration/          # needs `docker compose up`
cd agcms-dashboard && npx playwright test   # dashboard e2e, needs the stack on :4173
locust -f tests/load/locustfile.py --host=http://localhost:8000
```

On Windows the injection tests load ONNX Runtime, which can crash a shared
interpreter. Run `tests/unit/test_injection_agent.py` in its own process if
the full run errors.

## Evaluation

All accuracy, latency, ablation and baseline numbers come from the harness
under `tests/eval/` and are recorded with the machine used in
`docs/evaluation.md`. Headline results from the 2026-09-07 run on a laptop
CPU. Injection rows are the 378 held-out publisher test rows the classifier
never saw (199 injections); PII rows are 1,600 prompts from Faker and
ai4privacy plus benign negatives:

| Module | Config | Precision | Recall | F1 | FPR | median latency |
|---|---|---|---|---|---|---|
| Injection | keyword baseline | 0.978 | 0.226 | 0.367 | 0.006 | 0.02 ms |
| Injection | heuristics only | 0.833 | 0.276 | 0.415 | 0.062 | 0.3 ms |
| Injection | off-the-shelf DeBERTa | 0.986 | 0.699 | 0.818 | 0.011 | 126 ms |
| Injection | fine-tuned DistilBERT (3 seeds) | 1.000 | 0.923 | 0.959 +- 0.007 | 0.002 | 39 ms |
| Injection | heuristics + DistilBERT (shipped) | 1.000 | 0.920 | 0.958 | 0.000 | 41 ms |
| PII (entity level) | regex only | 0.956 | 0.672 | 0.789 | | 1.3 ms |
| PII (entity level) | regex + spaCy (shipped) | 0.926 | 0.810 | 0.864 | | 10.6 ms |

The classifier flags 0 of 1,200 PII-bearing benign prompts at the block
threshold after training with PII hard negatives. The response-compliance
checks score 1.0 on the synthetic response set, which is a functional check
rather than a benchmark. See `docs/evaluation.md` for per-source and per-type
breakdowns, the multi-seed table and the caveats.

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
