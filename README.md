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
| `agcms-injection` | 20 heuristic rules across 6 attack classes + fine-tuned DistilBERT (ONNX) |
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

The injection classifier is trained and exported locally before the first
build (weights are not committed):

```bash
python tests/eval/prepare_datasets.py          # corpora, incl. training rows
python agcms-injection/ml/train.py             # DistilBERT, ~2 h on a laptop CPU
python agcms-injection/ml/export_onnx.py       # -> agcms-injection/ml/model/onnx
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
locust -f tests/load/locustfile.py --host=http://localhost:8000
```

On Windows the injection tests load ONNX Runtime, which can crash a shared
interpreter. Run `tests/unit/test_injection_agent.py` in its own process if
the full run errors.

## Evaluation

All accuracy, latency, ablation and baseline numbers come from the harness
under `tests/eval/` and are recorded with the machine used in
`docs/evaluation.md`. Headline results from the 2026-09-06 run on a laptop
CPU (3,505 injection prompts from deepset, jackhhao and the AGCMS template
set; 1,600 PII prompts from Faker and ai4privacy plus benign negatives):

| Module | Config | Precision | Recall | F1 | FPR | median latency |
|---|---|---|---|---|---|---|
| Injection | keyword baseline | 0.998 | 0.291 | 0.451 | 0.001 | 0 ms |
| Injection | heuristics only | 0.935 | 0.328 | 0.485 | 0.026 | 0.06 ms |
| Injection | DeBERTa only | 0.993 | 0.758 | 0.860 | 0.006 | 253 ms |
| Injection | heuristics + DeBERTa (shipped) | 0.966 | 0.795 | 0.873 | 0.032 | 269 ms |
| PII (entity level) | regex only | 0.956 | 0.672 | 0.789 | | 1.3 ms |
| PII (entity level) | regex + spaCy (shipped) | 0.926 | 0.810 | 0.864 | | 10.6 ms |

The response-compliance checks score 1.0 on the synthetic response set, which
is a functional check rather than a benchmark. See `docs/evaluation.md` for
per-source and per-type breakdowns and the caveats.

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
