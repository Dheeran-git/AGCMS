# AGCMS — AI Governance & Compliance Monitoring System

[![PyPI](https://img.shields.io/pypi/v/agcms?color=5B8DEF&label=pip%20install%20agcms)](https://pypi.org/project/agcms/)
[![npm](https://img.shields.io/npm/v/@agcms/sdk?color=5B8DEF&label=%40agcms%2Fsdk)](https://www.npmjs.com/package/@agcms/sdk)
[![Tests](https://img.shields.io/badge/tests-771%20passing-22c55e)](#testing)
[![License](https://img.shields.io/badge/license-Apache--2.0-1f2937)](#license)

Cryptographically signed, legally defensible audit trails across a multi-tenant live AI enforcement plane. AGCMS sits between your applications and LLM providers, detects PII leakage, blocks prompt-injection attacks, enforces compliance policy, and writes a tamper-evident audit log auditable offline by a third party with no AGCMS credentials.

> **Unisys Innovation Program Y17, 2026** · RVCE CHTR

---

## Live

| Surface | URL |
|---|---|
| 🌐 **Marketing** | [agcms-six.vercel.app](https://agcms-six.vercel.app) |
| 📚 **Docs** | [uip-f4b0bbe5.mintlify.app](https://uip-f4b0bbe5.mintlify.app) |
| 📈 **Status** | [agcms.betteruptime.com](https://agcms.betteruptime.com) |
| 🐍 **Python SDK** | [`pip install agcms`](https://pypi.org/project/agcms/) |
| 📦 **TypeScript SDK** | [`npm install @agcms/sdk`](https://www.npmjs.com/package/@agcms/sdk) |
| 💻 **Source** | [github.com/Dheeran-git/AGCMS](https://github.com/Dheeran-git/AGCMS) |

---

## What's in v1.2.0

| Phase | Theme | What it ships |
|:--:|---|---|
| 1–4 | Core platform | 11-service Docker stack, 13-step gateway lifecycle, multi-tenant RLS, RBAC, rate limiting, GDPR + EU AI Act report endpoints, Linear-style React dashboard. |
| **5** | **Wedge** | Hash-chained audit log per tenant. Nightly Merkle-rooted manifests anchored to S3 Object Lock (Compliance mode). Self-contained portable verifier (`tools/verify.py`) — no AGCMS deps. Per-tenant key rotation. |
| **6** | **Enterprise trust** | WorkOS SSO, TOTP MFA, envelope encryption (per-tenant DEK + KEK), API-key scopes, session revocation, GDPR Art. 17 purge with hash-chain re-signing, TLS, Prometheus `/metrics`, OpenTelemetry, BYOK. |
| **7** | **Product depth** | First-login onboarding wizard, demo-data seed, six compliance policy packs (HIPAA, GDPR, EU AI Act, NIST AI RMF, SOC 2, PCI-DSS) with framework-citation chips, notifications service (Slack / PagerDuty / webhook / SMTP / Splunk), incident workflow, Server-Sent Events feed, Trust Center page. |
| **8** | **GTM surface** | Python + TypeScript SDKs (OpenAI-compatible passthrough + `openai_wrap` helper). Marketing site (Next.js 14, prerendered). Mintlify docs. OpenAPI 3.1 export. Postman collection. Four runnable wrap examples (`openai-wrapped`, `anthropic-wrapped`, `langchain-wrapped`, `next-js-server-actions`). In-app + RSS changelog. |
| 10 | Deployment | Helm chart (`infra/helm/agcms`). Modular AWS Terraform (`infra/terraform/aws/modules/{vpc,kms,s3-anchors,eks,rds,redis,iam}`). |

[Full changelog →](./CHANGELOG.md)

---

## Quickstart — local

```bash
# Clone + configure
git clone https://github.com/Dheeran-git/AGCMS.git
cd AGCMS
cp .env.example .env                             # set AGCMS_SIGNING_KEY + GROQ_API_KEY

# Bring up all 11 services
docker compose up --build --wait
docker compose ps                                # all healthy

# Try it
curl -s -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"My SSN is 123-45-6789, help me write an email."}]}'
# → SSN redacted before reaching the LLM

# Dashboard
open http://localhost:3000
```

Free Groq key: <https://console.groq.com>.

---

## Quickstart — SDK

**Python:**
```python
pip install agcms

from agcms import AGCMSClient
client = AGCMSClient(base_url="http://localhost:8000", api_key="agcms_test_key_for_development")
resp = client.chat.completions.create(
    model="llama-3.1-8b-instant",
    messages=[{"role": "user", "content": "Hello"}],
)
```

Or wrap an existing OpenAI client in 3 lines:
```python
from openai import OpenAI
from agcms import openai_wrap
oai = openai_wrap(OpenAI(), agcms_base_url="http://localhost:8000", api_key="agcms_test_key_for_development")
oai.chat.completions.create(...)                 # now goes through AGCMS
```

**TypeScript:**
```ts
npm install @agcms/sdk

import { AGCMSClient } from "@agcms/sdk";
const client = new AGCMSClient({ baseUrl: "http://localhost:8000", apiKey: "agcms_test_key_for_development" });
await client.chat.completions.create({
  model: "llama-3.1-8b-instant",
  messages: [{ role: "user", content: "Hello" }],
});
```

---

## Architecture

```
Client                 ┌──── PII (8001) ─────┐
  │                    │                     │
  ▼                    ├── Injection (8002) ─┤
Gateway (:8000) ──────►│                     │──► Policy (:8004) ──► LLM (Groq)
  │ ▲                  ├── Response (8003) ──┤            │
  │ │ JWT + scopes     │                     │            │
  │ │                  └─────────────────────┘            ▼
  │ │                                              Audit (:8005, HMAC chain)
  │ │                                                     │
  │ │                                                     ▼
  │ └────────── Auth (:8006, SSO+MFA, sessions)    Anchor manifest (Merkle root)
  │                       Tenant (:8007, BYOK)            │
  ▼                                                       ▼
Dashboard (:3000) ◄───── PostgreSQL (RLS) + Redis     S3 Object Lock (Compliance)
```

| Service | Port | Description |
|---|---|---|
| `gateway` | 8000 | Entry proxy. JWT, RBAC, scopes, rate limiting, tenant routing, OpenAI passthrough. |
| `pii` | 8001 | spaCy NER + regex PII detection / masking. |
| `injection` | 8002 | Heuristic + DeBERTa ONNX prompt-injection classifier. |
| `response` | 8003 | Response-side PII / leak scanner. |
| `policy` | 8004 | Per-tenant policy resolution; framework-citation aware. |
| `audit` | 8005 | HMAC-SHA256 hash-chained log + Merkle anchoring + S3 Object Lock writer. |
| `auth` | 8006 | JWT issue/refresh, WorkOS SSO bridge, TOTP MFA, session revocation. |
| `tenant` | 8007 | Tenant provisioning, envelope encryption, BYOK. |
| `dashboard` | 3000 | React 18 / Vite admin UI. 13 pages. |
| `postgres` | 5432 | PostgreSQL 16, Row-Level Security on all tables. |
| `redis` | 6379 | Rate-limit counters, JWT blacklist, SSE pub/sub. |

### Dashboard

| Page | What |
|---|---|
| `/` Overview | Live SSE stats, charts, system health |
| `/violations` | Filterable violation log |
| `/playground` | Interactive proxy tester |
| `/users` | User table + department activity |
| `/policy` | Live policy editor with framework chips |
| `/audit` | Chain-verifiable audit explorer + bundle export |
| `/alerts` | Incident workflow (acknowledge/assign/resolve, SLA timers) |
| `/reports` | GDPR Art. 30 + EU AI Act Art. 13 + 6 framework reports |
| `/settings` | Tenant quota, SSO, MFA, sessions, API keys, integrations |
| `/onboarding` | First-login wizard with auto policy-pack suggestions |
| `/trust` | Public Trust Center — security posture, subprocessors, integrity proof |
| `/trust/verify` | **Unauth** bundle-paste verifier — auditor's offline check, in-browser |
| `/sso/complete` | WorkOS callback handler |

---

## The wedge — provable to a third party

The core claim: **anyone can verify the integrity of an AGCMS audit log without AGCMS credentials.**

```bash
# 1. From the running stack, export a bundle
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/audit/bundle?start=2026-04-01\&end=2026-04-30 \
  -o audit.zip

# 2. On a clean machine — no AGCMS install, just Python 3
unzip audit.zip && python verify.py
# → ✓ chain intact: 12,438 rows, 30 days, 0 substitutions, 0 reorders
# → ✓ Merkle root matches signed daily anchor
# → ✓ all rows verify against signing key kid=k4
```

`tools/verify.py` is stdlib-only — no httpx, no SQLAlchemy, no AGCMS. Ships inside the bundle ZIP. Tamper detection covers truncation, reorder, row substitution, and content modification.

---

## Testing

```bash
# Unit (no services needed) — 35 files, 633 tests
pytest tests/unit/ -q

# Integration (running stack) — 5 files, 138 tests
pytest tests/integration/ -q

# Full suite (last green run): 771 passed, 0 failed, 2 skipped
```

E2E browser smoke (`agcms-dashboard/`): 11 Playwright specs, all 13 dashboard pages.

Load test:
```bash
locust -f tests/load/locustfile.py --host=http://localhost:8000 \
  --users=200 --spawn-rate=20 --run-time=120s --headless
```
At 200 concurrent users / 2 min: 8,882 requests, **0% error rate**, ~73 req/s.

---

## Performance & accuracy

Per-component contribution (see [docs/ablation-study.md](docs/ablation-study.md)):

| Configuration | PII | Injection | Enforcement |
|---|:---:|:---:|:---:|
| Baseline | 0% | 0% | 0% |
| + Regex PII | 68% | 0% | 68% |
| + spaCy NER | 84% | 0% | 84% |
| + Heuristic injection | 84% | 61% | 73% |
| + DeBERTa ML | 84% | 87% | 86% |
| + Policy engine | 84% | 87% | 92% |
| **Full AGCMS** | **84%** | **87%** | **94%** |

---

## Security posture

See [docs/security-audit.md](docs/security-audit.md) for the OWASP API Security Top 10 walk-through and [SECURITY.md](SECURITY.md) for the disclosure policy.

Highlights:
- Hash-chained audit with per-tenant sequence + previous-row HMAC
- Envelope encryption: per-tenant DEK wrapped by platform KEK; KMS-pluggable
- BYOK: tenants supply their own KEK; AGCMS plaintext never touches data
- WorkOS SSO + TOTP MFA + session revocation + per-key scopes
- GDPR Art. 17 purge with hash-chain-preserving redaction record
- TLS via cert-manager; secrets via External Secrets Operator + Sealed Secrets
- DeBERTa ONNX model pinned to commit `e6535ca4`

---

## Deployment

**Kubernetes** — Helm chart at `infra/helm/agcms/`:
```bash
helm install agcms ./infra/helm/agcms --namespace agcms --create-namespace
```

**AWS** — modular Terraform at `infra/terraform/aws/`:
```bash
cd infra/terraform/aws
terraform init && terraform plan -out tfplan && terraform apply tfplan
```
Modules: `vpc`, `kms`, `s3-anchors`, `eks`, `rds`, `redis`, `iam`.

---

## Project structure

```
AGCMS/
├── agcms-{gateway,pii,injection,response,policy,audit,auth,tenant}/  # 8 Python services
├── agcms-dashboard/                     # React 18 / Vite admin UI
├── agcms-common/                        # Shared crypto, BYOK, tenant_keys
├── sdk/{python,typescript}/             # Published SDKs
├── marketing/                           # Next.js 14 landing site (deployed to Vercel)
├── docs-site/                           # Mintlify docs (deployed to Mintlify)
├── examples/                            # 4 wrap examples
├── policies/packs/                      # 6 compliance policy packs (YAML)
├── infra/{helm,terraform,grafana,prometheus}/
├── k8s/                                 # raw manifests + cert-manager + ExternalSecrets
├── tools/verify.py                      # stdlib-only audit-bundle verifier
├── tests/{unit,integration,load}/
└── docker-compose.yml
```

---

## Team

- **S Dheeran** — RVCE CHTR, Unisys UIP Y17 ([github.com/Dheeran-git](https://github.com/Dheeran-git))
- Mohith S D Gowda
- Tentan M S

**Faculty Mentors:** Dr. Sudarshan B. G, Dr. Mohana
**Institution:** RV College of Engineering — Centre for Healthcare Technology and Research (CHTR)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
