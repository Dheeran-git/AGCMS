# AGCMS Changelog

All notable product-facing changes to AGCMS are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and each
release has a fixed `YYYY-MM-DD` date once cut.

## [Unreleased] — scope reset to the CHTR proposal

### Changed
- LLM router: Gemini `gemini-3.8-flash` is the default, then Groq, then
  OpenRouter (new, `nvidia/nemotron-3-ultra-550b-a55b:free`), then local
  Ollama; Mistral removed. Ordered failover on provider-side failures
  (`AGCMS_FAILOVER`, `AGCMS_PROVIDER_ORDER`); the provider and model that
  answered are recorded in the audit row and returned in `X-AGCMS-Provider`
  / `X-AGCMS-Failovers` headers and in the Playground panel.
- Per-tenant rate limit is read from the active policy's
  `rate_limits.requests_per_minute` (was a hardcoded 60); `AGCMS_TENANT_RPM`
  overrides it and `AGCMS_GLOBAL_IP_RPM` (200) sets the per-IP ceiling. Ollama default tag `llama3.2:3b` pulled.
- ROLEPLAY heuristic rules are advisory: recorded in `triggered_rules` and
  `attack_type` but they no longer raise the risk score alone; the classifier
  decides. Removes the 6 % held-out false-positive rate from "pretend to be"
  prompts.
- CI runs on `master`, Python 3.12, installs `agcms-common`, builds service
  images from the repo root; Kubernetes dashboard service targets port 80;
  Playwright suite targets port 4173.
- Injection classifier: off-the-shelf DeBERTa replaced by a DistilBERT
  fine-tuned on the publisher train splits with PII-bearing hard negatives
  (held-out F1 0.958 +- 0.007 over 3 seeds vs 0.818; PII-prompt false
  positives at the block threshold 0 % vs 11 to 17 %). Weights ship as ONNX
  inside the image; no runtime model download.
- Gateway fails closed by default (`AGCMS_FAIL_MODE=closed`): 503 when a
  scan or policy service is unavailable.
- Response echo check covers all 20 PII types and normalises spacing.
- Dashboard host port moved to 4173 (Windows reserves 3000-range ports).

### Fixed
- The gateway now sends the tenant's active policy row to the policy
  service on every request (cached 10 s, invalidated on deploy). Previously
  the resolver always used its built-in default, so policies deployed from
  the dashboard, including `escalate_threshold`, were never enforced.
- Audit export (JSON/CSV) includes `pii_entity_types`, `injection_type` and
  `response_violated`; they were missing from the export query.
- EU AI Act report no longer describes the detector as DeBERTa.
- Ollama default tag `llama3.2:3b` was not installed on the host (only
  `latest`); documented and pulled.

### Removed
- Marketing site, Mintlify docs site, Python/TypeScript SDKs, sample
  integrations, Terraform, Helm, Grafana/Prometheus, sealed/external secrets.
- WorkOS SSO, TOTP MFA, session management, BYOK, envelope encryption,
  notifications service, incident SLA extras, GDPR purge workflow,
  Merkle anchoring to S3, signing-key rotation, audit bundles and the
  offline verifier, compliance policy packs, onboarding wizard, demo seeder,
  changelog service, Trust Center and public verifier pages.
- Unverified ablation and latency figures, including `docs/ablation-study.md`
  and the stale `docs/security-audit.md` checklist; `docs/evaluation.md`
  holds the measured numbers.

### Kept
- Gateway lifecycle, PII / injection / response agents, policy resolver,
  HMAC hash-chained audit log with per-row and chain verification, JWT auth,
  tenant provisioning, RBAC, rate limiting, GDPR / EU AI Act report
  endpoints, SSE violation feed, nine-page dashboard.

## [1.2.0] — 2026-05-09

### Added
- **GTM surface** — public OpenAPI 3.1 export at `/openapi.yaml`,
  hand-curated Postman collection, cURL quickstart, four runnable sample
  integrations (`openai-wrapped`, `anthropic-wrapped`, `langchain-wrapped`,
  `next-js-server-actions`).
- **Python SDK** (`pip install agcms`) with OpenAI-compatible
  `chat.completions.create()`, `openai_wrap()` helper, and `agcms verify`
  CLI for offline audit-bundle validation.
- **TypeScript SDK** (`npm install @agcms/sdk`) with the same shape — works
  in Node, Deno, modern browsers.
- **In-app changelog** surface in Settings → About.

## [1.1.0] — 2026-04-22

### Added
- **Trust Center page** at `/trust` — security posture, audit-trail
  integrity explainer, subprocessor list, recent-incident feed.
- **Real-time violation feed** via Server-Sent Events on the Overview page
  (replaces 10 s polling).
- **Incident workflow** on the Alerts page — acknowledge, assign, resolve
  with mandatory notes; per-severity SLA timers.
- **Notifications service** with five providers: Slack, PagerDuty, generic
  webhook (HMAC-signed), email (SMTP/SES), and Splunk HEC. Configurable
  per-trigger rules in Settings → Integrations.
- **Compliance framework UI** — citation chips on policy rules, report
  findings, and violation detail dialogs (HIPAA, GDPR, EU AI Act,
  NIST AI RMF, SOC 2, PCI-DSS).
- **Policy packs** for HIPAA, GDPR, EU AI Act high-risk, NIST AI RMF,
  SOC 2 CC, and PCI-DSS — auto-suggested during onboarding.
- **Onboarding wizard** for first-login tenant admins.
- **Demo data toggle** — seeds 500 violations / 2 000 audit rows for
  buyer demos; one-click reversible.

## [1.0.0] — 2026-04-01

Initial public release. 13-step gateway lifecycle, 11 microservices,
multi-tenant RLS, HMAC-SHA256 signed audit, RBAC, rate limiting, GDPR /
EU AI Act report endpoints, 9-page React dashboard, Kubernetes manifests,
Groq / Gemini / Mistral / Ollama router.
