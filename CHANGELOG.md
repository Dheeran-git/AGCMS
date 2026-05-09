# AGCMS Changelog

All notable product-facing changes to AGCMS are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and each
release has a fixed `YYYY-MM-DD` date once cut.

## [1.2.0] — Unreleased

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
