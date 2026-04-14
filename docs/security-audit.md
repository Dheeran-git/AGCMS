# AGCMS Security Audit Checklist

**System:** AI Governance and Compliance Monitoring System (AGCMS)  
**Version:** Phase 3  
**Date:** 2026-04-13  
**Auditor:** S Dheeran, RVCE CHTR — Unisys UIP Y17

---

## OWASP API Security Top 10 Assessment

| # | Threat | Status | Evidence |
|---|--------|--------|----------|
| API1 | Broken Object Level Authorization | PASS | Every DB query filters by `ctx.tenant_id`; RLS policies on all tables in `database/init.sql` |
| API2 | Broken Authentication | PASS | JWT (HS256) + API key SHA-256 hash; dual-mode in `agcms-gateway/agcms/gateway/auth.py` |
| API3 | Broken Object Property Level Authorization | PASS | Response serializers expose only whitelisted fields per endpoint |
| API4 | Unrestricted Resource Consumption | PASS | Rate limits enforced per-tenant (`rate_limit_events` table); `requests_per_minute` and `requests_per_day` in policy config |
| API5 | Broken Function Level Authorization | PASS | RBAC via `require_admin` / `require_compliance` FastAPI dependencies in `rbac.py` |
| API6 | Unrestricted Access to Sensitive Business Flows | PASS | `/v1/chat/completions` requires API key; all `/api/v1/*` require JWT or API key |
| API7 | Server-Side Request Forgery | PASS | Proxy endpoints (`/auth/token`, `/tenant/provision`) use internal service URLs from env vars only — no user-controlled URLs |
| API8 | Security Misconfiguration | PASS | No default credentials in prod; secrets via env vars; CORS not wildcard |
| API9 | Improper Inventory Management | PASS | All 11 services documented; versioned `/api/v1/` prefix; policy version history |
| API10 | Unsafe Consumption of APIs | PASS | Upstream Groq API responses are passed through after compliance check; response compliance scanner validates output |

---

## Authentication & Authorisation

| Check | Status | Detail |
|-------|--------|--------|
| JWT expiry enforced | PASS | 30-min access token, 7-day refresh; `exp` claim validated by `jose.jwt.decode` |
| JWT signature algorithm pinned | PASS | HS256 only; algorithm explicitly passed to decode — no `alg=none` attack vector |
| API keys hashed in DB | PASS | SHA-256 hex stored in `tenants.api_key_hash`; raw key never persisted |
| API keys not logged | PASS | Audit logger logs `user_id`, not auth credentials |
| Refresh tokens single-use | PASS | jti UUID4 added to every refresh token; Redis blacklist in `tokens.py`; replayed jti returns 401 |
| Multi-factor authentication | NOT IMPLEMENTED | SSO/MFA deferred; noted for Phase 4 |
| Role hierarchy admin > compliance > user | PASS | `require_role()` in `rbac.py` — admin bypasses all gates |

---

## Injection & PII Detection

| Check | Status | Detail |
|-------|--------|--------|
| Prompt injection — heuristic layer | PASS | `HeuristicAgent` in `agcms-injection/agcms/injection/agent.py` — 15+ pattern rules |
| Prompt injection — ML layer | PASS | `protectai/deberta-v3-base-prompt-injection-v2` via ONNX Runtime |
| PII detection — NER | PASS | spaCy `en_core_web_sm`/`en_core_web_trf` — PERSON, ORG, GPE entity types |
| PII detection — regex | PASS | SSN (`\d{3}-\d{2}-\d{4}`), email, phone, credit card patterns in `pii/agent.py` |
| Sensitive data in logs | PASS | `masked_text` stored in audit log (not original); original only in Groq call |
| SQL injection via asyncpg | PASS | All queries use parameterised `$1 $2…` placeholders; no string interpolation |
| XSS in dashboard | PASS | React renders all API data via JSX auto-escaping; no raw HTML injection APIs used |

---

## Audit Trail Integrity

| Check | Status | Detail |
|-------|--------|--------|
| HMAC signing | PASS | HMAC-SHA256 via `AGCMS_SIGNING_KEY`; `AuditLogger.sign()` in `agcms-audit/agcms/audit/logger.py` |
| Tamper detection | PASS | `/api/v1/audit/verify/{id}` reconstructs and re-signs; any field change returns `verified=false` |
| Append-only log | PASS | No DELETE or UPDATE on `audit_logs`; partitioned by month for retention |
| Partition retention | PASS | Range partitions by `created_at`; old partitions can be dropped (dropping = archive, not edit) |
| Cross-tenant audit isolation | PASS | All audit queries filter by `tenant_id`; RLS on table |

---

## Multi-Tenancy & Data Isolation

| Check | Status | Detail |
|-------|--------|--------|
| Row-Level Security | PASS | `CREATE POLICY` on `tenant_users`, `policies`, `audit_logs`, `escalations`, `rate_limit_events` in `database/init.sql` |
| Tenant ID on every query | PASS | `authenticate()` returns `AuthContext.tenant_id`; all management API DB calls use it as `$1` |
| Cross-tenant data leak tested | PASS | Integration test `tests/integration/test_management_api_integration.py` — compliance user sees only own tenant's data |
| API key → tenant mapping | PASS | `tenants.api_key_hash` lookup; `is_active=TRUE` enforced |

---

## Known Gaps & Mitigations

| Gap | Risk | Mitigation / Plan |
|-----|------|-------------------|
| Refresh token replay | **RESOLVED (Phase 4)** | jti claim added to all refresh tokens; Redis blacklist in `agcms-auth/agcms/auth/tokens.py`; replay returns HTTP 401 |
| Rate limit bypass via key rotation | **RESOLVED (Phase 4)** | Global per-IP rate limit (200 RPM) added as pre-auth step in gateway `main.py`; separate Redis key namespace from per-tenant counters |
| SSO / SAML not implemented | Medium | Enterprise SSO deferred; dev key is only demo credential — not for production |
| No WAF in front of ingress | **RESOLVED (Phase 4)** | NGINX ModSecurity + OWASP CRS annotations added to `k8s/ingress.yaml`; `SecRuleEngine On` blocks SQLi, XSS, RCE at ingress layer |
| ONNX model download at build time | **RESOLVED (Phase 4)** | `revision=e6535ca4` pinned via `AGCMS_INJECTION_MODEL_SHA` env var in `agcms-injection/Dockerfile`; supply-chain update now requires explicit SHA change |

---

## Dependency Vulnerability Status

Run `pip-audit` against each service's `requirements.txt` before production deployment.  
As of 2026-04-13: no known HIGH/CRITICAL CVEs in pinned versions (asyncpg 0.29, fastapi 0.110, python-jose 3.3, spacy 3.7, onnxruntime 1.17).
