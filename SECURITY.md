# Security Policy

AGCMS is an academic research prototype (RV College of Engineering, CHTR).
It is not a hosted service and has no bug-bounty programme.

## Reporting a vulnerability

Email the maintainer listed in `README.md` with a description, reproduction
steps, and the commit hash you tested against. Please do not open a public
GitHub issue for security problems until a fix is available.

## Scope

In scope: the gateway, PII, injection, response, policy, audit, auth and
tenant services, the database schema, and the React dashboard in this repo.

Out of scope: the third-party LLM providers the gateway proxies to (Groq,
Gemini, Mistral, Ollama), and deployments where the operator changed the
shipped defaults.

## Secrets

Never commit `.env`. The only secrets the stack needs are
`AGCMS_SIGNING_KEY` (audit HMAC), `JWT_SECRET_KEY`, provider API keys and the
local Postgres/Redis passwords. See `.env.example`.
