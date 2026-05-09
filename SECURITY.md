# Security Policy

AGCMS is a runtime governance plane that sits between applications and LLM
providers, inspects traffic, enforces policy, and writes a cryptographically
signed audit trail. Because we sit on the request path of regulated workloads,
we take vulnerability reports very seriously.

## Reporting a vulnerability

**Email:** `security@agcms.com`
**PGP key:** published at `https://agcms.com/.well-known/pgp-key.asc`
**Encrypted submissions are preferred for any vulnerability with an exploit PoC.**

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (PoC code, request/response captures, or video).
- The version / commit hash you tested against (`git rev-parse HEAD` of the
  AGCMS deploy, or the `X-AGCMS-Version` response header).
- Whether you believe the vulnerability is being actively exploited.

Please do **not** open a public GitHub issue for security reports.

## Response targets

| Severity              | First response | Triage decision | Patch target  |
|-----------------------|----------------|-----------------|---------------|
| Critical (RCE, auth bypass, multi-tenant data leak) | 24 hours | 72 hours | 7 days |
| High (PII leak in audit log, privilege escalation)  | 48 hours | 7 days   | 30 days |
| Medium (misconfig, info disclosure with low blast)  | 5 days   | 14 days  | 90 days |
| Low (defense-in-depth gaps, hardening suggestions)  | 10 days  | 30 days  | next release |

We will acknowledge receipt of the report and keep you updated as we triage,
fix, and disclose.

## Scope

In scope:

- The AGCMS gateway, auth, tenant, audit, anchor, policy, PII, injection,
  response, and notifications services.
- The AGCMS dashboard (`agcms-dashboard`) and marketing site (`marketing`).
- The official Python SDK (`sdk/python`) and TypeScript SDK (`sdk/typescript`).
- The Helm chart (`infra/helm`) and Terraform module (`infra/terraform`).
- The audit-bundle verifier shipped under `tools/verify.py`.

Out of scope:

- Third-party LLM providers we proxy to (Groq, Gemini, Mistral, Ollama). Report
  those issues directly to the provider.
- Your local clone of the repo, your own dev fixtures, your `.env` files.
- Self-hosted deployments where the operator has disabled controls we ship by
  default (e.g. turned off MFA enforcement, reused the dev fallback KMS key).
- Social-engineering attacks on AGCMS personnel.
- Denial-of-service via volumetric traffic. Report DoS only when it can be
  triggered with a small request that disproportionately consumes resources.

## Safe harbor

If you make a good-faith effort to comply with this policy during your
research, we will:

- Consider your research authorized under the Computer Fraud and Abuse Act
  (and analogous laws in other jurisdictions).
- Work with you to understand and resolve the issue quickly.
- Not pursue legal action against you for the research, provided you do not:
  - Access, modify, or destroy data that is not your own.
  - Degrade the AGCMS service for other users.
  - Publicly disclose the vulnerability before we have had a reasonable
    chance to remediate it (see "Response targets" above).
  - Violate the privacy of AGCMS customers or end-users.

## Cryptographic + supply-chain expectations

AGCMS publishes:

- Container images via GHCR with cosign signatures.
- Python and TypeScript SDKs to PyPI and npm with sigstore attestations.
- Audit-bundle artifacts containing HMAC-SHA256 row signatures and a Merkle
  root signed with the `AGCMS_ANCHOR_KEY`.

If you discover a signing-key leak, a tampered artifact, or a Merkle-root
divergence between what AGCMS published and what you can recompute from the
bundle, treat it as a Critical-severity report.

## Acknowledgements

We maintain a hall of fame at `https://agcms.com/security/hall-of-fame` for
researchers who have responsibly disclosed valid issues. Let us know in your
report whether you would like to be credited and how you would like to be
listed.

## Last updated

2026-04-22
