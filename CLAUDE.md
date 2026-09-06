# AGCMS — project notes for Claude Code

AGCMS is an LLM governance proxy: gateway -> PII scan + injection scan -> policy
resolve -> forward to LLM -> response check -> signed audit log. See README.md
for the service map and `AGCMS_Complete_Build_Guide.md` for the original design
("RULE N" references in code point at that guide).

## Working rules

- Read a file before editing it. Keep files under 500 lines.
- Python services live in `agcms-*/agcms/<service>/`; shared code in `agcms-common`.
- Tests: `pytest tests/unit/` needs no services; `tests/integration/` needs
  `docker compose up`. Report real results, never "should pass".
- Never commit `.env` or secrets.
- Do not edit `AGCMS_Complete_Build_Guide.md` unless explicitly asked.
