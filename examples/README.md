# AGCMS Sample Integrations

Each subdirectory is a runnable, single-file example showing how to put the
AGCMS gateway in front of a popular LLM client.

| Directory                      | Stack                                      | Lines of glue |
|--------------------------------|--------------------------------------------|---------------|
| `openai-wrapped/`              | Python · `openai` + `agcms.openai_wrap`    | 3             |
| `anthropic-wrapped/`           | Python · `anthropic` + AGCMS HTTP passthrough | ~10        |
| `langchain-wrapped/`           | Python · `langchain-openai` + base_url override | 2        |
| `next-js-server-actions/`      | TypeScript · Next.js 14 server action      | ~15           |

All examples expect:

```bash
export AGCMS_BASE_URL="https://api.your-tenant.agcms.com"
export AGCMS_API_KEY="agc_live_..."
```

The point of these is *brevity* — each one demonstrates that adding AGCMS
governance does not require restructuring your application code.
