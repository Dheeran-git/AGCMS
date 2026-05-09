# AGCMS Python SDK

Official Python client for [AGCMS](https://agcms.com) — AI Governance &
Compliance Monitoring. Drop-in replacement for the OpenAI client that routes
every call through your AGCMS gateway, so you get PII redaction, prompt-injection
detection, policy enforcement, and signed audit trails for free.

## Install

```bash
pip install agcms
```

## Quickstart

```python
from agcms import AGCMSClient

client = AGCMSClient(
    base_url="https://api.your-tenant.agcms.com",
    api_key="agc_live_...",
)

resp = client.chat.completions.create(
    model="groq:llama-3.3-70b-versatile",
    messages=[{"role": "user", "content": "Hello!"}],
)

print(resp["choices"][0]["message"]["content"])
print("audit interaction_id:", client.last_interaction_id)
```

## Wrap an existing OpenAI client (3-line integration)

```python
from openai import OpenAI
from agcms import openai_wrap

client = openai_wrap(
    OpenAI(api_key="sk-..."),
    agcms_base_url="https://api.your-tenant.agcms.com",
    agcms_api_key="agc_live_...",
)

# Use it exactly like a regular OpenAI client; AGCMS sits in the middle.
client.chat.completions.create(model="gpt-4o", messages=[...])
```

## Verify an audit bundle (CLI)

```bash
agcms verify path/to/bundle.zip
```

Validates the hash chain, Merkle root, and signing-key chain offline — no
network calls, no AGCMS credentials needed.

## License

Apache-2.0
