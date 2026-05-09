# AGCMS Python SDK

Official Python client for **AGCMS** — AI Governance & Compliance Monitoring.
Drop-in replacement for the OpenAI client that routes every call through your
AGCMS gateway, so you get PII redaction, prompt-injection detection, policy
enforcement, and cryptographically signed audit trails for free.

- **Source:** https://github.com/Dheeran-git/AGCMS
- **Docs:** https://uip-f4b0bbe5.mintlify.app
- **Marketing:** https://agcms-six.vercel.app

## Install

```bash
pip install agcms
```

## Quickstart

```python
from agcms import AGCMSClient

client = AGCMSClient(
    base_url="http://localhost:8000",          # your AGCMS gateway
    api_key="agcms_test_key_for_development",  # or a real per-tenant key
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
    agcms_base_url="http://localhost:8000",
    agcms_api_key="agcms_test_key_for_development",
)

# Use it exactly like a regular OpenAI client; AGCMS sits in the middle.
client.chat.completions.create(model="gpt-4o", messages=[...])
```

## Verify an audit bundle (CLI)

```bash
python -m agcms.cli verify path/to/bundle.zip
```

Validates the hash chain, Merkle root, and signing-key chain offline — no
network calls, no AGCMS credentials needed.

## Run AGCMS yourself

The repo ships a 11-service `docker-compose.yml`:

```bash
git clone https://github.com/Dheeran-git/AGCMS.git
cd AGCMS && cp .env.example .env
docker compose up --build --wait
# → gateway on :8000, dashboard on :3000
```

## License

Apache-2.0
