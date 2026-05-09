"""Route Anthropic Messages API calls through AGCMS.

The AGCMS gateway exposes an OpenAI-compatible /v1/chat/completions endpoint;
for Anthropic users we recommend pointing the official Anthropic client at
AGCMS via its `base_url` and using the gateway's `provider="anthropic"` knob.

Run:
    pip install anthropic
    export ANTHROPIC_API_KEY=sk-ant-...
    export AGCMS_BASE_URL=https://api.your-tenant.agcms.com
    export AGCMS_API_KEY=agc_live_...
    python main.py
"""

import os

from anthropic import Anthropic

# Anthropic client points at AGCMS instead of api.anthropic.com.
# AGCMS gateway forwards to Anthropic with PII redaction + audit.
client = Anthropic(
    api_key=os.environ["AGCMS_API_KEY"],          # AGCMS gateway auth
    base_url=os.environ["AGCMS_BASE_URL"] + "/v1/anthropic",
    default_headers={"X-Anthropic-Key": os.environ["ANTHROPIC_API_KEY"]},
)

msg = client.messages.create(
    model="claude-3-5-sonnet-latest",
    max_tokens=256,
    messages=[
        {"role": "user", "content": "Explain HMAC-SHA256 in two sentences."},
    ],
)

print(msg.content[0].text)
