"""3-line OpenAI integration via AGCMS.

Run:
    pip install openai agcms
    export OPENAI_API_KEY=sk-...
    export AGCMS_BASE_URL=https://api.your-tenant.agcms.com
    export AGCMS_API_KEY=agc_live_...
    python main.py
"""

import os

from openai import OpenAI

from agcms import openai_wrap

client = openai_wrap(
    OpenAI(api_key=os.environ["OPENAI_API_KEY"]),
    agcms_base_url=os.environ["AGCMS_BASE_URL"],
    agcms_api_key=os.environ["AGCMS_API_KEY"],
)

resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Summarise the EU AI Act in one sentence."}],
)

print(resp["choices"][0]["message"]["content"])
print("audit interaction_id:", client.last_interaction_id)
