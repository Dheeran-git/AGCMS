"""Use AGCMS with LangChain by overriding the OpenAI client base URL.

Two-line glue: point ChatOpenAI at the AGCMS gateway and pass the AGCMS
API key in place of the OpenAI key.

Run:
    pip install langchain-openai
    export AGCMS_BASE_URL=https://api.your-tenant.agcms.com
    export AGCMS_API_KEY=agc_live_...
    python main.py
"""

import os

from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="groq:llama-3.3-70b-versatile",
    base_url=os.environ["AGCMS_BASE_URL"] + "/v1",
    api_key=os.environ["AGCMS_API_KEY"],
)

resp = llm.invoke([HumanMessage(content="What is a Merkle root?")])
print(resp.content)
