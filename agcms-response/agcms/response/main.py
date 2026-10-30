from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from agcms.response.agent import ResponseComplianceAgent

# Backstop for direct callers; replies and prompts above this are rejected (422).
MAX_TEXT_CHARS = 100_000

app = FastAPI(
    title="AGCMS Response Compliance Agent",
    description="Response compliance checking service",
    version="1.0.0",
)

_agent = ResponseComplianceAgent()


class CheckRequest(BaseModel):
    response_text: str = Field(max_length=MAX_TEXT_CHARS)
    original_prompt: Optional[str] = Field(default=None, max_length=MAX_TEXT_CHARS)
    policy: Optional[dict] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "response"}


@app.post("/check")
def check(req: CheckRequest):
    """Runs in FastAPI's threadpool: the regex checks are CPU-bound and stateless."""
    result = _agent.check(
        response_text=req.response_text,
        original_prompt=req.original_prompt,
        policy=req.policy,
    )
    return result.to_dict()
