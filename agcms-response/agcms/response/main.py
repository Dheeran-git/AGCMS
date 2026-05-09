from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from agcms.common.observability import init_observability
from agcms.response.agent import ResponseComplianceAgent

app = FastAPI(
    title="AGCMS Response Compliance Agent",
    description="Response compliance checking service",
    version="1.0.0",
)

init_observability(app, "response")

_agent = ResponseComplianceAgent()


class CheckRequest(BaseModel):
    response_text: str
    original_prompt: Optional[str] = None
    policy: Optional[dict] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "response"}


@app.post("/check")
async def check(req: CheckRequest):
    result = _agent.check(
        response_text=req.response_text,
        original_prompt=req.original_prompt,
        policy=req.policy,
    )
    return result.to_dict()
