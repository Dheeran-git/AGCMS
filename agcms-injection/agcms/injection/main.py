from fastapi import FastAPI
from pydantic import BaseModel

from agcms.injection.agent import InjectionAgent

app = FastAPI(
    title="AGCMS Injection Detection Agent",
    description="Prompt injection classification service",
    version="2.0.0",
)

_agent = InjectionAgent()


class ScanRequest(BaseModel):
    text: str


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "injection",
        "ml_classifier": _agent._onnx_session is not None,
    }


@app.post("/scan")
async def scan(req: ScanRequest):
    result = _agent.scan(req.text)
    return result.to_dict()
