import threading

from fastapi import FastAPI
from pydantic import BaseModel, Field

from agcms.injection.agent import InjectionAgent

# Backstop for direct callers; the gateway enforces its own, smaller prompt cap.
MAX_TEXT_CHARS = 100_000

app = FastAPI(
    title="AGCMS Injection Detection Agent",
    description="Prompt injection classification service",
    version="2.0.0",
)

_agent = InjectionAgent()
# The Hugging Face fast tokenizer is not safe to share across threads; scans run
# one at a time in FastAPI's threadpool so inference never blocks /health.
_lock = threading.Lock()


class ScanRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT_CHARS)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "injection",
        "ml_classifier": _agent._onnx_session is not None,
    }


@app.post("/scan")
def scan(req: ScanRequest):
    with _lock:
        result = _agent.scan(req.text)
    return result.to_dict()
