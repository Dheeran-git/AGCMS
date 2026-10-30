import threading
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from agcms.pii.agent import PIIAgent

# Backstop for direct callers; the gateway enforces its own, smaller prompt cap.
MAX_TEXT_CHARS = 100_000

app = FastAPI(
    title="AGCMS PII Detection Agent",
    description="PII detection and masking service",
    version="1.0.0",
)

_agent = PIIAgent()
# spaCy pipelines are not guaranteed thread-safe; scans run one at a time in
# FastAPI's threadpool so a long scan never blocks /health.
_lock = threading.Lock()


class ScanRequest(BaseModel):
    text: str = Field(max_length=MAX_TEXT_CHARS)
    policy: Optional[dict] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "pii"}


@app.post("/scan")
def scan(req: ScanRequest):
    with _lock:
        result = _agent.scan_sync(req.text, req.policy or {})
    return {
        "has_pii": result.has_pii,
        "risk_level": result.risk_level,
        "entity_types": result.entity_types,
        "entities": [
            {
                "text": e.text,
                "entity_type": e.entity_type,
                "start": e.start,
                "end": e.end,
                "confidence": e.confidence,
            }
            for e in result.entities
        ],
        "masked_text": result.mask(req.text) if result.has_pii else None,
    }
