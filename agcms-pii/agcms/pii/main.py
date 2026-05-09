from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional

from agcms.common.observability import init_observability
from agcms.pii.agent import PIIAgent

app = FastAPI(
    title="AGCMS PII Detection Agent",
    description="PII detection and masking service",
    version="1.0.0",
)

init_observability(app, "pii")

_agent = PIIAgent()


class ScanRequest(BaseModel):
    text: str
    policy: Optional[dict] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "pii"}


@app.post("/scan")
async def scan(req: ScanRequest):
    result = await _agent.scan(req.text, req.policy or {})
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
