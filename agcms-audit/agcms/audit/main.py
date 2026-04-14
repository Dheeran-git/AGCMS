import json
import os
import uuid
from contextlib import asynccontextmanager
from decimal import Decimal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

from agcms.db import database


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.connect()
    yield
    await database.disconnect()


app = FastAPI(
    title="AGCMS Audit Logging Service",
    description="Audit log writing and querying service",
    version="1.0.0",
    lifespan=lifespan,
)

# Lazy init — logger import requires AGCMS_SIGNING_KEY and DB
_logger = None


def _get_logger():
    global _logger
    if _logger is None:
        from agcms.audit.logger import AuditLogger
        _logger = AuditLogger()
    return _logger


class LogRequest(BaseModel):
    interaction_id: str
    tenant_id: str
    user_id: str
    department: Optional[str] = None
    raw_body: dict
    pii_result: Optional[dict] = None
    injection_result: Optional[dict] = None
    decision: Optional[dict] = None
    compliance_result: Optional[dict] = None
    start_time: float
    llm_provider: str = "groq"
    llm_model: Optional[str] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "audit"}


@app.post("/log")
async def log_entry(req: LogRequest):
    logger = _get_logger()
    entry = await logger.log(
        interaction_id=req.interaction_id,
        tenant_id=req.tenant_id,
        user_id=req.user_id,
        department=req.department,
        raw_body=req.raw_body,
        pii_result=req.pii_result,
        injection_result=req.injection_result,
        decision=req.decision,
        compliance_result=req.compliance_result,
        start_time=req.start_time,
        llm_provider=req.llm_provider,
        llm_model=req.llm_model,
    )
    return {"status": "logged", "interaction_id": entry["interaction_id"]}


@app.get("/verify/{interaction_id}")
async def verify_entry(interaction_id: str):
    """Recompute the HMAC signature over the stored row and compare.

    Reconstructs the exact entry dict shape used by ``AuditLogger.sign()``
    at write time. Any type drift (e.g., Decimal vs float, datetime object
    vs isoformat string) will cause verification to fail — handle them
    explicitly below.
    """
    try:
        iid = uuid.UUID(interaction_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid interaction_id (must be UUID)")

    query = (
        "SELECT interaction_id, tenant_id, user_id, department, created_at, "
        "llm_provider, llm_model, prompt_hash, pii_detected, pii_entity_types, "
        "pii_risk_level, injection_score, injection_type, enforcement_action, "
        "enforcement_reason, triggered_policies, response_violated, "
        "response_violations, total_latency_ms, log_signature "
        "FROM audit_logs WHERE interaction_id = :iid "
        "ORDER BY created_at DESC LIMIT 1"
    )
    row = await database.fetch_one(query, values={"iid": iid})
    if row is None:
        raise HTTPException(status_code=404, detail="Audit log not found")

    entry = dict(row)

    # Convert UUID → str (signer stores str(interaction_id))
    entry["interaction_id"] = str(entry["interaction_id"])

    # Convert datetime → isoformat string (signer called .isoformat())
    if entry.get("created_at") is not None:
        entry["created_at"] = entry["created_at"].isoformat()

    # Convert Decimal → float (signer stored round(score, 3) as float)
    if isinstance(entry.get("injection_score"), Decimal):
        entry["injection_score"] = float(entry["injection_score"])

    # ARRAY columns come back as lists — good. But empty arrays may be [] or None;
    # the signer stored `[]` for triggered_policies (default in logger) so prefer [].
    if entry.get("pii_entity_types") is None:
        entry["pii_entity_types"] = []
    if entry.get("triggered_policies") is None:
        entry["triggered_policies"] = []

    # JSONB → asyncpg may return str or dict depending on version
    rv = entry.get("response_violations")
    if isinstance(rv, str):
        try:
            entry["response_violations"] = json.loads(rv)
        except Exception:
            pass

    from agcms.audit.logger import AuditLogger
    verified = AuditLogger.verify(entry)

    return {
        "verified": verified,
        "interaction_id": entry["interaction_id"],
        "tenant_id": entry["tenant_id"],
    }
