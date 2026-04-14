"""Dashboard API endpoints — serves data to the React frontend.

All routes are prefixed with /api/dashboard/ and proxied through nginx.
"""

import asyncio
import os
import time
import uuid

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

from agcms.gateway.router import forward_to_llm

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_DB_URL = os.environ.get("DATABASE_URL", "")

# Service URLs (same env vars as main.py)
_PII_URL = os.environ.get("PII_SERVICE_URL", "http://pii:8001")
_INJECTION_URL = os.environ.get("INJECTION_SERVICE_URL", "http://injection:8002")
_RESPONSE_URL = os.environ.get("RESPONSE_SERVICE_URL", "http://response:8003")
_POLICY_URL = os.environ.get("POLICY_SERVICE_URL", "http://policy:8004")
_AUDIT_URL = os.environ.get("AUDIT_SERVICE_URL", "http://audit:8005")


@router.get("/stats")
async def get_stats():
    """Return aggregate stats for the overview dashboard."""
    # Query PostgreSQL via audit service or directly
    # Phase 1: return stats from a direct DB query
    try:
        import asyncpg
        conn = await asyncpg.connect(_DB_URL.replace("+asyncpg", ""))
        try:
            row = await conn.fetchrow("""
                SELECT
                    COUNT(*) AS total_requests,
                    COUNT(*) FILTER (WHERE enforcement_action != 'ALLOW') AS violations,
                    COUNT(*) FILTER (WHERE pii_detected = TRUE) AS pii_detections,
                    COUNT(*) FILTER (WHERE injection_score > 0.5) AS injection_blocks,
                    AVG(total_latency_ms) AS avg_latency_ms
                FROM audit_logs
                WHERE created_at >= NOW() - INTERVAL '24 hours'
            """)
            return {
                "total_requests": row["total_requests"],
                "violations": row["violations"],
                "pii_detections": row["pii_detections"],
                "injection_blocks": row["injection_blocks"],
                "avg_latency_ms": round(row["avg_latency_ms"] or 0, 1),
                "period": "24h",
            }
        finally:
            await conn.close()
    except Exception as e:
        return {
            "total_requests": 0,
            "violations": 0,
            "pii_detections": 0,
            "injection_blocks": 0,
            "avg_latency_ms": 0,
            "period": "24h",
            "error": str(e),
        }


@router.get("/violations")
async def get_violations(limit: int = 50, offset: int = 0):
    """Return recent violations for the violations page."""
    try:
        import asyncpg
        conn = await asyncpg.connect(_DB_URL.replace("+asyncpg", ""))
        try:
            rows = await conn.fetch("""
                SELECT
                    interaction_id,
                    tenant_id,
                    user_id,
                    department,
                    created_at,
                    enforcement_action,
                    enforcement_reason,
                    pii_detected,
                    pii_entity_types,
                    pii_risk_level,
                    injection_score,
                    injection_type,
                    response_violated,
                    total_latency_ms
                FROM audit_logs
                WHERE enforcement_action != 'ALLOW'
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
            """, limit, offset)

            total = await conn.fetchval("""
                SELECT COUNT(*) FROM audit_logs
                WHERE enforcement_action != 'ALLOW'
            """)

            return {
                "violations": [
                    {
                        "interaction_id": str(r["interaction_id"]),
                        "tenant_id": r["tenant_id"],
                        "user_id": r["user_id"],
                        "department": r["department"],
                        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                        "action": r["enforcement_action"],
                        "reason": r["enforcement_reason"],
                        "pii_detected": r["pii_detected"],
                        "pii_entity_types": r["pii_entity_types"] or [],
                        "pii_risk_level": r["pii_risk_level"],
                        "injection_score": float(r["injection_score"]) if r["injection_score"] else None,
                        "injection_type": r["injection_type"],
                        "response_violated": r["response_violated"],
                        "latency_ms": r["total_latency_ms"],
                    }
                    for r in rows
                ],
                "total": total,
                "limit": limit,
                "offset": offset,
            }
        finally:
            await conn.close()
    except Exception as e:
        return {"violations": [], "total": 0, "limit": limit, "offset": offset, "error": str(e)}


@router.get("/timeline")
async def get_timeline(hours: int = 24):
    """Return hourly request counts for the chart."""
    try:
        import asyncpg
        conn = await asyncpg.connect(_DB_URL.replace("+asyncpg", ""))
        try:
            rows = await conn.fetch("""
                SELECT
                    date_trunc('hour', created_at) AS hour,
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE enforcement_action != 'ALLOW') AS violations,
                    COUNT(*) FILTER (WHERE pii_detected = TRUE) AS pii
                FROM audit_logs
                WHERE created_at >= NOW() - make_interval(hours => $1)
                GROUP BY hour
                ORDER BY hour
            """, hours)
            return {
                "timeline": [
                    {
                        "hour": r["hour"].isoformat(),
                        "total": r["total"],
                        "violations": r["violations"],
                        "pii": r["pii"],
                    }
                    for r in rows
                ],
            }
        finally:
            await conn.close()
    except Exception as e:
        return {"timeline": [], "error": str(e)}


# ---------------------------------------------------------------------------
# Playground Chat — enriched lifecycle with governance metadata
# ---------------------------------------------------------------------------

class PlaygroundChatRequest(BaseModel):
    message: str


@router.post("/playground/chat")
async def playground_chat(req: PlaygroundChatRequest):
    """Run the 13-step governance lifecycle and return full metadata."""
    total_start = time.time()
    interaction_id = str(uuid.uuid4())
    prompt_text = req.message

    # --- Steps 4 & 5: PII + Injection scan (parallel) ---
    pii_result = {"has_pii": False, "risk_level": "NONE", "entity_types": [], "entities": [], "masked_text": None}
    injection_result = {"risk_score": 0.0, "attack_type": None, "is_injection": False, "triggered_rules": []}

    pii_start = time.time()
    inj_start = pii_start
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            pii_task = client.post(f"{_PII_URL}/scan", json={"text": prompt_text})
            inj_task = client.post(f"{_INJECTION_URL}/scan", json={"text": prompt_text})
            pii_resp, inj_resp = await asyncio.gather(pii_task, inj_task, return_exceptions=True)

        if isinstance(pii_resp, httpx.Response) and pii_resp.status_code == 200:
            pii_result = pii_resp.json()
        if isinstance(inj_resp, httpx.Response) and inj_resp.status_code == 200:
            injection_result = inj_resp.json()
    except Exception:
        pass
    pii_ms = round((time.time() - pii_start) * 1000, 1)
    inj_ms = pii_ms  # ran in parallel

    # --- Step 6: Policy resolution ---
    policy_start = time.time()
    decision = {"action": "ALLOW", "reason": None, "triggered_policies": []}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            policy_resp = await client.post(f"{_POLICY_URL}/resolve", json={
                "pii_result": pii_result,
                "injection_result": injection_result,
            })
        if policy_resp.status_code == 200:
            decision = policy_resp.json()
    except Exception:
        pass
    policy_ms = round((time.time() - policy_start) * 1000, 1)

    action = decision.get("action", "ALLOW")
    masked_text = pii_result.get("masked_text")

    # --- Steps 7-10: Enforce → LLM → Compliance ---
    llm_response_text = None
    compliance_result = None
    llm_ms = 0.0
    compliance_ms = 0.0

    if action != "BLOCK":
        # Prepare messages
        if action == "REDACT" and masked_text:
            messages = [{"role": "user", "content": masked_text}]
        else:
            messages = [{"role": "user", "content": prompt_text}]

        # Forward to LLM
        llm_start = time.time()
        llm_result = await forward_to_llm(messages=messages)
        llm_ms = round((time.time() - llm_start) * 1000, 1)

        # Extract response text
        if "choices" in llm_result:
            choices = llm_result.get("choices", [])
            if choices:
                llm_response_text = choices[0].get("message", {}).get("content", "")

        # Response compliance check
        if llm_response_text:
            comp_start = time.time()
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    comp_resp = await client.post(f"{_RESPONSE_URL}/check", json={
                        "response_text": llm_response_text,
                        "original_prompt": prompt_text,
                    })
                if comp_resp.status_code == 200:
                    compliance_result = comp_resp.json()
            except Exception:
                pass
            compliance_ms = round((time.time() - comp_start) * 1000, 1)

    total_ms = round((time.time() - total_start) * 1000, 1)

    # Fire-and-forget audit log
    async def _log():
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(f"{_AUDIT_URL}/log", json={
                    "interaction_id": interaction_id,
                    "tenant_id": "playground",
                    "user_id": "demo-user",
                    "department": None,
                    "raw_body": {"messages": [{"role": "user", "content": prompt_text}]},
                    "pii_result": pii_result,
                    "injection_result": injection_result,
                    "decision": decision,
                    "compliance_result": compliance_result,
                    "start_time": total_start,
                    "llm_provider": "groq",
                })
        except Exception:
            pass

    asyncio.create_task(_log())

    return {
        "interaction_id": interaction_id,
        "governance": {
            "pii": pii_result,
            "injection": injection_result,
            "policy": decision,
            "compliance": compliance_result,
        },
        "llm_response": llm_response_text,
        "original_text": prompt_text,
        "masked_text": masked_text,
        "timing": {
            "pii_ms": pii_ms,
            "injection_ms": inj_ms,
            "policy_ms": policy_ms,
            "llm_ms": llm_ms,
            "compliance_ms": compliance_ms,
            "total_ms": total_ms,
        },
    }
