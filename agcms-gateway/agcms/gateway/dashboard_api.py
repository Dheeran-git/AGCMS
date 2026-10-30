"""Dashboard API endpoints — serves data to the React frontend.

All routes are prefixed with /api/dashboard/ and proxied through nginx. Every
route needs an authenticated caller, and every query is scoped to the caller's
tenant. The Playground runs the governed lifecycle as that tenant: its policy,
its rate limit and its audit chain.
"""

import asyncio
import os
import time
import uuid
from typing import Optional

import asyncpg
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from redis.exceptions import RedisError

from agcms.gateway.auth import AuthContext
from agcms.gateway.messages import reply_text
from agcms.gateway.rate_limiter import check_rate_limit, tenant_rpm
from agcms.gateway.rbac import get_current_auth, require_compliance
from agcms.gateway.router import default_provider, forward_to_llm, list_providers, pop_routing
from agcms.gateway.tenant_policy import active_policy

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_DB_URL = os.environ.get("DATABASE_URL", "")

# Service URLs (same env vars as main.py)
_PII_URL = os.environ.get("PII_SERVICE_URL", "http://pii:8001")
_INJECTION_URL = os.environ.get("INJECTION_SERVICE_URL", "http://injection:8002")
_RESPONSE_URL = os.environ.get("RESPONSE_SERVICE_URL", "http://response:8003")
_POLICY_URL = os.environ.get("POLICY_SERVICE_URL", "http://policy:8004")
_AUDIT_URL = os.environ.get("AUDIT_SERVICE_URL", "http://audit:8005")


async def _fetch(query: str, *args, one: bool = False):
    """Run a read query; a database failure is a 503, never an empty 200."""
    try:
        conn = await asyncpg.connect(_DB_URL.replace("+asyncpg", ""))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {exc}") from exc
    try:
        return await (conn.fetchrow(query, *args) if one else conn.fetch(query, *args))
    finally:
        await conn.close()


@router.get("/stats")
async def get_stats(ctx: AuthContext = Depends(require_compliance)):
    """Return the caller's tenant aggregate stats for the last 24 hours."""
    row = await _fetch("""
        SELECT
            COUNT(*) AS total_requests,
            COUNT(*) FILTER (WHERE enforcement_action != 'ALLOW') AS violations,
            COUNT(*) FILTER (WHERE pii_detected = TRUE) AS pii_detections,
            COUNT(*) FILTER (WHERE injection_score > 0.5) AS injection_blocks,
            AVG(total_latency_ms) AS avg_latency_ms
        FROM audit_logs
        WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'
    """, ctx.tenant_id, one=True)
    return {
        "total_requests": row["total_requests"],
        "violations": row["violations"],
        "pii_detections": row["pii_detections"],
        "injection_blocks": row["injection_blocks"],
        "avg_latency_ms": round(row["avg_latency_ms"] or 0, 1),
        "period": "24h",
    }


@router.get("/violations")
async def get_violations(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    ctx: AuthContext = Depends(require_compliance),
):
    """Return the caller's tenant's recent non-ALLOW decisions."""
    rows = await _fetch("""
        SELECT
            interaction_id, tenant_id, user_id, department, created_at,
            enforcement_action, enforcement_reason, pii_detected, pii_entity_types,
            pii_risk_level, injection_score, injection_type, response_violated,
            total_latency_ms
        FROM audit_logs
        WHERE tenant_id = $1 AND enforcement_action != 'ALLOW'
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    """, ctx.tenant_id, limit, offset)
    total = await _fetch("""
        SELECT COUNT(*) AS n FROM audit_logs
        WHERE tenant_id = $1 AND enforcement_action != 'ALLOW'
    """, ctx.tenant_id, one=True)
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
                "injection_score": float(r["injection_score"]) if r["injection_score"] is not None else None,
                "injection_type": r["injection_type"],
                "response_violated": r["response_violated"],
                "latency_ms": r["total_latency_ms"],
            }
            for r in rows
        ],
        "total": total["n"],
        "limit": limit,
        "offset": offset,
    }


@router.get("/timeline")
async def get_timeline(
    hours: int = Query(24, ge=1, le=720),
    ctx: AuthContext = Depends(require_compliance),
):
    """Return the caller's tenant's hourly request counts for the chart."""
    rows = await _fetch("""
        SELECT
            date_trunc('hour', created_at) AS hour,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE enforcement_action != 'ALLOW') AS violations,
            COUNT(*) FILTER (WHERE pii_detected = TRUE) AS pii
        FROM audit_logs
        WHERE tenant_id = $1 AND created_at >= NOW() - make_interval(hours => $2)
        GROUP BY hour
        ORDER BY hour
    """, ctx.tenant_id, hours)
    return {
        "timeline": [
            {"hour": r["hour"].isoformat(), "total": r["total"],
             "violations": r["violations"], "pii": r["pii"]}
            for r in rows
        ],
    }


# ---------------------------------------------------------------------------
# Playground Chat — enriched lifecycle with governance metadata
# ---------------------------------------------------------------------------

_MAX_MESSAGE_CHARS = 8000


class PlaygroundChatRequest(BaseModel):
    message: str = Field(..., max_length=_MAX_MESSAGE_CHARS)
    provider: Optional[str] = None


def _unavailable(what: str) -> HTTPException:
    return HTTPException(status_code=503, detail=f"{what} unavailable; request rejected (fail-closed)")


async def _scan(prompt_text: str, tenant_policy: Optional[dict]) -> tuple[dict, dict]:
    """PII and injection scans in parallel; either failing is a 503."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        pii_resp, inj_resp = await asyncio.gather(
            client.post(f"{_PII_URL}/scan", json={
                "text": prompt_text, "policy": (tenant_policy or {}).get("pii"),
            }),
            client.post(f"{_INJECTION_URL}/scan", json={"text": prompt_text}),
            return_exceptions=True,
        )
    for name, resp in (("PII scan", pii_resp), ("Injection scan", inj_resp)):
        if not (isinstance(resp, httpx.Response) and resp.status_code == 200):
            raise _unavailable(name)
    return pii_resp.json(), inj_resp.json()


async def _resolve(pii_result: dict, injection_result: dict, tenant_policy: Optional[dict]) -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{_POLICY_URL}/resolve", json={
                "pii_result": pii_result, "injection_result": injection_result, "policy": tenant_policy,
            })
    except httpx.HTTPError as exc:
        raise _unavailable("Policy service") from exc
    if resp.status_code != 200:
        raise _unavailable("Policy service")
    return resp.json()


async def _check(response_text: str, prompt_text: str, tenant_policy: Optional[dict]) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(f"{_RESPONSE_URL}/check", json={
                "response_text": response_text, "original_prompt": prompt_text, "policy": tenant_policy,
            })
        return resp.json() if resp.status_code == 200 else None
    except httpx.HTTPError:
        return None


@router.post("/playground/chat")
async def playground_chat(req: PlaygroundChatRequest, ctx: AuthContext = Depends(require_compliance)):
    """Run the governed lifecycle as the caller's tenant and return full metadata."""
    total_start = time.time()
    interaction_id = str(uuid.uuid4())
    prompt_text = req.message.strip()
    if not prompt_text:
        raise HTTPException(status_code=422, detail="Message must not be empty.")

    try:
        tenant_policy = await active_policy(ctx.tenant_id)
    except Exception as exc:
        raise _unavailable("Policy lookup") from exc
    try:
        allowed, count = await check_rate_limit(ctx.tenant_id, rpm_limit=tenant_rpm(tenant_policy))
    except RedisError as exc:
        raise _unavailable("Rate limiter") from exc
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded ({count} requests/minute)")

    scan_start = time.time()
    pii_result, injection_result = await _scan(prompt_text, tenant_policy)
    scan_ms = round((time.time() - scan_start) * 1000, 1)

    policy_start = time.time()
    decision = await _resolve(pii_result, injection_result, tenant_policy)
    policy_ms = round((time.time() - policy_start) * 1000, 1)

    action = decision.get("action", "ALLOW")
    masked_text = pii_result.get("masked_text")
    routing: dict = {}
    llm_response_text = None
    llm_error = None
    compliance_result = None
    llm_ms = compliance_ms = 0.0

    if action != "BLOCK":
        content = masked_text if action == "REDACT" and masked_text else prompt_text
        llm_start = time.time()
        llm_result = await forward_to_llm(messages=[{"role": "user", "content": content}], provider=req.provider)
        llm_ms = round((time.time() - llm_start) * 1000, 1)
        routing = pop_routing(llm_result)
        llm_response_text = reply_text(llm_result) or None
        if not llm_response_text and "error" in llm_result:
            llm_error = str(llm_result.get("reason") or llm_result.get("error"))
        if llm_response_text:
            comp_start = time.time()
            compliance_result = await _check(llm_response_text, prompt_text, tenant_policy)
            compliance_ms = round((time.time() - comp_start) * 1000, 1)

    total_ms = round((time.time() - total_start) * 1000, 1)

    async def _log():
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(f"{_AUDIT_URL}/log", json={
                    "interaction_id": interaction_id,
                    "tenant_id": ctx.tenant_id,
                    "user_id": ctx.user_id,
                    "department": "playground",
                    "raw_body": {"messages": [{"role": "user", "content": prompt_text}]},
                    "pii_result": pii_result,
                    "injection_result": injection_result,
                    "decision": decision,
                    "compliance_result": compliance_result,
                    "start_time": total_start,
                    "llm_provider": routing.get("provider") or "none",
                    "llm_model": routing.get("model"),
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
        "llm_error": llm_error,
        "llm_provider": routing.get("provider"),
        "llm_model": routing.get("model"),
        "llm_attempts": routing.get("attempts", []),
        "original_text": prompt_text,
        "masked_text": masked_text,
        "timing": {
            "pii_ms": scan_ms,
            "injection_ms": scan_ms,  # ran in parallel with the PII scan
            "policy_ms": policy_ms,
            "llm_ms": llm_ms,
            "compliance_ms": compliance_ms,
            "total_ms": total_ms,
        },
    }


@router.get("/playground/providers")
async def get_playground_providers(ctx: AuthContext = Depends(get_current_auth)):
    """List LLM providers and whether each one's API key is configured.

    Powers the provider picker in the Playground UI. Providers are listed in
    failover order: Gemini, Groq, OpenRouter, local Ollama.
    """
    return {"providers": list_providers(), "default": default_provider()}
