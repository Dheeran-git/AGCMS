"""AGCMS Proxy Gateway — 13-step request lifecycle.

Client → Auth → Rate Limit → PII scan → Injection scan → Policy resolve →
Enforce → Forward to LLM → Response compliance → Audit log → Deliver
"""

import asyncio
import os
import time
import uuid

import asyncpg
import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agcms.gateway.auth import authenticate
from agcms.gateway.dashboard_api import router as dashboard_router
from agcms.gateway.management_api import router as management_router
from agcms.gateway.messages import joined_prompt, redact_messages, reply_text, validate_body
from agcms.gateway.rate_limiter import check_global_ip_rate_limit, check_rate_limit, tenant_rpm
from agcms.gateway.router import forward_to_llm, list_providers, pop_routing
from agcms.gateway.tenant_policy import active_policy

app = FastAPI(
    title="AGCMS Proxy Gateway",
    description="AI Governance and Compliance Monitoring System — Gateway",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router)
app.include_router(management_router)

# Internal service URLs
_PII_URL = os.environ.get("PII_SERVICE_URL", "http://pii:8001")
_INJECTION_URL = os.environ.get("INJECTION_SERVICE_URL", "http://injection:8002")
_RESPONSE_URL = os.environ.get("RESPONSE_SERVICE_URL", "http://response:8003")
_POLICY_URL = os.environ.get("POLICY_SERVICE_URL", "http://policy:8004")
_AUDIT_URL = os.environ.get("AUDIT_SERVICE_URL", "http://audit:8005")

_DB_URL = os.environ.get("DATABASE_URL", "postgresql://agcms:secret@postgres:5432/agcms")

# Governance failure mode. "closed" (default) rejects the request with 503 when
# a scan or the policy service is unavailable, so an outage can never let
# unscreened prompts through. "open" forwards the prompt unscreened and logs it,
# trading governance for availability.
_FAIL_MODE = os.environ.get("AGCMS_FAIL_MODE", "closed").lower()


def _error_response(code: str, reason: str, interaction_id: str, status: int) -> JSONResponse:
    """RULE 7: Structured error responses."""
    return JSONResponse(
        status_code=status,
        content={"error": code, "reason": reason, "interaction_id": interaction_id},
        headers={"X-AGCMS-Interaction-ID": interaction_id},
    )


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "gateway"}


@app.get("/v1/models")
async def list_models():
    """List available LLM providers and their configuration status."""
    return {"object": "list", "data": list_providers()}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """13-step request lifecycle for OpenAI-compatible chat completions."""
    start_time = time.time()
    interaction_id = str(uuid.uuid4())

    # --- Step 1: Parse request ---
    try:
        body = await request.json()
    except Exception:
        return _error_response(
            "invalid_request", "Request body must be valid JSON",
            interaction_id, 400,
        )

    invalid = validate_body(body)
    if invalid:
        return _error_response("invalid_request", invalid, interaction_id, 400)

    prompt_text, segments = joined_prompt(body["messages"])

    # --- Step 1b: Global IP rate limit (pre-auth, prevents key-rotation bypass) ---
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    client_ip = client_ip.split(",")[0].strip()
    ip_allowed, ip_count = await check_global_ip_rate_limit(client_ip)
    if not ip_allowed:
        return _error_response(
            "rate_limited",
            f"Global rate limit exceeded for IP ({ip_count} requests/minute)",
            interaction_id, 429,
        )

    # --- Step 2: Authenticate ---
    auth_header = request.headers.get("Authorization", "")
    ctx, auth_error = await authenticate(auth_header)
    if auth_error or ctx is None:
        return _error_response("auth_failed", auth_error or "auth failed", interaction_id, 401)

    # Scope enforcement: /v1/* ingest routes require the 'ingest' scope.
    # dev_key and JWT callers always carry it via role-derived scopes.
    if not ctx.has_scope("ingest"):
        return _error_response(
            "forbidden",
            "API key lacks 'ingest' scope required for this endpoint",
            interaction_id, 403,
        )

    tenant_id = ctx.tenant_id
    # JWT carries a real user_id claim; for API-key auth we fall back to the
    # client-supplied header (preserves Phase-1 behavior for dashboard/demos).
    if ctx.auth_method == "jwt":
        user_id = ctx.user_id
    else:
        user_id = request.headers.get("X-AGCMS-User-ID", "anonymous")
    department = request.headers.get("X-AGCMS-Department")

    # --- Step 3: Rate limit (limit comes from the tenant's active policy) ---
    try:
        tenant_policy = await active_policy(tenant_id)
    except Exception as exc:
        if _FAIL_MODE == "closed":
            return _error_response(
                "governance_unavailable",
                f"Policy lookup failed ({exc}); request rejected (fail-closed)",
                interaction_id, 503,
            )
        tenant_policy = None
    allowed, count = await check_rate_limit(tenant_id, rpm_limit=tenant_rpm(tenant_policy))
    if not allowed:
        return _error_response(
            "rate_limited",
            f"Rate limit exceeded ({count} requests/minute)",
            interaction_id, 429,
        )

    # --- Steps 4 & 5: PII scan + Injection scan (parallel) ---
    pii_result = None
    injection_result = None

    async with httpx.AsyncClient(timeout=10.0) as client:
        pii_task = client.post(f"{_PII_URL}/scan", json={
            "text": prompt_text, "policy": (tenant_policy or {}).get("pii"),
        })
        injection_task = client.post(f"{_INJECTION_URL}/scan", json={"text": prompt_text})

        pii_resp, injection_resp = await asyncio.gather(
            pii_task, injection_task, return_exceptions=True,
        )

    if isinstance(pii_resp, httpx.Response) and pii_resp.status_code == 200:
        pii_result = pii_resp.json()
    if isinstance(injection_resp, httpx.Response) and injection_resp.status_code == 200:
        injection_result = injection_resp.json()
    if _FAIL_MODE == "closed" and (pii_result is None or injection_result is None):
        failed = [n for n, r in (("pii", pii_result), ("injection", injection_result)) if r is None]
        return _error_response(
            "governance_unavailable",
            f"Detection service unavailable ({', '.join(failed)}); request rejected (fail-closed)",
            interaction_id, 503,
        )

    # --- Step 6: Policy resolution ---
    decision = {"action": "ALLOW", "reason": None, "triggered_policies": []}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            policy_resp = await client.post(f"{_POLICY_URL}/resolve", json={
                "pii_result": pii_result,
                "injection_result": injection_result,
                "policy": tenant_policy,
            })
        if policy_resp.status_code == 200:
            decision = policy_resp.json()
        elif _FAIL_MODE == "closed":
            raise RuntimeError(f"policy service returned {policy_resp.status_code}")
    except Exception as exc:
        if _FAIL_MODE == "closed":
            return _error_response(
                "governance_unavailable",
                f"Policy service unavailable ({exc}); request rejected (fail-closed)",
                interaction_id, 503,
            )
        # fail-open: allow if the policy service is down

    action = decision.get("action", "ALLOW")

    # --- Step 7: Enforce ---
    if action == "BLOCK":
        # Fire-and-forget audit log (RULE 6)
        asyncio.create_task(_audit_log(
            interaction_id, tenant_id, user_id, department, body,
            pii_result, injection_result, decision, None, start_time,
        ))
        return _error_response(
            "request_blocked",
            decision.get("reason", "Request blocked by policy"),
            interaction_id, 403,
        )

    if action == "ESCALATE":
        # Create escalation record (fire-and-forget) and continue processing
        asyncio.create_task(_create_escalation(
            interaction_id=interaction_id,
            tenant_id=tenant_id,
            reason=decision.get("reason", "Escalation triggered by policy"),
            severity="critical",
        ))

    # --- Step 8: Prepare messages for LLM ---
    forwarded_messages = body["messages"]
    if action == "REDACT" and pii_result and pii_result.get("entities"):
        forwarded_messages = redact_messages(forwarded_messages, segments, pii_result["entities"])

    # --- Step 9: Forward to LLM ---
    llm_response = await forward_to_llm(
        messages=forwarded_messages,
        model=body.get("model"),
        temperature=body.get("temperature"),
        max_tokens=body.get("max_tokens"),
        provider=body.get("provider"),
    )

    routing = pop_routing(llm_response)

    # Check for LLM errors
    if "error" in llm_response and "choices" not in llm_response:
        asyncio.create_task(_audit_log(
            interaction_id, tenant_id, user_id, department, body,
            pii_result, injection_result, decision, None, start_time, routing,
        ))
        return _error_response(
            llm_response.get("error", "llm_error"),
            llm_response.get("reason", "LLM request failed"),
            interaction_id, 502,
        )

    # --- Step 10: Response compliance check ---
    response_text = reply_text(llm_response)
    compliance_result = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            comp_resp = await client.post(f"{_RESPONSE_URL}/check", json={
                "response_text": response_text,
                "original_prompt": prompt_text,
                "policy": tenant_policy,
            })
        if comp_resp.status_code == 200:
            compliance_result = comp_resp.json()
    except Exception:
        pass

    # --- Step 11: Audit log (fire-and-forget, RULE 6) ---
    asyncio.create_task(_audit_log(
        interaction_id, tenant_id, user_id, department, body,
        pii_result, injection_result, decision, compliance_result, start_time, routing,
    ))

    # --- Step 12: Deliver response ---
    return JSONResponse(
        content=llm_response,
        headers={"X-AGCMS-Interaction-ID": interaction_id,
                 "X-AGCMS-Provider": routing.get("provider") or "",
                 "X-AGCMS-Failovers": str(len(routing.get("attempts") or []))},
    )


async def _create_escalation(
    interaction_id: str,
    tenant_id: str,
    reason: str,
    severity: str = "warning",
) -> None:
    """Insert an escalation record into the DB (fire-and-forget)."""
    dsn = _DB_URL.replace("postgresql+asyncpg://", "postgresql://")
    try:
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(
                "INSERT INTO escalations (interaction_id, tenant_id, reason, status, severity) "
                "VALUES ($1::uuid, $2, $3, 'PENDING', $4)",
                interaction_id,
                tenant_id,
                reason,
                severity,
            )
        finally:
            await conn.close()
    except Exception:
        pass  # Fire-and-forget: do not crash the response delivery


async def _audit_log(
    interaction_id: str,
    tenant_id: str,
    user_id: str,
    department: str | None,
    raw_body: dict,
    pii_result: dict | None,
    injection_result: dict | None,
    decision: dict | None,
    compliance_result: dict | None,
    start_time: float,
    routing: dict | None = None,
):
    """Send audit log entry to the audit service (fire-and-forget)."""
    routing = routing or {}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{_AUDIT_URL}/log", json={
                "llm_provider": routing.get("provider") or "none",
                "llm_model": routing.get("model"),
                "interaction_id": interaction_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "department": department,
                "raw_body": raw_body,
                "pii_result": pii_result,
                "injection_result": injection_result,
                "decision": decision,
                "compliance_result": compliance_result,
                "start_time": start_time,
            })
    except Exception:
        pass  # Fire-and-forget: do not crash the response delivery
