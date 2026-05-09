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

from agcms.common.observability import init_observability, metrics
from agcms.gateway.auth import authenticate
from agcms.gateway.dashboard_api import router as dashboard_router
from agcms.gateway.gdpr import router as gdpr_router
from agcms.gateway.management_api import router as management_router
from agcms.gateway.onboarding import router as onboarding_router
from agcms.gateway.demo_seed import router as demo_router
from agcms.gateway.changelog import router as changelog_router
from agcms.gateway.notifications import notify, router as notifications_router
from agcms.gateway.openapi_export import install as install_openapi_export
from agcms.gateway.rate_limiter import check_global_ip_rate_limit, check_rate_limit
from agcms.gateway.router import forward_to_llm, list_providers

app = FastAPI(
    title="AGCMS Proxy Gateway",
    description="AI Governance and Compliance Monitoring System — Gateway",
    version="1.0.0",
)

init_observability(app, "gateway")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router)
app.include_router(management_router)
app.include_router(gdpr_router)
app.include_router(onboarding_router)
app.include_router(demo_router)
app.include_router(notifications_router)
app.include_router(changelog_router)
install_openapi_export(app)

# Internal service URLs
_PII_URL = os.environ.get("PII_SERVICE_URL", "http://pii:8001")
_INJECTION_URL = os.environ.get("INJECTION_SERVICE_URL", "http://injection:8002")
_RESPONSE_URL = os.environ.get("RESPONSE_SERVICE_URL", "http://response:8003")
_POLICY_URL = os.environ.get("POLICY_SERVICE_URL", "http://policy:8004")
_AUDIT_URL = os.environ.get("AUDIT_SERVICE_URL", "http://audit:8005")

_DB_URL = os.environ.get("DATABASE_URL", "postgresql://agcms:secret@postgres:5432/agcms")


def _error_response(code: str, reason: str, interaction_id: str, status: int) -> JSONResponse:
    """RULE 7: Structured error responses."""
    return JSONResponse(
        status_code=status,
        content={"error": code, "reason": reason, "interaction_id": interaction_id},
        headers={"X-AGCMS-Interaction-ID": interaction_id},
    )


def _extract_prompt_text(body: dict) -> str:
    """Extract concatenated user message text from OpenAI-format body."""
    messages = body.get("messages", [])
    return " ".join(
        m.get("content", "")
        for m in messages
        if isinstance(m, dict) and m.get("role") == "user" and isinstance(m.get("content"), str)
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

    messages = body.get("messages")
    if not messages or not isinstance(messages, list):
        return _error_response(
            "invalid_request", "Request must include 'messages' array",
            interaction_id, 400,
        )

    prompt_text = _extract_prompt_text(body)

    # --- Step 1b: Global IP rate limit (pre-auth, prevents key-rotation bypass) ---
    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")
    client_ip = client_ip.split(",")[0].strip()
    ip_allowed, ip_count = await check_global_ip_rate_limit(client_ip)
    if not ip_allowed:
        metrics.rate_limit_rejected.labels(tier="ip").inc()
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
    # Tag the request for the observability middleware so per-request
    # counters can group by tenant.
    request.state.tenant_id = tenant_id
    # JWT carries a real user_id claim; for API-key auth we fall back to the
    # client-supplied header (preserves Phase-1 behavior for dashboard/demos).
    if ctx.auth_method == "jwt":
        user_id = ctx.user_id
    else:
        user_id = request.headers.get("X-AGCMS-User-ID", "anonymous")
    department = request.headers.get("X-AGCMS-Department")

    # --- Step 3: Rate limit ---
    allowed, count = await check_rate_limit(tenant_id)
    if not allowed:
        metrics.rate_limit_rejected.labels(tier="tenant").inc()
        return _error_response(
            "rate_limited",
            f"Rate limit exceeded ({count} requests/minute)",
            interaction_id, 429,
        )

    # --- Steps 4 & 5: PII scan + Injection scan (parallel) ---
    pii_result = None
    injection_result = None

    async with httpx.AsyncClient(timeout=10.0) as client:
        pii_task = client.post(f"{_PII_URL}/scan", json={"text": prompt_text})
        injection_task = client.post(f"{_INJECTION_URL}/scan", json={"text": prompt_text})

        pii_resp, injection_resp = await asyncio.gather(
            pii_task, injection_task, return_exceptions=True,
        )

    if isinstance(pii_resp, httpx.Response) and pii_resp.status_code == 200:
        pii_result = pii_resp.json()
        for finding in (pii_result or {}).get("findings", []) or []:
            metrics.pii_detected.labels(
                tenant=tenant_id,
                category=finding.get("type", "unknown"),
            ).inc()
    if isinstance(injection_resp, httpx.Response) and injection_resp.status_code == 200:
        injection_result = injection_resp.json()
        if (injection_result or {}).get("detected"):
            metrics.injection_detected.labels(
                tenant=tenant_id,
                technique=(injection_result.get("technique") or "unknown"),
            ).inc()

    # --- Step 6: Policy resolution ---
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
        pass  # Fail open — allow if policy service is down

    action = decision.get("action", "ALLOW")
    metrics.enforcement_action.labels(tenant=tenant_id, action=action).inc()

    # --- Step 7: Enforce ---
    if action == "BLOCK":
        # Fire-and-forget audit log (RULE 6)
        asyncio.create_task(_audit_log(
            interaction_id, tenant_id, user_id, department, body,
            pii_result, injection_result, decision, None, start_time,
        ))
        asyncio.create_task(_notify_violation(
            tenant_id, "violation", "warning",
            decision.get("reason", "Request blocked by policy"),
            interaction_id, "BLOCK", pii_result, injection_result,
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
        asyncio.create_task(_notify_violation(
            tenant_id, "escalation", "critical",
            decision.get("reason", "Escalation triggered by policy"),
            interaction_id, "ESCALATE", pii_result, injection_result,
        ))

    # --- Step 8: Prepare messages for LLM ---
    forwarded_messages = body.get("messages", [])
    if action == "REDACT" and pii_result and pii_result.get("masked_text"):
        # Replace user messages with masked versions
        masked_text = pii_result["masked_text"]
        forwarded_messages = _redact_messages(forwarded_messages, prompt_text, masked_text)

    # --- Step 9: Forward to LLM ---
    llm_response = await forward_to_llm(
        messages=forwarded_messages,
        model=body.get("model"),
        temperature=body.get("temperature"),
        max_tokens=body.get("max_tokens"),
        provider=body.get("provider"),
    )

    # Check for LLM errors
    if "error" in llm_response and "choices" not in llm_response:
        asyncio.create_task(_audit_log(
            interaction_id, tenant_id, user_id, department, body,
            pii_result, injection_result, decision, None, start_time,
        ))
        return _error_response(
            llm_response.get("error", "llm_error"),
            llm_response.get("reason", "LLM request failed"),
            interaction_id, 502,
        )

    # --- Step 10: Response compliance check ---
    response_text = _extract_response_text(llm_response)
    compliance_result = None
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            comp_resp = await client.post(f"{_RESPONSE_URL}/check", json={
                "response_text": response_text,
                "original_prompt": prompt_text,
            })
        if comp_resp.status_code == 200:
            compliance_result = comp_resp.json()
    except Exception:
        pass

    # --- Step 11: Audit log (fire-and-forget, RULE 6) ---
    asyncio.create_task(_audit_log(
        interaction_id, tenant_id, user_id, department, body,
        pii_result, injection_result, decision, compliance_result, start_time,
    ))

    # --- Step 12: Deliver response ---
    return JSONResponse(
        content=llm_response,
        headers={"X-AGCMS-Interaction-ID": interaction_id},
    )


def _redact_messages(messages: list, original: str, masked: str) -> list:
    """Replace user message content with PII-masked versions."""
    result = []
    for msg in messages:
        if msg.get("role") == "user" and isinstance(msg.get("content"), str):
            content = msg["content"]
            # If this message's content is part of the original prompt, mask it
            if content in original or original in content:
                result.append({**msg, "content": masked})
            else:
                result.append(msg)
        else:
            result.append(msg)
    return result


def _extract_response_text(llm_response: dict) -> str:
    """Extract assistant message text from OpenAI-format response."""
    choices = llm_response.get("choices", [])
    if choices:
        return choices[0].get("message", {}).get("content", "")
    return ""


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


async def _notify_violation(
    tenant_id: str,
    event: str,
    severity: str,
    summary: str,
    interaction_id: str,
    action: str,
    pii_result: dict | None,
    injection_result: dict | None,
) -> None:
    """Fire a notification event into the dispatcher (fire-and-forget)."""
    try:
        details = {
            "interaction_id": interaction_id,
            "action": action,
            "pii_categories": [
                f.get("type") for f in (pii_result or {}).get("findings", []) or []
                if isinstance(f, dict)
            ],
            "injection_detected": bool((injection_result or {}).get("detected")),
        }
        await notify(tenant_id, event, severity, summary, details)
    except Exception:
        pass  # Notifications must never break the request path


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
):
    """Send audit log entry to the audit service (fire-and-forget)."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(f"{_AUDIT_URL}/log", json={
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
