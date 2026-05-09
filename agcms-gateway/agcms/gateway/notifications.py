"""Notification dispatcher + provider adapters.

A tenant configures one or more *providers* (Slack channel, PagerDuty
service key, generic webhook URL, SMTP relay, Splunk HEC) and one or
more *rules* that map ``(trigger_event, severity_min)`` → provider.

When the gateway emits an event via :func:`notify`, the dispatcher
loads matching rules, fans out to each provider's adapter, retries
twice with exponential backoff on transient failures, and records
every attempt in ``notification_deliveries``.

Outbound calls run inside a fire-and-forget task so they never block
the request path; failures only surface via the deliveries table and
the metrics counter.

Webhooks are HMAC-SHA256-signed with a per-provider shared secret
(``config.signing_secret``); receivers verify by recomputing the HMAC
over the raw body and comparing it to the ``X-AGCMS-Signature`` header.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import smtplib
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Any, Literal

import asyncpg
import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_admin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])

_DB_URL = os.environ.get("DATABASE_URL", "")


def _db_dsn() -> str:
    return _DB_URL.replace("+asyncpg", "")


PROVIDER_KINDS = ("slack", "pagerduty", "webhook", "email", "splunk_hec")
TRIGGER_EVENTS = ("violation", "escalation", "audit_chain_break", "rate_limit_breach")
SEVERITIES = ("info", "warning", "critical")
SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}

Severity = Literal["info", "warning", "critical"]
TriggerEvent = Literal["violation", "escalation", "audit_chain_break", "rate_limit_breach"]


# ============================================================
# Pydantic schemas
# ============================================================


class ProviderCreate(BaseModel):
    kind: str = Field(..., description="One of slack/pagerduty/webhook/email/splunk_hec")
    name: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class RuleCreate(BaseModel):
    provider_id: str
    trigger_event: str
    severity_min: str = "info"
    enabled: bool = True


# ============================================================
# Provider adapters
# ============================================================


def sign_webhook_payload(secret: str, body: bytes) -> str:
    """HMAC-SHA256 hex digest, lowercase. Receiver-side verification is
    a single hmac.compare_digest call against the X-AGCMS-Signature header."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def _send_slack(config: dict[str, Any], payload: dict[str, Any]) -> None:
    url = config.get("webhook_url") or ""
    if not url:
        raise ValueError("slack provider missing config.webhook_url")
    body = {
        "text": _slack_text(payload),
        "username": "AGCMS",
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(url, json=body)
        resp.raise_for_status()


def _slack_text(payload: dict[str, Any]) -> str:
    sev = payload.get("severity", "info").upper()
    event = payload.get("event", "?")
    summary = payload.get("summary", "")
    return f"[{sev}] {event} — {summary}"


async def _send_pagerduty(config: dict[str, Any], payload: dict[str, Any]) -> None:
    routing_key = config.get("routing_key") or ""
    if not routing_key:
        raise ValueError("pagerduty provider missing config.routing_key")
    sev = payload.get("severity", "info")
    body = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": payload.get("dedup_key") or str(uuid.uuid4()),
        "payload": {
            "summary": payload.get("summary", "AGCMS event"),
            "severity": "critical" if sev == "critical" else "warning",
            "source": "agcms",
            "custom_details": payload,
        },
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            "https://events.pagerduty.com/v2/enqueue", json=body
        )
        resp.raise_for_status()


async def _send_webhook(config: dict[str, Any], payload: dict[str, Any]) -> None:
    url = config.get("url") or ""
    if not url:
        raise ValueError("webhook provider missing config.url")
    secret = config.get("signing_secret") or ""
    body = json.dumps(payload, sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-AGCMS-Signature"] = sign_webhook_payload(secret, body)
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(url, content=body, headers=headers)
        resp.raise_for_status()


async def _send_email(config: dict[str, Any], payload: dict[str, Any]) -> None:
    host = config.get("smtp_host") or ""
    if not host:
        raise ValueError("email provider missing config.smtp_host")
    port = int(config.get("smtp_port", 587))
    user = config.get("username") or ""
    pwd = config.get("password") or ""
    from_addr = config.get("from_addr") or "alerts@agcms.local"
    to_addrs = config.get("to_addrs") or []
    if not to_addrs:
        raise ValueError("email provider missing config.to_addrs")

    subject = f"[AGCMS {payload.get('severity','info').upper()}] {payload.get('event','event')}"
    body = json.dumps(payload, indent=2, sort_keys=True)
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    def _blocking_send():
        with smtplib.SMTP(host, port, timeout=5.0) as srv:
            srv.ehlo()
            if config.get("starttls", True):
                srv.starttls()
            if user:
                srv.login(user, pwd)
            srv.sendmail(from_addr, to_addrs, msg.as_string())

    await asyncio.to_thread(_blocking_send)


async def _send_splunk_hec(config: dict[str, Any], payload: dict[str, Any]) -> None:
    url = config.get("url") or ""
    token = config.get("token") or ""
    if not url or not token:
        raise ValueError("splunk_hec provider missing config.url or config.token")
    body = {
        "time": int(datetime.now(timezone.utc).timestamp()),
        "host": "agcms",
        "source": "agcms",
        "sourcetype": "agcms:event",
        "event": payload,
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Splunk {token}"},
            json=body,
        )
        resp.raise_for_status()


PROVIDER_DISPATCH = {
    "slack": _send_slack,
    "pagerduty": _send_pagerduty,
    "webhook": _send_webhook,
    "email": _send_email,
    "splunk_hec": _send_splunk_hec,
}


# ============================================================
# Dispatcher
# ============================================================


async def _matching_rules(
    conn: asyncpg.Connection,
    tenant_id: str,
    event: str,
    severity: str,
) -> list[asyncpg.Record]:
    rank_floor = SEVERITY_RANK[severity]
    rows = await conn.fetch(
        """
        SELECT r.id AS rule_id, r.severity_min,
               p.id AS provider_id, p.kind, p.config
        FROM notification_rules r
        JOIN notification_providers p ON p.id = r.provider_id
        WHERE r.tenant_id = $1
          AND r.trigger_event = $2
          AND r.enabled = TRUE
          AND p.enabled = TRUE
        """,
        tenant_id,
        event,
    )
    return [r for r in rows if SEVERITY_RANK[r["severity_min"]] <= rank_floor]


async def _record_delivery(
    conn: asyncpg.Connection,
    tenant_id: str,
    rule_id: uuid.UUID | None,
    provider_kind: str,
    event: str,
    severity: str,
    status: str,
    attempts: int,
    error: str | None,
    payload: dict[str, Any],
) -> None:
    await conn.execute(
        """
        INSERT INTO notification_deliveries
            (tenant_id, rule_id, provider_kind, trigger_event, severity,
             status, attempts, error, payload)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
        """,
        tenant_id,
        rule_id,
        provider_kind,
        event,
        severity,
        status,
        attempts,
        error,
        json.dumps(payload),
    )


async def _send_with_retries(
    kind: str,
    config: dict[str, Any],
    payload: dict[str, Any],
    max_attempts: int = 3,
) -> tuple[str, int, str | None]:
    """Try sending up to ``max_attempts`` times with exponential backoff.
    Returns (status, attempts, error_message_or_None)."""
    sender = PROVIDER_DISPATCH.get(kind)
    if sender is None:
        return ("failed", 1, f"unknown provider kind: {kind}")
    attempt = 0
    last_err: str | None = None
    while attempt < max_attempts:
        attempt += 1
        try:
            await sender(config, payload)
            return ("sent", attempt, None)
        except Exception as exc:  # pragma: no cover — exercised via tests
            last_err = f"{type(exc).__name__}: {exc}"
            log.warning("notification %s attempt %d failed: %s", kind, attempt, last_err)
            if attempt < max_attempts:
                await asyncio.sleep(0.2 * (2 ** (attempt - 1)))
    return ("failed", attempt, last_err)


async def notify(
    tenant_id: str,
    event: TriggerEvent,
    severity: Severity,
    summary: str,
    details: dict[str, Any] | None = None,
) -> int:
    """Fan out an event to every configured + matching provider.

    Returns the number of providers the event was dispatched to. Runs
    in the caller's task — wrap in ``asyncio.create_task`` if you need
    fire-and-forget semantics on the request path.
    """
    payload = {
        "event": event,
        "severity": severity,
        "summary": summary,
        "tenant_id": tenant_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        **(details or {}),
    }
    conn = await asyncpg.connect(_db_dsn())
    try:
        rules = await _matching_rules(conn, tenant_id, event, severity)
        for r in rules:
            status, attempts, err = await _send_with_retries(
                r["kind"], r["config"] or {}, payload
            )
            await _record_delivery(
                conn,
                tenant_id,
                r["rule_id"],
                r["kind"],
                event,
                severity,
                status,
                attempts,
                err,
                payload,
            )
        return len(rules)
    finally:
        await conn.close()


# ============================================================
# Management endpoints
# ============================================================


@router.get("/providers")
async def list_providers(ctx: AuthContext = Depends(require_admin)):
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            "SELECT id, kind, name, config, enabled, created_at "
            "FROM notification_providers WHERE tenant_id = $1 ORDER BY created_at DESC",
            ctx.tenant_id,
        )
    finally:
        await conn.close()
    return {
        "providers": [
            {
                "id": str(r["id"]),
                "kind": r["kind"],
                "name": r["name"],
                "config": _redact_config(r["kind"], r["config"] or {}),
                "enabled": r["enabled"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


def _redact_config(kind: str, config: dict[str, Any]) -> dict[str, Any]:
    """Hide secret-looking fields when listing providers — they shouldn't
    leak back to admins via the management API even though the admin set them."""
    redacted = dict(config)
    for k in ("signing_secret", "password", "token", "routing_key"):
        if k in redacted and redacted[k]:
            v = str(redacted[k])
            redacted[k] = v[:4] + "•" * max(0, len(v) - 8) + v[-4:] if len(v) > 8 else "••••"
    return redacted


@router.post("/providers")
async def create_provider(
    body: ProviderCreate, ctx: AuthContext = Depends(require_admin)
):
    if body.kind not in PROVIDER_KINDS:
        raise HTTPException(400, f"unknown kind '{body.kind}'")
    conn = await asyncpg.connect(_db_dsn())
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO notification_providers (tenant_id, kind, name, config, enabled)
            VALUES ($1, $2, $3, $4::jsonb, $5)
            RETURNING id, kind, name, enabled, created_at
            """,
            ctx.tenant_id,
            body.kind,
            body.name,
            json.dumps(body.config),
            body.enabled,
        )
    finally:
        await conn.close()
    return {
        "id": str(row["id"]),
        "kind": row["kind"],
        "name": row["name"],
        "enabled": row["enabled"],
        "created_at": row["created_at"].isoformat(),
    }


@router.delete("/providers/{provider_id}")
async def delete_provider(
    provider_id: str, ctx: AuthContext = Depends(require_admin)
):
    conn = await asyncpg.connect(_db_dsn())
    try:
        result = await conn.execute(
            "DELETE FROM notification_providers WHERE id = $1 AND tenant_id = $2",
            provider_id,
            ctx.tenant_id,
        )
    finally:
        await conn.close()
    if result.endswith(" 0"):
        raise HTTPException(404, "provider not found")
    return {"deleted": provider_id}


@router.post("/providers/{provider_id}/test")
async def test_provider(
    provider_id: str, ctx: AuthContext = Depends(require_admin)
):
    conn = await asyncpg.connect(_db_dsn())
    try:
        row = await conn.fetchrow(
            "SELECT kind, config FROM notification_providers "
            "WHERE id = $1 AND tenant_id = $2",
            provider_id,
            ctx.tenant_id,
        )
    finally:
        await conn.close()
    if row is None:
        raise HTTPException(404, "provider not found")
    payload = {
        "event": "test",
        "severity": "info",
        "summary": "AGCMS notification test",
        "tenant_id": ctx.tenant_id,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    status, attempts, err = await _send_with_retries(
        row["kind"], row["config"] or {}, payload, max_attempts=1
    )
    if status != "sent":
        raise HTTPException(502, f"test send failed: {err}")
    return {"status": "sent", "attempts": attempts}


@router.get("/rules")
async def list_rules(ctx: AuthContext = Depends(require_admin)):
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            "SELECT id, provider_id, trigger_event, severity_min, enabled, created_at "
            "FROM notification_rules WHERE tenant_id = $1 ORDER BY created_at DESC",
            ctx.tenant_id,
        )
    finally:
        await conn.close()
    return {
        "rules": [
            {
                "id": str(r["id"]),
                "provider_id": str(r["provider_id"]),
                "trigger_event": r["trigger_event"],
                "severity_min": r["severity_min"],
                "enabled": r["enabled"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ]
    }


@router.post("/rules")
async def create_rule(body: RuleCreate, ctx: AuthContext = Depends(require_admin)):
    if body.trigger_event not in TRIGGER_EVENTS:
        raise HTTPException(400, f"unknown trigger '{body.trigger_event}'")
    if body.severity_min not in SEVERITIES:
        raise HTTPException(400, f"unknown severity '{body.severity_min}'")
    conn = await asyncpg.connect(_db_dsn())
    try:
        # Make sure the provider belongs to this tenant.
        provider = await conn.fetchrow(
            "SELECT id FROM notification_providers WHERE id = $1 AND tenant_id = $2",
            body.provider_id,
            ctx.tenant_id,
        )
        if provider is None:
            raise HTTPException(404, "provider not found")
        row = await conn.fetchrow(
            """
            INSERT INTO notification_rules
                (tenant_id, provider_id, trigger_event, severity_min, enabled)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, created_at
            """,
            ctx.tenant_id,
            body.provider_id,
            body.trigger_event,
            body.severity_min,
            body.enabled,
        )
    finally:
        await conn.close()
    return {
        "id": str(row["id"]),
        "provider_id": body.provider_id,
        "trigger_event": body.trigger_event,
        "severity_min": body.severity_min,
        "enabled": body.enabled,
        "created_at": row["created_at"].isoformat(),
    }


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str, ctx: AuthContext = Depends(require_admin)):
    conn = await asyncpg.connect(_db_dsn())
    try:
        result = await conn.execute(
            "DELETE FROM notification_rules WHERE id = $1 AND tenant_id = $2",
            rule_id,
            ctx.tenant_id,
        )
    finally:
        await conn.close()
    if result.endswith(" 0"):
        raise HTTPException(404, "rule not found")
    return {"deleted": rule_id}


@router.get("/deliveries")
async def list_deliveries(
    ctx: AuthContext = Depends(require_admin), limit: int = 50
):
    conn = await asyncpg.connect(_db_dsn())
    try:
        rows = await conn.fetch(
            "SELECT id, provider_kind, trigger_event, severity, status, attempts, "
            "error, created_at FROM notification_deliveries "
            "WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2",
            ctx.tenant_id,
            limit,
        )
    finally:
        await conn.close()
    return {
        "deliveries": [
            {
                "id": str(r["id"]),
                "provider_kind": r["provider_kind"],
                "trigger_event": r["trigger_event"],
                "severity": r["severity"],
                "status": r["status"],
                "attempts": r["attempts"],
                "error": r["error"],
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ]
    }


__all__ = [
    "router",
    "notify",
    "sign_webhook_payload",
    "PROVIDER_KINDS",
    "TRIGGER_EVENTS",
    "SEVERITIES",
]
