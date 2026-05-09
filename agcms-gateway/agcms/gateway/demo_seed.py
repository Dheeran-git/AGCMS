"""Demo / sample data seeder.

Tenant admins can flip ``demo_mode_enabled`` to populate their tenant
with a realistic mix of audit rows, violations, escalations, and users —
purpose-built for sales demos and CCO walkthroughs without exposing real
prod data.

Demo audit rows carry ``schema_version = 'DEMO-1.0'`` and a placeholder
log_signature. The chain verifier knows to skip them (they're sandbox
data, not part of the tamper-evident chain). Removal is a hard delete
keyed on the schema_version sentinel and a ``[DEMO]`` reason prefix on
escalations + an ``external_id`` prefix on demo users.
"""
from __future__ import annotations

import hashlib
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_admin

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])

_DEMO_SCHEMA = "DEMO-1.0"
_DEMO_REASON_PREFIX = "[DEMO]"
_DEMO_USER_PREFIX = "demo-user-"

_DB_URL = os.environ.get("DATABASE_URL", "")


def _db_dsn() -> str:
    return _DB_URL.replace("+asyncpg", "")


# ─── Vocabularies for realistic data ─────────────────────────────────────────

_DEPARTMENTS = ["engineering", "support", "marketing", "legal"]

_DEMO_USERS = [
    ("alex.chen", "engineering"),
    ("priya.menon", "engineering"),
    ("daria.silva", "engineering"),
    ("tom.nakamura", "engineering"),
    ("noor.jansen", "support"),
    ("sam.olivera", "support"),
    ("carla.dimitriou", "support"),
    ("jordan.brooks", "support"),
    ("hassan.kaur", "marketing"),
    ("mei.lebowski", "marketing"),
    ("riley.almasi", "marketing"),
    ("vincent.tahiri", "legal"),
    ("ines.sundberg", "legal"),
    ("oliver.adekunle", "legal"),
    ("fatou.kowalski", "legal"),
]

_PII_CATEGORIES = [
    "us_ssn",
    "email",
    "phone_number",
    "credit_card_number",
    "medical_record_number",
    "diagnosis_code",
]

_INJECTION_TYPES = ["direct", "jailbreak", "role_manipulation", "instruction_override"]

_LLM_PROVIDERS = ["groq", "gemini", "mistral", "ollama"]


def _fake_signature(*parts: str) -> str:
    h = hashlib.sha256(("|".join(parts) + "|demo").encode()).hexdigest()
    return h


def _random_action() -> str:
    # 75% ALLOW, 15% REDACT, 7% BLOCK, 3% ESCALATE — close to typical mix
    r = random.random()
    if r < 0.75:
        return "ALLOW"
    if r < 0.90:
        return "REDACT"
    if r < 0.97:
        return "BLOCK"
    return "ESCALATE"


def _random_demo_row(tenant_id: str, user_external_id: str, dept: str) -> dict[str, Any]:
    action = _random_action()
    has_pii = action in ("REDACT", "BLOCK") or random.random() < 0.1
    has_injection = action in ("BLOCK", "ESCALATE") and random.random() < 0.4

    pii_cats = (
        random.sample(_PII_CATEGORIES, k=random.randint(1, 2)) if has_pii else None
    )
    risk_level = (
        random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]) if has_pii else None
    )
    injection_score = round(random.uniform(0.55, 0.95), 3) if has_injection else None
    injection_type = random.choice(_INJECTION_TYPES) if has_injection else None

    created_at = datetime.now(timezone.utc) - timedelta(
        seconds=random.randint(60, 30 * 24 * 3600)  # last 30 days
    )

    interaction_id = uuid.uuid4()
    prompt_text = f"demo-prompt-{interaction_id}"
    return {
        "interaction_id": interaction_id,
        "tenant_id": tenant_id,
        "user_id": user_external_id,
        "department": dept,
        "created_at": created_at,
        "llm_provider": random.choice(_LLM_PROVIDERS),
        "llm_model": "demo-model",
        "prompt_hash": hashlib.sha256(prompt_text.encode()).hexdigest(),
        "pii_detected": has_pii,
        "pii_entity_types": pii_cats,
        "pii_risk_level": risk_level,
        "injection_score": injection_score,
        "injection_type": injection_type,
        "enforcement_action": action,
        "enforcement_reason": (
            f"{_DEMO_REASON_PREFIX} {action.lower()}"
            + (f" — {pii_cats[0]}" if pii_cats else "")
            + (f" — injection {injection_type}" if injection_type else "")
        ),
        "triggered_policies": ["demo-pack"] if has_pii or has_injection else None,
        "total_latency_ms": random.randint(80, 850),
        "log_signature": _fake_signature(str(interaction_id), tenant_id),
        "schema_version": _DEMO_SCHEMA,
        "sequence_number": 0,  # demo rows aren't chained
        "signing_key_id": "demo",
    }


# ─── DB ops ──────────────────────────────────────────────────────────────────


async def _seed(conn: asyncpg.Connection, tenant_id: str) -> dict[str, int]:
    """Bulk-insert demo data. Idempotent within a single demo-mode toggle."""
    # 1) Users
    inserted_users = 0
    for handle, dept in _DEMO_USERS:
        external_id = f"{_DEMO_USER_PREFIX}{handle}"
        await conn.execute(
            """
            INSERT INTO tenant_users (tenant_id, external_id, email, department, role, is_active)
            VALUES ($1, $2, $3, $4, 'user', TRUE)
            ON CONFLICT (tenant_id, external_id) DO NOTHING
            """,
            tenant_id,
            external_id,
            f"{handle}@demo.agcms.local",
            dept,
        )
        inserted_users += 1

    # 2) Audit rows — 2000 spread over the last 30 days
    rows = []
    for _ in range(2000):
        handle, dept = random.choice(_DEMO_USERS)
        rows.append(_random_demo_row(tenant_id, f"{_DEMO_USER_PREFIX}{handle}", dept))

    await conn.executemany(
        """
        INSERT INTO audit_logs (
            interaction_id, tenant_id, user_id, department, created_at,
            llm_provider, llm_model, prompt_hash,
            pii_detected, pii_entity_types, pii_risk_level,
            injection_score, injection_type,
            enforcement_action, enforcement_reason, triggered_policies,
            total_latency_ms,
            log_signature, schema_version, sequence_number, signing_key_id
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8,
            $9, $10, $11,
            $12, $13,
            $14, $15, $16,
            $17,
            $18, $19, $20, $21
        )
        """,
        [
            (
                r["interaction_id"], r["tenant_id"], r["user_id"], r["department"],
                r["created_at"], r["llm_provider"], r["llm_model"], r["prompt_hash"],
                r["pii_detected"], r["pii_entity_types"], r["pii_risk_level"],
                r["injection_score"], r["injection_type"],
                r["enforcement_action"], r["enforcement_reason"], r["triggered_policies"],
                r["total_latency_ms"],
                r["log_signature"], r["schema_version"], r["sequence_number"],
                r["signing_key_id"],
            )
            for r in rows
        ],
    )

    # 3) Escalations — 20 pulled from the high-action audit rows
    high_severity_rows = [
        r for r in rows if r["enforcement_action"] in ("BLOCK", "ESCALATE")
    ][:20]
    for r in high_severity_rows:
        await conn.execute(
            """
            INSERT INTO escalations (interaction_id, tenant_id, created_at, reason, status)
            VALUES ($1, $2, $3, $4, 'PENDING')
            """,
            r["interaction_id"],
            tenant_id,
            r["created_at"],
            f"{_DEMO_REASON_PREFIX} {r['enforcement_reason']}",
        )

    return {
        "users": inserted_users,
        "audit_rows": len(rows),
        "escalations": len(high_severity_rows),
    }


async def _clear(conn: asyncpg.Connection, tenant_id: str) -> dict[str, int]:
    """Hard-delete all demo data for the tenant."""
    deleted_audit = await conn.fetchval(
        "WITH d AS (DELETE FROM audit_logs "
        "WHERE tenant_id = $1 AND schema_version = $2 RETURNING 1) "
        "SELECT COUNT(*) FROM d",
        tenant_id,
        _DEMO_SCHEMA,
    )
    deleted_escalations = await conn.fetchval(
        "WITH d AS (DELETE FROM escalations "
        "WHERE tenant_id = $1 AND reason LIKE $2 RETURNING 1) "
        "SELECT COUNT(*) FROM d",
        tenant_id,
        f"{_DEMO_REASON_PREFIX}%",
    )
    deleted_users = await conn.fetchval(
        "WITH d AS (DELETE FROM tenant_users "
        "WHERE tenant_id = $1 AND external_id LIKE $2 RETURNING 1) "
        "SELECT COUNT(*) FROM d",
        tenant_id,
        f"{_DEMO_USER_PREFIX}%",
    )
    return {
        "audit_rows": int(deleted_audit or 0),
        "escalations": int(deleted_escalations or 0),
        "users": int(deleted_users or 0),
    }


# ─── HTTP API ────────────────────────────────────────────────────────────────


@router.get("/status")
async def demo_status(ctx: AuthContext = Depends(require_admin)):
    conn = await asyncpg.connect(_db_dsn())
    try:
        flag = await conn.fetchval(
            "SELECT demo_mode_enabled FROM tenants WHERE id = $1", ctx.tenant_id
        )
        audit_count = await conn.fetchval(
            "SELECT COUNT(*) FROM audit_logs "
            "WHERE tenant_id = $1 AND schema_version = $2",
            ctx.tenant_id,
            _DEMO_SCHEMA,
        )
    finally:
        await conn.close()
    return {
        "demo_mode_enabled": bool(flag),
        "demo_audit_rows": int(audit_count or 0),
    }


@router.post("/seed")
async def demo_seed(ctx: AuthContext = Depends(require_admin)):
    """Seed the tenant with demo data. Idempotent — re-seeding adds more rows."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        async with conn.transaction():
            counts = await _seed(conn, ctx.tenant_id)
            await conn.execute(
                "UPDATE tenants SET demo_mode_enabled = TRUE WHERE id = $1",
                ctx.tenant_id,
            )
    finally:
        await conn.close()
    return {"seeded": counts, "demo_mode_enabled": True}


@router.post("/clear")
async def demo_clear(ctx: AuthContext = Depends(require_admin)):
    """Hard-delete all demo data and turn the flag off."""
    conn = await asyncpg.connect(_db_dsn())
    try:
        async with conn.transaction():
            counts = await _clear(conn, ctx.tenant_id)
            await conn.execute(
                "UPDATE tenants SET demo_mode_enabled = FALSE WHERE id = $1",
                ctx.tenant_id,
            )
    finally:
        await conn.close()
    return {"cleared": counts, "demo_mode_enabled": False}


__all__ = ["router"]
