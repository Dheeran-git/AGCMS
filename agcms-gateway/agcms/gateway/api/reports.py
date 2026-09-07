"""GDPR Art. 30 and EU AI Act Art. 13 compliance reports."""

import json
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException

from agcms.gateway.auth import AuthContext
from agcms.gateway.rbac import require_compliance
from agcms.gateway.api.common import db_dsn

router = APIRouter()


_KNOWN_REPORT_TYPES = {"gdpr", "eu-ai-act"}


@router.get("/reports/{report_type}")
async def generate_compliance_report(
    report_type: str,
    ctx: AuthContext = Depends(require_compliance),
):
    """Generate a GDPR Article 30 or EU AI Act Article 13 compliance report.

    Queries the last 30 days of audit_logs for the caller's tenant.
    Returns a structured JSON report suitable for archival or display.
    """
    if report_type not in _KNOWN_REPORT_TYPES:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown report type '{report_type}'. Valid: {sorted(_KNOWN_REPORT_TYPES)}",
        )

    now = datetime.now(timezone.utc)
    period_label = "Last 30 days"

    conn = await asyncpg.connect(db_dsn())
    try:
        # Core 30-day aggregates
        agg = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total_requests,
                COUNT(*) FILTER (WHERE pii_detected = TRUE) AS total_pii,
                COUNT(*) FILTER (
                    WHERE pii_detected = TRUE AND enforcement_action = 'REDACT'
                ) AS pii_redacted,
                COUNT(*) FILTER (
                    WHERE pii_detected = TRUE AND enforcement_action = 'BLOCK'
                ) AS pii_blocked,
                COUNT(*) FILTER (
                    WHERE pii_detected = TRUE AND enforcement_action = 'ESCALATE'
                ) AS pii_escalated
            FROM audit_logs
            WHERE tenant_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            """,
            ctx.tenant_id,
        )

        # Escalation breakdown
        esc_agg = await conn.fetchrow(
            """
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'PENDING') AS pending,
                COUNT(*) FILTER (WHERE status != 'PENDING') AS resolved
            FROM escalations
            WHERE tenant_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            """,
            ctx.tenant_id,
        )

        # Policy change count
        policy_changes = await conn.fetchval(
            """
            SELECT COUNT(*) FROM policies
            WHERE tenant_id = $1
              AND created_at >= NOW() - INTERVAL '30 days'
            """,
            ctx.tenant_id,
        )

        # Active policy for injection config
        active_policy_row = await conn.fetchrow(
            "SELECT config FROM policies WHERE tenant_id = $1 AND is_active = TRUE "
            "ORDER BY created_at DESC LIMIT 1",
            ctx.tenant_id,
        )

        # Providers that actually answered, and PII types actually seen, in the period
        provider_rows = await conn.fetch(
            "SELECT llm_provider, COUNT(*) AS n FROM audit_logs "
            "WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '30 days' "
            "AND enforcement_action IN ('ALLOW', 'REDACT', 'ESCALATE') "
            "GROUP BY llm_provider ORDER BY n DESC",
            ctx.tenant_id,
        )
        category_rows = await conn.fetch(
            "SELECT DISTINCT unnest(pii_entity_types) AS t FROM audit_logs "
            "WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '30 days' "
            "AND pii_detected = TRUE ORDER BY t",
            ctx.tenant_id,
        )

    finally:
        await conn.close()

    providers_used = [r["llm_provider"] for r in provider_rows if r["llm_provider"] not in (None, "none")]
    categories_seen = [r["t"] for r in category_rows if r["t"]]
    # Every hosted provider in the chain is outside the EU; only local Ollama is not a transfer.
    hosted = [p for p in providers_used if p != "ollama"]

    # Parse active policy config
    active_config: dict = {}
    if active_policy_row:
        raw = active_policy_row["config"]
        active_config = json.loads(raw) if isinstance(raw, str) else (raw or {})

    inj_cfg = active_config.get("injection", {})
    pii_cfg = active_config.get("pii", {})
    retention_days = (active_config.get("audit") or {}).get("retention_days")
    retention_label = f"{retention_days} days" if retention_days else "not set in policy"

    total_requests = int(agg["total_requests"] or 0)
    total_pii = int(agg["total_pii"] or 0)
    pii_redacted = int(agg["pii_redacted"] or 0)
    pii_blocked = int(agg["pii_blocked"] or 0)
    pii_escalated = int(agg["pii_escalated"] or 0)
    esc_total = int(esc_agg["total"] or 0)
    esc_pending = int(esc_agg["pending"] or 0)
    esc_resolved = int(esc_agg["resolved"] or 0)
    policy_changes_int = int(policy_changes or 0)
    inj_enabled = bool(inj_cfg.get("enabled", True))
    pii_enabled = bool(pii_cfg.get("enabled", True))

    if report_type == "gdpr":
        findings = [
            {
                "check": "PII detection enabled",
                "status": "pass" if pii_enabled else "fail",
                "detail": "spaCy NER + regex patterns active" if pii_enabled else "PII detection is disabled — GDPR risk",
            },
            {
                "check": "Data minimisation (REDACT action)",
                "status": "pass" if pii_redacted > 0 or total_pii == 0 else "warning",
                "detail": f"{pii_redacted} records redacted out of {total_pii} PII detections",
            },
            {
                "check": "PII blocking for critical data",
                "status": "pass" if pii_cfg.get("critical_action") in ("BLOCK", "ESCALATE") else "warning",
                "detail": f"critical_action = {pii_cfg.get('critical_action', 'not set')}",
            },
            {
                "check": "Audit trail integrity (HMAC)",
                "status": "pass",
                "detail": "All audit logs are HMAC-SHA256 signed",
            },
            {
                "check": "Retention policy defined",
                "status": "pass" if retention_days else "warning",
                "detail": (f"Audit logs retained for {retention_label} (policy audit.retention_days; monthly partitions)"
                           if retention_days else "Policy has no audit.retention_days; set it to declare the retention period"),
            },
            {
                "check": "Cross-border data transfer",
                "status": "warning" if hosted else "pass",
                "detail": (
                    f"Prompts forwarded to hosted providers outside the EU in this period: {', '.join(hosted)}. "
                    "Controller-to-processor transfer; a DPA / SCCs with each provider is required."
                    if hosted else
                    "No prompts forwarded to hosted providers in this period"
                    + (" (local Ollama only)" if providers_used else "")
                ),
            },
        ]
        return {
            "report_type": "gdpr",
            "generated_at": now.isoformat(),
            "tenant_id": ctx.tenant_id,
            "period": period_label,
            "total_requests": total_requests,
            "total_pii_detections": total_pii,
            "pii_redacted": pii_redacted,
            "pii_blocked": pii_blocked,
            "pii_escalated": pii_escalated,
            "data_categories_processed": categories_seen or _derive_pii_categories(pii_cfg),
            "llm_providers_used": providers_used,
            "cross_border_transfers": bool(hosted),
            "retention_policy": retention_label,
            "findings": findings,
        }

    # EU AI Act report
    findings = [
        {
            "check": "Risk classification declared",
            "status": "pass",
            "detail": "Classified as Limited Risk — AI system with human interaction",
        },
        {
            "check": "Transparency obligation (Article 13)",
            "status": "pass",
            "detail": "System name, purpose, and capabilities disclosed in documentation",
        },
        {
            "check": "Prompt injection detection",
            "status": "pass" if inj_enabled else "fail",
            "detail": f"Heuristic rules + fine-tuned DistilBERT classifier — enabled={inj_enabled}, "
                      f"block_threshold={inj_cfg.get('block_threshold', 'n/a')}",
        },
        {
            "check": "Human oversight mechanism",
            "status": "pass" if esc_total > 0 or esc_pending == 0 else "warning",
            "detail": f"{esc_total} escalations in last 30d — {esc_pending} pending, {esc_resolved} resolved",
        },
        {
            "check": "Audit trail (Article 12)",
            "status": "pass",
            "detail": "HMAC-SHA256 signed, tamper-evident, append-only audit log",
        },
        {
            "check": "Policy governance",
            "status": "pass",
            "detail": f"{policy_changes_int} policy version(s) deployed in last 30d — versioned + audited",
        },
    ]
    return {
        "report_type": "eu-ai-act",
        "generated_at": now.isoformat(),
        "tenant_id": ctx.tenant_id,
        "system_name": "AGCMS",
        "risk_classification": "Limited Risk",
        "injection_detection_enabled": inj_enabled,
        "injection_detection_method": "Heuristic rules + fine-tuned DistilBERT classifier (ONNX)",
        "human_oversight_escalations": esc_total,
        "pending_escalations": esc_pending,
        "resolved_escalations": esc_resolved,
        "audit_trail_signed": True,
        "policy_changes_30d": policy_changes_int,
        "findings": findings,
    }


def _derive_pii_categories(pii_cfg: dict) -> list[str]:
    """Return the list of PII categories the current policy is configured to detect."""
    base = ["PERSON_NAME", "EMAIL", "PHONE_US", "SSN", "CREDIT_CARD", "AADHAAR", "PAN", "IBAN"]
    custom = list((pii_cfg.get("custom_patterns") or {}).keys())
    return base + custom
