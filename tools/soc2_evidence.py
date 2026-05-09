#!/usr/bin/env python3
"""AGCMS SOC 2 Type II evidence collector.

Produces a single ZIP that an auditor (Vanta / Drata / a human pen-tester
working from the SOC 2 Common Criteria) can use as point-in-time evidence
of the controls AGCMS has in place.

Usage
-----
    python tools/soc2_evidence.py --out evidence-2026-04-22.zip
    python tools/soc2_evidence.py --out evidence.zip --tenant t_acme
    python tools/soc2_evidence.py --out evidence.zip --include-audit-chain

Environment
-----------
    DATABASE_URL          required — same DSN every service uses.
    AGCMS_ANCHOR_KEY      optional — when set, the dump's manifest is
                          HMAC-signed with it so reviewers can confirm the
                          ZIP wasn't doctored after we produced it.

The ZIP contains
----------------
    manifest.json                  who/what/when + sha256 of every file
    manifest.sig                   HMAC-SHA256(manifest.json) hex digest
                                    (only when AGCMS_ANCHOR_KEY is present)
    cc_inventory.json              CC reference → AGCMS evidence file map
    tenants.json                   CC2.x — entity boundaries, plan, SSO state
    users.json                     CC6.1 — user accounts + RBAC roles
    api_keys.json                  CC6.1/6.6 — scoped keys, revocation status
    sso_connections.json           CC6.1 — WorkOS orgs + enforcement
    mfa_enrollment.json            CC6.1 — TOTP coverage by tenant
    auth_sessions_summary.json     CC6.2 — active vs revoked, last seen
    signing_keys.json              CC7.1/CC7.2 — kid registry, retired_at
    signing_key_rotations.json     CC7.1 — dual-approval rotation log
    tenant_keys.json               CC6.7 — per-tenant DEK (kid + kek_id only,
                                    never wrapped material)
    audit_chain_summary.json       CC7.3 — per-tenant chain head + last anchor
    audit_chain_integrity.json     CC7.3 — chain replay report (only when
                                    --include-audit-chain is passed)
    audit_roots_recent.json        CC7.3 — last 30 days of Merkle anchors
    gdpr_purges.json               CC8.1 / GDPR Art. 17 — purge history
    notification_rules.json        CC7.4 — alert routing
    config_snapshot.json           CC8.1 — env-var fingerprints (no secrets)

Nothing in this dump contains plaintext PII, plaintext API keys, plaintext
TOTP secrets, or wrapped DEK material. All sensitive identifiers are
SHA-256 hashed; key material is reduced to (kid, kek_id, fingerprint).

Exit codes
----------
    0 — dump produced successfully
    1 — DB error or partial dump
    2 — bad arguments / missing env
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import io
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import asyncpg
except ImportError:  # pragma: no cover - import-time check
    print("ERROR: asyncpg is required. Install with: pip install asyncpg",
          file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Common Criteria reference map
# ---------------------------------------------------------------------------

CC_INVENTORY: dict[str, list[str]] = {
    "CC2.x — System Boundaries": ["tenants.json", "config_snapshot.json"],
    "CC6.1 — Logical Access": [
        "users.json", "api_keys.json", "sso_connections.json",
        "mfa_enrollment.json",
    ],
    "CC6.2 — Authentication": ["auth_sessions_summary.json"],
    "CC6.6 — Access Removal": ["api_keys.json", "auth_sessions_summary.json"],
    "CC6.7 — Encryption At Rest": ["tenant_keys.json"],
    "CC7.1 — Change Detection": [
        "signing_keys.json", "signing_key_rotations.json",
    ],
    "CC7.2 — Anomaly Monitoring": ["audit_chain_integrity.json"],
    "CC7.3 — Recovery / Integrity": [
        "audit_chain_summary.json", "audit_roots_recent.json",
    ],
    "CC7.4 — Incident Detection": ["notification_rules.json"],
    "CC8.1 — Change Management / Privacy": [
        "gdpr_purges.json", "config_snapshot.json",
    ],
}


# ---------------------------------------------------------------------------
# Data collectors
# ---------------------------------------------------------------------------


def _hash(value: Any) -> str:
    if value is None:
        return ""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _row(record: asyncpg.Record) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in dict(record).items():
        if isinstance(value, (bytes, bytearray, memoryview)):
            out[key] = bytes(value).hex()
        elif isinstance(value, datetime):
            out[key] = value.astimezone(timezone.utc).isoformat()
        else:
            out[key] = value
    return out


async def _fetch(conn: asyncpg.Connection, sql: str, *args: Any) -> list[dict[str, Any]]:
    rows = await conn.fetch(sql, *args)
    return [_row(r) for r in rows]


async def collect_tenants(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT id, name, plan, is_active, created_at,
               workos_org_id IS NOT NULL AS sso_configured,
               sso_enforced,
               (onboarding_state ? 'completed_at') AS onboarding_complete,
               demo_mode_enabled,
               (settings -> 'kms_key_arn') AS byok_key_present
        FROM tenants
    """
    rows = await _fetch(conn, sql + (" WHERE id = $1" if tenant else ""),
                        *([tenant] if tenant else []))
    for r in rows:
        r["admin_email_hash"] = _hash(r.pop("admin_email", None))
        r["byok_enabled"] = bool(r.pop("byok_key_present", None))
    return rows


async def collect_users(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT tenant_id, role, auth_provider, is_active,
               created_at, revoked_before,
               external_id, email
        FROM tenant_users
    """
    rows = await _fetch(conn, sql + (" WHERE tenant_id = $1" if tenant else ""),
                        *([tenant] if tenant else []))
    for r in rows:
        r["external_id_hash"] = _hash(r.pop("external_id"))
        r["email_hash"] = _hash(r.pop("email", None))
    return rows


async def collect_api_keys(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT tenant_id, name, scopes, created_at, last_used_at,
               revoked_at, key_hash
        FROM api_keys
    """
    rows = await _fetch(conn, sql + (" WHERE tenant_id = $1" if tenant else ""),
                        *([tenant] if tenant else []))
    for r in rows:
        r["key_fingerprint"] = (r.pop("key_hash") or "")[:16]
    return rows


async def collect_sso(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT id AS tenant_id, name, workos_org_id, sso_enforced
        FROM tenants
        WHERE workos_org_id IS NOT NULL
    """
    if tenant:
        sql += " AND id = $1"
        return await _fetch(conn, sql, tenant)
    return await _fetch(conn, sql)


async def collect_mfa(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    """Per-tenant aggregate: # users with MFA enabled vs total non-revoked."""
    sql = """
        SELECT u.tenant_id,
               COUNT(*) FILTER (WHERE m.enabled IS TRUE) AS mfa_enabled,
               COUNT(*) FILTER (WHERE u.is_active) AS active_users,
               COUNT(*) AS total_users
        FROM tenant_users u
        LEFT JOIN user_mfa m ON m.tenant_user_id = u.id
    """
    sql += (" WHERE u.tenant_id = $1 " if tenant else " ")
    sql += "GROUP BY u.tenant_id ORDER BY u.tenant_id"
    return await _fetch(conn, sql, *([tenant] if tenant else []))


async def collect_sessions(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT tenant_id,
               COUNT(*) AS total,
               COUNT(*) FILTER (WHERE revoked_at IS NULL
                                AND expires_at > NOW()) AS active,
               COUNT(*) FILTER (WHERE revoked_at IS NOT NULL) AS revoked,
               MAX(last_seen_at) AS most_recent_activity
        FROM auth_sessions
    """
    sql += (" WHERE tenant_id = $1 " if tenant else " ")
    sql += "GROUP BY tenant_id ORDER BY tenant_id"
    return await _fetch(conn, sql, *([tenant] if tenant else []))


async def collect_signing_keys(conn: asyncpg.Connection) -> list[dict[str, Any]]:
    return await _fetch(conn, """
        SELECT kid, purpose, key_hash, is_active, created_at, retired_at, notes
        FROM signing_keys
        ORDER BY purpose, created_at DESC
    """)


async def collect_signing_rotations(conn: asyncpg.Connection) -> list[dict[str, Any]]:
    return await _fetch(conn, """
        SELECT id, purpose, new_kid, old_kid, state,
               proposed_by, approved_by, executed_by, cancelled_by,
               proposed_at, approved_at, executed_at, cancelled_at,
               reason
        FROM signing_key_rotations
        ORDER BY proposed_at DESC
        LIMIT 200
    """)


async def collect_tenant_keys(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT tenant_id, kid, kek_id, is_active, created_at, retired_at
        FROM tenant_keys
    """
    rows = await _fetch(conn, sql + (" WHERE tenant_id = $1" if tenant else ""),
                        *([tenant] if tenant else []))
    return rows


async def collect_chain_summary(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT h.tenant_id, h.last_sequence_number, h.last_log_signature,
               h.last_row_created_at, h.updated_at,
               (SELECT MAX(period_end) FROM audit_roots r
                WHERE r.tenant_id = h.tenant_id) AS last_anchor_period_end
        FROM chain_heads h
    """
    sql += (" WHERE h.tenant_id = $1 " if tenant else " ")
    sql += "ORDER BY h.tenant_id"
    return await _fetch(conn, sql, *([tenant] if tenant else []))


async def collect_chain_integrity(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    """Run chain_verifier on each tenant. Slower — only when explicitly asked."""
    try:
        from agcms.audit.chain_verifier import verify_chain
    except ImportError:
        return [{"error": "agcms-audit module not importable from this venv"}]

    tenants = (
        [tenant] if tenant else
        [r["tenant_id"] for r in await _fetch(conn, "SELECT tenant_id FROM chain_heads")]
    )
    out: list[dict[str, Any]] = []
    for t in tenants:
        rows = await conn.fetch(
            "SELECT * FROM audit_logs WHERE tenant_id = $1 "
            "ORDER BY sequence_number ASC",
            t,
        )
        report = verify_chain([dict(r) for r in rows])
        out.append({
            "tenant_id": t,
            "row_count": len(rows),
            "issues": [vars(i) for i in report.issues],
            "ok": report.ok,
        })
    return out


async def collect_audit_roots(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT tenant_id, period_start, period_end, row_count,
               first_sequence_number, last_sequence_number,
               merkle_root, signed_root, anchor_key_id,
               s3_url, s3_object_version, retention_until, created_at
        FROM audit_roots
        WHERE created_at > NOW() - INTERVAL '30 days'
    """
    if tenant:
        sql += " AND tenant_id = $1"
        return await _fetch(conn, sql + " ORDER BY tenant_id, period_start DESC", tenant)
    return await _fetch(conn, sql + " ORDER BY tenant_id, period_start DESC")


async def collect_gdpr_purges(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT id, tenant_id, target_user_external_id, requested_by, approved_by,
               state, requested_at, approved_at, executed_at, cancelled_at,
               row_count, reason
        FROM gdpr_purges
    """
    sql += (" WHERE tenant_id = $1 " if tenant else " ")
    sql += "ORDER BY requested_at DESC LIMIT 500"
    rows = await _fetch(conn, sql, *([tenant] if tenant else []))
    for r in rows:
        r["target_user_external_id_hash"] = _hash(r.pop("target_user_external_id", None))
    return rows


async def collect_notification_rules(conn: asyncpg.Connection, tenant: str | None) -> list[dict[str, Any]]:
    sql = """
        SELECT tenant_id, name, trigger_event, provider, severity_filter,
               is_active, created_at
        FROM notification_rules
    """
    sql += (" WHERE tenant_id = $1 " if tenant else " ")
    sql += "ORDER BY tenant_id, name"
    return await _fetch(conn, sql, *([tenant] if tenant else []))


def collect_config() -> dict[str, Any]:
    """Fingerprints (not values) of security-relevant env vars + git rev."""
    keys = [
        "AGCMS_KMS_BACKEND", "AGCMS_ANCHOR_KEY", "AGCMS_KMS_LOCAL_KEY",
        "AGCMS_AUDIT_HMAC_KEY", "AGCMS_JWT_SECRET", "AGCMS_PUBLIC_URL",
        "AGCMS_API_VERSION", "AGCMS_ANCHOR_S3_BUCKET",
        "OTEL_EXPORTER_OTLP_ENDPOINT", "WORKOS_API_KEY",
        "DATABASE_URL", "REDIS_URL",
    ]
    snap = {
        k: {"present": k in os.environ, "fingerprint": _hash(os.environ.get(k, ""))[:16]}
        for k in keys
    }
    snap["dump_host"] = os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "?")
    return snap


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


async def collect_all(database_url: str, tenant: str | None,
                      include_chain: bool) -> dict[str, Any]:
    conn = await asyncpg.connect(database_url)
    try:
        result: dict[str, Any] = {
            "tenants.json": await collect_tenants(conn, tenant),
            "users.json": await collect_users(conn, tenant),
            "api_keys.json": await collect_api_keys(conn, tenant),
            "sso_connections.json": await collect_sso(conn, tenant),
            "mfa_enrollment.json": await collect_mfa(conn, tenant),
            "auth_sessions_summary.json": await collect_sessions(conn, tenant),
            "signing_keys.json": await collect_signing_keys(conn),
            "signing_key_rotations.json": await collect_signing_rotations(conn),
            "tenant_keys.json": await collect_tenant_keys(conn, tenant),
            "audit_chain_summary.json": await collect_chain_summary(conn, tenant),
            "audit_roots_recent.json": await collect_audit_roots(conn, tenant),
            "gdpr_purges.json": await collect_gdpr_purges(conn, tenant),
            "notification_rules.json": await collect_notification_rules(conn, tenant),
            "config_snapshot.json": collect_config(),
        }
        if include_chain:
            result["audit_chain_integrity.json"] = await collect_chain_integrity(conn, tenant)
        return result
    finally:
        await conn.close()


def write_zip(out_path: Path, payload: dict[str, Any], tenant: str | None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    files: dict[str, bytes] = {}
    for name, data in payload.items():
        files[name] = json.dumps(data, indent=2, default=str, sort_keys=True).encode("utf-8")

    manifest = {
        "tool": "agcms-soc2-evidence",
        "version": "1.0.0",
        "generated_at": now,
        "tenant_filter": tenant,
        "files": [
            {"name": n, "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}
            for n, b in sorted(files.items())
        ],
    }
    files["cc_inventory.json"] = json.dumps(
        CC_INVENTORY, indent=2, sort_keys=True
    ).encode("utf-8")
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

    anchor = os.environ.get("AGCMS_ANCHOR_KEY")
    if anchor:
        sig = hmac.new(anchor.encode("utf-8"), files["manifest.json"], "sha256").hexdigest()
        files["manifest.sig"] = sig.encode("ascii")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="Output ZIP path.")
    parser.add_argument("--tenant", help="Restrict to a single tenant_id.")
    parser.add_argument("--include-audit-chain", action="store_true",
                        help="Run full chain replay per tenant (slow).")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL"),
                        help="Postgres DSN. Defaults to $DATABASE_URL.")
    args = parser.parse_args()

    if not args.database_url:
        print("ERROR: --database-url or $DATABASE_URL required", file=sys.stderr)
        return 2

    # asyncpg uses 'postgresql://', not the SQLAlchemy '+asyncpg' suffix.
    dsn = args.database_url.replace("postgresql+asyncpg://", "postgresql://")

    try:
        payload = asyncio.run(collect_all(dsn, args.tenant, args.include_audit_chain))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    write_zip(out_path, payload, args.tenant)

    file_count = len(payload) + 2  # +manifest +cc_inventory
    if os.environ.get("AGCMS_ANCHOR_KEY"):
        file_count += 1
    print(f"Wrote {out_path} ({file_count} files, "
          f"{out_path.stat().st_size:,} bytes).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
