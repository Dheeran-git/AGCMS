"""Nightly Merkle-root anchor service.

For each tenant and closed period, compute a Merkle root over the period's
ordered ``log_signature`` values, HMAC-sign the root with the active
anchor key, persist to ``audit_roots``, and optionally upload a signed
manifest to S3 under Object Lock (Compliance mode).

The anchor is independent of per-row signing: even if an attacker
compromises both the row key and the database, the published manifests
remain a third-party-verifiable record of what the chain looked like at
rollover — S3 Object Lock makes the uploaded manifest immutable for the
retention window.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Dict, Optional

import sqlalchemy

from agcms.audit.keys import REGISTRY
from agcms.audit.merkle import compute_root
from agcms.db import audit_roots, database

log = logging.getLogger(__name__)

DEFAULT_RETENTION_YEARS = 7

# An S3 uploader is an async callable (manifest_dict, retention_until) ->
# {"url": "s3://...", "version_id": "..."}. Left as a protocol so tests
# can inject a fake without pulling boto3 into the core service.
S3Uploader = Callable[[dict, datetime], Awaitable[dict]]


def _sign_anchor_root(root_bytes: bytes, kid: str) -> str:
    key = REGISTRY.anchor_key(kid)
    return hmac.new(key, root_bytes, hashlib.sha256).hexdigest()


def yesterday_utc() -> tuple[datetime, datetime]:
    """Return ``(start, end)`` for the previous UTC day (00:00 inclusive, 24h)."""
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return today - timedelta(days=1), today


async def anchor_period(
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    *,
    retention_years: int = DEFAULT_RETENTION_YEARS,
    s3_uploader: Optional[S3Uploader] = None,
) -> Optional[dict]:
    """Compute + persist the Merkle root for one (tenant, period).

    Returns the manifest dict that was anchored, or None if the period
    was empty or already anchored.
    """
    kid = REGISTRY.active_anchor_kid
    if kid is None:
        raise RuntimeError(
            "AGCMS_ANCHOR_KEY is not configured; anchor service cannot sign roots."
        )

    existing = await database.fetch_one(
        sqlalchemy.text(
            "SELECT id FROM audit_roots WHERE tenant_id = :tid "
            "AND period_start = :ps AND period_end = :pe"
        ).bindparams(tid=tenant_id, ps=period_start, pe=period_end),
    )
    if existing is not None:
        log.info(
            "anchor skipped (exists) tenant=%s period=%s..%s",
            tenant_id, period_start.isoformat(), period_end.isoformat(),
        )
        return None

    rows = await database.fetch_all(
        sqlalchemy.text(
            "SELECT sequence_number, log_signature FROM audit_logs "
            "WHERE tenant_id = :tid AND sequence_number > 0 "
            "AND created_at >= :ps AND created_at < :pe "
            "ORDER BY sequence_number ASC"
        ).bindparams(tid=tenant_id, ps=period_start, pe=period_end),
    )
    if not rows:
        log.info(
            "anchor skipped (empty) tenant=%s period=%s..%s",
            tenant_id, period_start.isoformat(), period_end.isoformat(),
        )
        return None

    signatures = [r["log_signature"] for r in rows]
    root_bytes = compute_root(signatures)
    merkle_root_hex = root_bytes.hex()
    signed_root_hex = _sign_anchor_root(root_bytes, kid)

    first_seq = rows[0]["sequence_number"]
    last_seq = rows[-1]["sequence_number"]
    retention_until = period_end + timedelta(days=365 * retention_years)

    manifest: Dict = {
        "tenant_id": tenant_id,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "row_count": len(signatures),
        "first_sequence_number": first_seq,
        "last_sequence_number": last_seq,
        "merkle_root": merkle_root_hex,
        "signed_root": signed_root_hex,
        "anchor_key_id": kid,
        "hash_algorithm": "sha256",
        "tree_scheme": "tagged-leaf-tagged-node-duplicate-odd",
    }

    s3_url: Optional[str] = None
    s3_version: Optional[str] = None
    if s3_uploader is not None:
        uploaded = await s3_uploader(manifest, retention_until)
        s3_url = uploaded.get("url")
        s3_version = uploaded.get("version_id")
        manifest["s3_url"] = s3_url
        manifest["s3_object_version"] = s3_version

    await database.execute(
        audit_roots.insert().values(
            tenant_id=tenant_id,
            period_start=period_start,
            period_end=period_end,
            row_count=len(signatures),
            first_sequence_number=first_seq,
            last_sequence_number=last_seq,
            merkle_root=merkle_root_hex,
            signed_root=signed_root_hex,
            anchor_key_id=kid,
            s3_url=s3_url,
            s3_object_version=s3_version,
            retention_until=retention_until,
        )
    )
    log.info(
        "anchor wrote tenant=%s period=%s..%s rows=%d kid=%s",
        tenant_id, period_start.isoformat(), period_end.isoformat(), len(signatures), kid,
    )
    return manifest


async def anchor_all_tenants(
    period_start: datetime,
    period_end: datetime,
    *,
    s3_uploader: Optional[S3Uploader] = None,
) -> Dict[str, Optional[dict]]:
    """Run ``anchor_period`` for every active tenant.

    Per-tenant failures do not abort the run — each tenant's outcome is
    reported independently so the cron summary surfaces partial failures.
    """
    tenant_rows = await database.fetch_all(
        sqlalchemy.text("SELECT id FROM tenants WHERE is_active = TRUE")
    )
    summary: Dict[str, Optional[dict]] = {}
    for r in tenant_rows:
        tid = r["id"]
        try:
            summary[tid] = await anchor_period(
                tid, period_start, period_end, s3_uploader=s3_uploader
            )
        except Exception as exc:
            log.exception("anchor failed for tenant %s", tid)
            summary[tid] = {"error": str(exc)}
    return summary


__all__ = [
    "anchor_period",
    "anchor_all_tenants",
    "yesterday_utc",
]
