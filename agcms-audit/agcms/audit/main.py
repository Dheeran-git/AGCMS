import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
from typing import Optional

from agcms.common.observability import init_observability
from agcms.db import database

log = logging.getLogger(__name__)


async def _anchor_scheduler_loop():
    """Run the anchor sweep once per day at ~00:15 UTC.

    Disabled when AGCMS_ANCHOR_SCHEDULER != "1". The endpoint
    ``POST /anchor/run`` can always be called manually for dev/demo.
    """
    from agcms.audit.anchor import anchor_all_tenants, yesterday_utc
    from agcms.audit.s3_anchor import build_uploader_from_env

    uploader = build_uploader_from_env()
    while True:
        now = datetime.now(timezone.utc)
        next_run = (now + timedelta(days=1)).replace(
            hour=0, minute=15, second=0, microsecond=0
        )
        await asyncio.sleep(max(1.0, (next_run - now).total_seconds()))
        try:
            start, end = yesterday_utc()
            await anchor_all_tenants(start, end, s3_uploader=uploader)
        except Exception:
            log.exception("scheduled anchor sweep failed")


async def _seed_signing_keys_from_env() -> None:
    """Ensure the signing_keys table has a row for every active kid in the registry.

    Migrations seed the v1 row key at init time, but the anchor kid (a1 by
    default) can only be seeded here because its material comes from
    AGCMS_ANCHOR_KEY, which Postgres cannot read during init. Idempotent:
    ON CONFLICT DO NOTHING so repeated starts are no-ops.
    """
    import hashlib
    import sqlalchemy

    from agcms.audit.keys import REGISTRY

    seeds: list[tuple[str, str, bytes]] = []
    row_kid = REGISTRY.active_row_kid
    try:
        seeds.append(("row", row_kid, REGISTRY.row_key(row_kid)))
    except KeyError:
        pass
    anchor_kid = REGISTRY.active_anchor_kid
    if anchor_kid is not None:
        try:
            seeds.append(("anchor", anchor_kid, REGISTRY.anchor_key(anchor_kid)))
        except KeyError:
            pass

    for purpose, kid, material in seeds:
        key_hash = hashlib.sha256(material).hexdigest()
        await database.execute(
            sqlalchemy.text(
                "INSERT INTO signing_keys (kid, purpose, key_hash, is_active, notes) "
                "VALUES (:kid, :purpose, :key_hash, TRUE, :notes) "
                "ON CONFLICT (kid) DO NOTHING"
            ).bindparams(
                kid=kid,
                purpose=purpose,
                key_hash=key_hash,
                notes="seeded from env at audit startup",
            ),
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.connect()
    await _seed_signing_keys_from_env()
    scheduler_task = None
    if os.environ.get("AGCMS_ANCHOR_SCHEDULER") == "1":
        scheduler_task = asyncio.create_task(_anchor_scheduler_loop())
    try:
        yield
    finally:
        if scheduler_task is not None:
            scheduler_task.cancel()
        await database.disconnect()


app = FastAPI(
    title="AGCMS Audit Logging Service",
    description="Audit log writing and querying service",
    version="1.0.0",
    lifespan=lifespan,
)

init_observability(app, "audit")

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

    import sqlalchemy
    query = sqlalchemy.text(
        "SELECT interaction_id, tenant_id, user_id, department, created_at, "
        "llm_provider, llm_model, prompt_hash, pii_detected, pii_entity_types, "
        "pii_risk_level, injection_score, injection_type, enforcement_action, "
        "enforcement_reason, triggered_policies, response_violated, "
        "response_violations, total_latency_ms, log_signature, "
        "previous_log_hash, sequence_number, signing_key_id "
        "FROM audit_logs WHERE interaction_id = :iid "
        "ORDER BY created_at DESC LIMIT 1"
    ).bindparams(iid=iid)
    row = await database.fetch_one(query)
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
        "sequence_number": entry.get("sequence_number"),
        "signing_key_id": entry.get("signing_key_id"),
    }


class BundleRequest(BaseModel):
    tenant_id: str
    period_start: str
    period_end: str


@app.post("/bundle")
async def build_bundle_endpoint(req: BundleRequest):
    """Produce a signed, self-verifiable audit bundle ZIP.

    Returns the ZIP bytes with content-type ``application/zip``. Intended
    to be called by the dashboard's Audit → Export flow and by the
    compliance team; gateway enforces admin/compliance RBAC.
    """
    from agcms.audit.bundle import build_bundle

    try:
        start = datetime.fromisoformat(req.period_start)
        end = datetime.fromisoformat(req.period_end)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"period_start/period_end must be ISO-8601 timestamps: {exc}",
        )
    if end <= start:
        raise HTTPException(status_code=400, detail="period_end must be after period_start")

    data = await build_bundle(req.tenant_id, period_start=start, period_end=end)

    day = start.strftime("%Y%m%d")
    filename = f"agcms-bundle-{req.tenant_id}-{day}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class AnchorRunRequest(BaseModel):
    tenant_id: Optional[str] = None
    period_start: Optional[str] = None
    period_end: Optional[str] = None


@app.post("/anchor/run")
async def run_anchor(req: AnchorRunRequest):
    """Compute + persist Merkle root(s) for a period.

    If ``tenant_id`` is omitted, runs across all active tenants.
    If ``period_start``/``period_end`` are omitted, defaults to the
    previous UTC day (which is what the scheduler does nightly).

    Intended to be gated by admin auth at the gateway. Idempotent:
    re-running for a period that was already anchored returns a no-op.
    """
    from agcms.audit.anchor import (
        anchor_period,
        anchor_all_tenants,
        yesterday_utc,
    )
    from agcms.audit.s3_anchor import build_uploader_from_env

    if req.period_start is None or req.period_end is None:
        start, end = yesterday_utc()
    else:
        try:
            start = datetime.fromisoformat(req.period_start)
            end = datetime.fromisoformat(req.period_end)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"period_start/period_end must be ISO-8601 timestamps: {exc}",
            )
    if end <= start:
        raise HTTPException(
            status_code=400,
            detail="period_end must be strictly greater than period_start",
        )

    uploader = build_uploader_from_env()
    if req.tenant_id:
        manifest = await anchor_period(
            req.tenant_id, start, end, s3_uploader=uploader
        )
        return {"anchored": manifest is not None, "manifest": manifest}
    summary = await anchor_all_tenants(start, end, s3_uploader=uploader)
    return {"summary": summary}


class RotationProposeRequest(BaseModel):
    purpose: str
    new_kid: str
    new_key_material: str
    proposed_by: str
    reason: str


class RotationActorRequest(BaseModel):
    actor: str


@app.get("/signing-keys")
async def list_signing_keys_endpoint():
    """List every signing key (active + retired) with its purpose and fingerprint."""
    from agcms.audit.key_rotation_repo import list_signing_keys

    keys = await list_signing_keys()
    return {"signing_keys": [_serialize_dt(k) for k in keys]}


@app.get("/signing-keys/rotations")
async def list_rotations_endpoint(limit: int = 50):
    from agcms.audit.key_rotation_repo import list_rotations

    rotations = await list_rotations(limit=limit)
    return {"rotations": [_serialize_dt(r) for r in rotations]}


@app.post("/signing-keys/rotations", status_code=201)
async def propose_rotation_endpoint(req: RotationProposeRequest):
    from agcms.audit.key_rotation import RotationError
    from agcms.audit.key_rotation_repo import propose_rotation

    try:
        rec = await propose_rotation(
            purpose=req.purpose,
            new_kid=req.new_kid,
            new_key_material=req.new_key_material,
            proposed_by=req.proposed_by,
            reason=req.reason,
        )
    except RotationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _serialize_dt(rec)


@app.post("/signing-keys/rotations/{rotation_id}/approve")
async def approve_rotation_endpoint(rotation_id: str, req: RotationActorRequest):
    from agcms.audit.key_rotation import RotationError
    from agcms.audit.key_rotation_repo import approve_rotation

    try:
        rec = await approve_rotation(rotation_id, approver=req.actor)
    except RotationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _serialize_dt(rec)


@app.post("/signing-keys/rotations/{rotation_id}/execute")
async def execute_rotation_endpoint(rotation_id: str, req: RotationActorRequest):
    from agcms.audit.key_rotation import RotationError
    from agcms.audit.key_rotation_repo import execute_rotation

    try:
        rec = await execute_rotation(rotation_id, executor=req.actor)
    except RotationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _serialize_dt(rec)


@app.post("/signing-keys/rotations/{rotation_id}/cancel")
async def cancel_rotation_endpoint(rotation_id: str, req: RotationActorRequest):
    from agcms.audit.key_rotation import RotationError
    from agcms.audit.key_rotation_repo import cancel_rotation

    try:
        rec = await cancel_rotation(rotation_id, canceller=req.actor)
    except RotationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return _serialize_dt(rec)


def _serialize_dt(rec: dict) -> dict:
    out = dict(rec)
    for k, v in list(out.items()):
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        elif isinstance(v, uuid.UUID):
            out[k] = str(v)
    return out


@app.get("/chain/verify")
async def verify_chain_endpoint(
    tenant_id: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    """Replay the full per-tenant hash chain and report integrity.

    Returns a structured ChainReport: count of chain rows examined,
    first/last sequence number + signature, and any detected issues
    (``gap``, ``reorder``, ``signature``, ``link``, ``unknown_kid``,
    ``missing_field``, ``tenant_mismatch``). When ``ok`` is true the
    chain is intact over the queried range.

    Caller must be authenticated as admin or compliance for the tenant;
    enforcement lives in the gateway, not here.
    """
    from agcms.audit.chain_verifier import verify_tenant_chain

    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")

    report = await verify_tenant_chain(tenant_id, start=start, end=end)
    return report.to_dict()
