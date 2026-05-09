from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Optional

from agcms.common.observability import init_observability
from agcms.policy.packs import list_packs, load_pack, merge_packs
from agcms.policy.resolver import PolicyResolver
from agcms.policy.validator import validate_policy

app = FastAPI(
    title="AGCMS Policy Resolution Engine",
    description="Policy resolution and rule management service",
    version="1.0.0",
)

init_observability(app, "policy")

_resolver = PolicyResolver()


class ResolveRequest(BaseModel):
    pii_result: Optional[dict] = None
    injection_result: Optional[dict] = None
    policy: Optional[dict] = None


class ValidateRequest(BaseModel):
    config: Any


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "policy"}


@app.post("/resolve")
async def resolve(req: ResolveRequest):
    decision = _resolver.resolve(
        pii_result=req.pii_result,
        injection_result=req.injection_result,
        policy=req.policy,
    )
    return decision.to_dict()


@app.post("/validate")
async def validate(req: ValidateRequest):
    """Validate a policy config dict against the AGCMS policy DSL.

    Returns {"valid": true} on success, or {"valid": false, "errors": [...]}
    listing all constraint violations.
    """
    errors = validate_policy(req.config)
    if errors:
        return {"valid": False, "errors": errors}
    return {"valid": True, "errors": []}


class MergePacksRequest(BaseModel):
    base: dict[str, Any]
    pack_ids: list[str]


@app.get("/packs")
async def packs_index():
    """List every installed policy pack with summary metadata."""
    return {"packs": list_packs()}


@app.get("/packs/{pack_id}")
async def packs_get(pack_id: str):
    """Return a single pack by id."""
    try:
        return load_pack(pack_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"pack '{pack_id}' not found")


@app.post("/packs/merge")
async def packs_merge(req: MergePacksRequest):
    """Merge a base policy with an ordered list of packs (last wins)."""
    try:
        return merge_packs(req.base, req.pack_ids)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
