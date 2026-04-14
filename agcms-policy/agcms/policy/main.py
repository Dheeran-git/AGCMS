from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Optional

from agcms.policy.resolver import PolicyResolver
from agcms.policy.validator import validate_policy

app = FastAPI(
    title="AGCMS Policy Resolution Engine",
    description="Policy resolution and rule management service",
    version="1.0.0",
)

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
