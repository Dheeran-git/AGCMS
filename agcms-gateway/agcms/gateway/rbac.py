"""RBAC dependencies for the AGCMS Management API.

Wraps the gateway's ``authenticate()`` function into FastAPI dependencies
so management endpoints can gate access by role.

Roles (from DB ``tenant_users.role`` CHECK):
    admin      — full access
    compliance — read audit/users/stats; read+update escalations and policy
    user       — only /auth/me

``admin`` implicitly passes every ``require_role()`` gate.
"""

from typing import Optional

from fastapi import Depends, Header, HTTPException, status

from agcms.common import scopes as scope_vocab
from agcms.gateway.auth import AuthContext, authenticate


async def get_current_auth(
    authorization: Optional[str] = Header(default=None),
) -> AuthContext:
    """FastAPI dependency: returns the authenticated AuthContext or raises 401."""
    ctx, err = await authenticate(authorization)
    if err or ctx is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=err or "Unauthorized",
        )
    return ctx


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: allow only the given roles (admin always allowed)."""

    async def _dep(ctx: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if ctx.role != "admin" and ctx.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{ctx.role}' not permitted for this endpoint",
            )
        return ctx

    return _dep


# Convenience dependencies (most common gates)
require_admin = require_role("admin")
require_compliance = require_role("compliance")


def require_scope(scope: str):
    """FastAPI dependency factory: gate by API-key / JWT scope.

    JWT-authenticated callers have their scopes derived from ``role`` via
    ``scopes_for_role``. API-key callers carry the exact scope array from
    their ``api_keys`` row. The ``admin`` scope implicitly grants all.
    """
    if scope not in scope_vocab.ALL_SCOPES:
        raise ValueError(f"Unknown scope '{scope}'")

    async def _dep(ctx: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if not ctx.has_scope(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope '{scope}'",
            )
        return ctx

    return _dep
