"""Shared API-key scope vocabulary (Phase 6.4).

Scopes are the unit of least-privilege for raw API-key auth on the
gateway ingest path and on the management API. JWT auth derives scopes
from ``role``.

Policy
------

* ``ingest``        — POST /v1/chat/completions, /v1/embeddings, etc.
* ``read:audit``    — GET  /api/v1/audit/*, /api/v1/reports/*
* ``read:policy``   — GET  /api/v1/policy
* ``write:policy``  — PUT  /api/v1/policy, /api/v1/policy/rules/*
* ``admin``         — all of the above + tenant/user management,
                      key rotation, and GDPR purge.

The helper ``scopes_for_role()`` maps traditional RBAC roles onto the
scope set a JWT holder implicitly carries.
"""
from __future__ import annotations

from typing import FrozenSet, Iterable

INGEST = "ingest"
READ_AUDIT = "read:audit"
READ_POLICY = "read:policy"
WRITE_POLICY = "write:policy"
ADMIN = "admin"

ALL_SCOPES: FrozenSet[str] = frozenset({
    INGEST, READ_AUDIT, READ_POLICY, WRITE_POLICY, ADMIN,
})

_ROLE_SCOPES = {
    "admin":      ALL_SCOPES,
    "compliance": frozenset({INGEST, READ_AUDIT, READ_POLICY}),
    "user":       frozenset({INGEST}),
}


def scopes_for_role(role: str) -> FrozenSet[str]:
    """Return the scope set granted to a JWT holder with ``role``.

    Unknown roles fall through to the most restrictive set (``ingest``-only)
    rather than raising, so a typo can never accidentally grant admin.
    """
    return _ROLE_SCOPES.get(role, frozenset({INGEST}))


def has_scope(granted: Iterable[str], required: str) -> bool:
    """True if ``required`` is satisfied by ``granted``.

    ``admin`` is a superset — it satisfies any required scope.
    """
    granted_set = set(granted)
    if ADMIN in granted_set:
        return True
    return required in granted_set


def validate_scopes(scopes: Iterable[str]) -> list[str]:
    """Return the input as a deduped, sorted, validated list.

    Raises ``ValueError`` on unknown scope names so bad config fails
    fast at key-creation time instead of silently dropping scopes.
    """
    uniq = sorted(set(scopes))
    bad = [s for s in uniq if s not in ALL_SCOPES]
    if bad:
        raise ValueError(f"Unknown scope(s): {bad}. Valid: {sorted(ALL_SCOPES)}")
    if not uniq:
        raise ValueError("At least one scope is required")
    return uniq


__all__ = [
    "INGEST", "READ_AUDIT", "READ_POLICY", "WRITE_POLICY", "ADMIN",
    "ALL_SCOPES", "scopes_for_role", "has_scope", "validate_scopes",
]
