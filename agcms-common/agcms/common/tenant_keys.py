"""Persistence layer for per-tenant DEKs (envelope encryption, Phase 6.3).

Responsibilities
----------------
* **Mint** — call on tenant creation: generate a DEK, wrap it via the
  active KMS, insert a row into ``tenant_keys``, and install the
  plaintext DEK into the in-process cache.
* **Hydrate** — call on service startup: stream all active wrapped DEKs
  from the DB, unwrap each, and install into the cache. After hydration
  ``encrypt_for_tenant`` / ``decrypt_for_tenant`` are ready to use.
* **Rotate** — mint a fresh DEK, mark the old row retired. Existing
  ciphertexts continue to decrypt because ``install_tenant_key`` keeps
  the retired DEK in the cache until a re-encryption sweep removes it.

Callers supply an asyncpg-compatible connection or pool (``conn``)
with an ``execute`` / ``fetch`` / ``fetchrow`` interface. The module
stays DB-flavor-agnostic to avoid pulling asyncpg into agcms-common.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Optional

from agcms.common import byok as _byok
from agcms.common import crypto


async def _load_byok_config(conn: Any, tenant_id: str) -> Optional[_byok.ByokConfig]:
    """Look up the tenant's BYOK selection (None when on platform KEK).

    Tolerates older databases that pre-date migration 014: if the
    ``kms_key_arn`` column is missing, returns ``None`` so callers stay
    on the platform KEK without crashing.
    """
    try:
        row = await conn.fetchrow(
            "SELECT kms_key_arn, kms_key_provider FROM tenants WHERE id = $1",
            tenant_id,
        )
    except Exception:
        return None
    if not row:
        return None
    data = dict(row)
    arn = data.get("kms_key_arn")
    if not arn:
        return None
    provider = (data.get("kms_key_provider") or "aws").lower()
    return _byok.ByokConfig(provider=provider, key_arn=arn)


def _kms_for(config: Optional[_byok.ByokConfig]) -> crypto.KMSClient:
    pinned = _byok.build_kms_for_tenant(config)
    return pinned if pinned is not None else crypto.get_kms()


async def mint_and_store(conn: Any, tenant_id: str) -> crypto.TenantKey:
    """Mint a new DEK for ``tenant_id``, persist it, and cache it.

    If the tenant already has an active DEK, that one is returned
    unchanged — this operation is idempotent on the happy path.
    """
    config = await _load_byok_config(conn, tenant_id)
    kms = _kms_for(config)
    _byok.register_tenant_kms(tenant_id, kms if config else None)

    existing = await conn.fetchrow(
        "SELECT kid, wrapped_dek FROM tenant_keys "
        "WHERE tenant_id = $1 AND is_active = TRUE",
        tenant_id,
    )
    if existing:
        return crypto.install_tenant_key(
            tenant_id, bytes(existing["wrapped_dek"]), kms=kms,
        )

    key = crypto.mint_tenant_key(tenant_id, kms=kms)
    await conn.execute(
        "INSERT INTO tenant_keys (tenant_id, kid, wrapped_dek, kek_id) "
        "VALUES ($1, $2, $3, $4)",
        tenant_id, key.kid, key.wrapped_dek, kms.kek_id,
    )
    return key


async def hydrate(conn: Any, tenant_ids: Optional[Iterable[str]] = None) -> List[str]:
    """Install every active DEK so the process can encrypt/decrypt.

    Returns the list of tenant_ids whose keys were hydrated. Safe to
    call multiple times: ``install_tenant_key`` simply refreshes the
    cache entry.

    Each tenant's BYOK selection (if any) is looked up so the right
    KMS handles unwrap and so subsequent encrypt/decrypt calls go
    through the same client.
    """
    if tenant_ids is None:
        rows = await conn.fetch(
            "SELECT tenant_id, wrapped_dek FROM tenant_keys WHERE is_active = TRUE"
        )
    else:
        ids = list(tenant_ids)
        if not ids:
            return []
        rows = await conn.fetch(
            "SELECT tenant_id, wrapped_dek FROM tenant_keys "
            "WHERE is_active = TRUE AND tenant_id = ANY($1::text[])",
            ids,
        )

    loaded: List[str] = []
    for row in rows:
        tenant_id = row["tenant_id"]
        config = await _load_byok_config(conn, tenant_id)
        kms = _kms_for(config)
        _byok.register_tenant_kms(tenant_id, kms if config else None)
        crypto.install_tenant_key(tenant_id, bytes(row["wrapped_dek"]), kms=kms)
        loaded.append(tenant_id)
    return loaded


async def rotate(conn: Any, tenant_id: str) -> crypto.TenantKey:
    """Rotate a tenant's DEK. Old row is marked retired; both DEKs
    stay in the cache so legacy ciphertexts still decrypt during the
    re-encryption window.

    A rotation also re-resolves BYOK — used when the tenant has just
    pointed AGCMS at a different customer KMS key.
    """
    config = await _load_byok_config(conn, tenant_id)
    kms = _kms_for(config)
    _byok.register_tenant_kms(tenant_id, kms if config else None)

    async with conn.transaction():
        await conn.execute(
            "UPDATE tenant_keys SET is_active = FALSE, retired_at = NOW() "
            "WHERE tenant_id = $1 AND is_active = TRUE",
            tenant_id,
        )
        key = crypto.mint_tenant_key(tenant_id, kms=kms)
        await conn.execute(
            "INSERT INTO tenant_keys (tenant_id, kid, wrapped_dek, kek_id) "
            "VALUES ($1, $2, $3, $4)",
            tenant_id, key.kid, key.wrapped_dek, kms.kek_id,
        )
        return key


__all__ = ["mint_and_store", "hydrate", "rotate"]
