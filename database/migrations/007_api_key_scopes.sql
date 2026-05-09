-- ============================================================
-- Migration 007 — Scoped API keys (Phase 6.4)
--
-- Replaces the single `tenants.api_key_hash` column with a dedicated
-- `api_keys` table that supports:
--   * many keys per tenant
--   * per-key scopes (ingest / read:audit / read:policy / write:policy / admin)
--   * named keys (for rotation / audit trail)
--   * revocation via revoked_at
--   * last_used_at telemetry
--
-- The legacy `tenants.api_key_hash` column stays populated for
-- backward compatibility with services that have not been updated
-- yet; new writes go to both. We remove it in a future migration.
-- ============================================================

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL DEFAULT 'default',
    key_hash        CHAR(64) NOT NULL UNIQUE,
    scopes          TEXT[] NOT NULL DEFAULT ARRAY['ingest']::TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID REFERENCES tenant_users(id),
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID REFERENCES tenant_users(id),
    notes           TEXT,
    CHECK (array_length(scopes, 1) >= 1)
);

CREATE INDEX idx_api_keys_tenant_active
    ON api_keys (tenant_id) WHERE revoked_at IS NULL;

-- Partial unique index: any given (tenant, name) must be unique among
-- active keys; revoked keys can share the name with a new replacement.
CREATE UNIQUE INDEX idx_api_keys_tenant_name_active
    ON api_keys (tenant_id, name) WHERE revoked_at IS NULL;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_api_keys ON api_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true));

-- Backfill: copy every tenant's current api_key_hash into the new
-- table as a full-scope 'legacy' key. This keeps existing API-key
-- holders working without reissuing credentials.
INSERT INTO api_keys (tenant_id, name, key_hash, scopes, notes)
SELECT
    id,
    'legacy',
    api_key_hash,
    ARRAY['ingest', 'read:audit', 'read:policy', 'write:policy', 'admin']::TEXT[],
    'Auto-backfilled from tenants.api_key_hash at 6.4 migration'
FROM tenants
WHERE api_key_hash IS NOT NULL
ON CONFLICT (key_hash) DO NOTHING;
