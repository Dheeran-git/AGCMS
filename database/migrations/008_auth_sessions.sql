-- Phase 6.5 — Session revocation
--
-- Every issued access token now produces a row in ``auth_sessions`` keyed by
-- its ``jti``. Token verification on the gateway consults this row (via a
-- short-TTL Redis cache) to detect:
--   (a) explicit per-session revocation (``revoked_at`` set)
--   (b) bulk revocation via ``tenant_users.revoked_before`` — any token whose
--       ``iat`` is older than that timestamp is rejected.
--
-- The access-token Redis blacklist keeps per-jti checks O(1); the DB row is
-- the source of truth + the surface the /sessions endpoints read from.

-- Bulk-revocation pivot: every session issued BEFORE this timestamp is dead.
ALTER TABLE tenant_users
    ADD COLUMN IF NOT EXISTS revoked_before TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS auth_sessions (
    jti              VARCHAR(64) PRIMARY KEY,
    tenant_user_id   UUID NOT NULL REFERENCES tenant_users(id) ON DELETE CASCADE,
    tenant_id        VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issued_at        TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    last_seen_at     TIMESTAMPTZ,
    revoked_at       TIMESTAMPTZ,
    revoked_by       UUID REFERENCES tenant_users(id),
    revoke_reason    VARCHAR(64),
    user_agent       TEXT,
    ip_address       INET,
    issued_via       VARCHAR(32) NOT NULL
                     CHECK (issued_via IN ('api_key', 'sso', 'mfa', 'refresh'))
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_active
    ON auth_sessions (tenant_user_id, issued_at DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant
    ON auth_sessions (tenant_id, issued_at DESC);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry
    ON auth_sessions (expires_at) WHERE revoked_at IS NULL;

-- RLS: a session row is visible only to its tenant. Admins run with the
-- tenant GUC set via gateway middleware; no need for a separate bypass.
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_auth_sessions ON auth_sessions
    USING (tenant_id = current_setting('app.current_tenant_id', true));
