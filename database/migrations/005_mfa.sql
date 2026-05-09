-- Phase 6.2 — Multi-Factor Authentication (TOTP + recovery codes)
--
-- One row per enrolled tenant_user. A tenant_user without a row here has
-- not enrolled MFA. ``enabled`` gates login: a freshly-enrolled user's
-- row is inserted with enabled=FALSE and only flips to TRUE after the
-- user proves possession of the secret via /v1/auth/mfa/verify-enrollment.
--
-- ``totp_secret`` is stored as the plaintext base32 string in this phase.
-- Phase 6.3 (envelope encryption at rest) will wrap it with a per-tenant
-- DEK and migrate existing rows through the KMS abstraction.
--
-- ``recovery_codes`` is a JSONB array of SHA-256 hex hashes. Recovery
-- codes are single-use: a successful login with one removes that hash
-- from the array atomically.

CREATE TABLE IF NOT EXISTS user_mfa (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_user_id    UUID NOT NULL UNIQUE
                           REFERENCES tenant_users(id) ON DELETE CASCADE,
    totp_secret       VARCHAR(64) NOT NULL,
    recovery_codes    JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    enrolled_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at       TIMESTAMPTZ,
    last_used_at      TIMESTAMPTZ,
    disabled_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_user_mfa_enabled
    ON user_mfa (enabled) WHERE enabled = TRUE;
