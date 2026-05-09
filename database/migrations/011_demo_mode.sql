-- Phase 7.2: tenant-level demo-mode toggle.
--
-- When enabled, the gateway exposes seed/clear endpoints that fill the
-- tenant with realistic-looking demo violations / users / escalations.
-- Demo audit rows are tagged ``schema_version = 'DEMO-1.0'`` so the
-- chain verifier can recognise (and exclude) them — they don't carry
-- HMAC chain signatures because they're sandbox data.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS demo_mode_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_audit_logs_demo_schema
    ON audit_logs (tenant_id)
    WHERE schema_version = 'DEMO-1.0';
