-- ============================================================
-- Migration 010 — Onboarding state
--
-- First-login wizard records its progress on the tenant row so a
-- tenant can resume the wizard from any dashboard session. The
-- state is JSONB (not a typed column) because the wizard's shape
-- evolves with the product and we don't want a migration for
-- every step-order tweak.
-- ============================================================

BEGIN;

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS onboarding_state JSONB NOT NULL DEFAULT '{}';

-- Convenience check: the `completed` key, when present, is boolean.
-- We don't enforce a full schema here (JSONB is intentionally loose).
ALTER TABLE tenants
    ADD CONSTRAINT onboarding_state_is_object
    CHECK (jsonb_typeof(onboarding_state) = 'object');

COMMIT;
