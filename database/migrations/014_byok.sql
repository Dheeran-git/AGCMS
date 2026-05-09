-- ============================================================
-- Migration 014 — Bring-Your-Own-Key (BYOK) for envelope encryption
-- (Phase 10.3)
--
-- Adds a per-tenant pointer to a customer-managed KMS key. When set,
-- the AGCMS envelope-encryption layer wraps and unwraps that tenant's
-- DEK via the customer's KMS instead of the AGCMS-platform KEK.
--
-- Backwards compatible: tenants with kms_key_arn = NULL continue to
-- use the platform KMS exactly as before. Existing tenant_keys rows
-- (and the wrapped_dek bytes therein) remain valid until a rotation.
-- ============================================================

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS kms_key_arn TEXT,
    ADD COLUMN IF NOT EXISTS kms_key_provider VARCHAR(16)
        CHECK (kms_key_provider IN ('aws', 'gcp', 'azure', NULL));

CREATE INDEX IF NOT EXISTS idx_tenants_byok_enabled
    ON tenants (id) WHERE kms_key_arn IS NOT NULL;

COMMENT ON COLUMN tenants.kms_key_arn IS
    'Customer-managed KMS key identifier (ARN for AWS, resource name for GCP/Azure). '
    'When set, the tenant''s DEK is wrapped/unwrapped via this key. NULL means the '
    'AGCMS-platform KEK is used.';

COMMENT ON COLUMN tenants.kms_key_provider IS
    'Which cloud provider hosts the BYOK key. Determines which KMSClient '
    'implementation handles wrap/unwrap.';
