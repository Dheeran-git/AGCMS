-- ============================================================
-- Migration 006 — Per-tenant Data Encryption Keys (Phase 6.3)
-- Adds the `tenant_keys` table for envelope-encryption bootstrap.
--
-- Each tenant gets one active DEK at any time. The DEK itself is
-- never stored; only its wrapped form (opaque bytes from the KMS)
-- plus a derived 16-byte key-id (`kid`) used to link ciphertexts
-- back to the DEK version that produced them.
--
-- Rotation keeps the prior DEK row with retired_at set until all
-- ciphertexts bearing its kid have been re-encrypted.
-- ============================================================

CREATE TABLE tenant_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid             BYTEA NOT NULL,           -- 16-byte DEK identifier
    wrapped_dek     BYTEA NOT NULL,           -- KMS-wrapped DEK
    kek_id          VARCHAR(64) NOT NULL,     -- KMS KEK identifier (rotation evidence)
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at      TIMESTAMPTZ,
    CHECK (octet_length(kid) = 16),
    CHECK (octet_length(wrapped_dek) >= 28)   -- AES-GCM: 12B nonce + 16B tag minimum
);

CREATE UNIQUE INDEX idx_tenant_keys_one_active
    ON tenant_keys (tenant_id) WHERE is_active;

CREATE INDEX idx_tenant_keys_kid ON tenant_keys (tenant_id, kid);

ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenant_keys ON tenant_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true));
