-- ============================================================
-- AGCMS Migration 002 — Hash-chained audit log
-- Phase 5.1: wedge completion (legally defensible audit trail)
-- ============================================================
--
-- Adds per-tenant hash chain on audit_logs, plus scaffolding for
-- nightly Merkle-root anchoring to S3 Object Lock (Phase 5.2) and
-- signing-key rotation with kid lookup (Phase 5.5).
--
-- Sequence number conventions:
--   0    = legacy row written before chain enforcement (no chain hash).
--   >= 1 = chain row. Row N's signing payload includes row (N-1)'s
--          log_signature as previous_log_hash; row 1 uses the zero hash
--          ('0' * 64).
--
-- Chain extension is serialized per-tenant via SELECT ... FOR UPDATE on
-- chain_heads. All writes for one tenant must go through the same
-- transaction path the writer uses; concurrent chain extension is not
-- permitted by design.

BEGIN;

-- ------------------------------------------------------------
-- 1. signing_keys — kid-indexed key registry
-- ------------------------------------------------------------
CREATE TABLE signing_keys (
    kid             VARCHAR(32) PRIMARY KEY,
    purpose         VARCHAR(16) NOT NULL CHECK (purpose IN ('row', 'anchor')),
    key_hash        CHAR(64),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at      TIMESTAMPTZ,
    notes           TEXT
);

-- At most one active key per purpose at any time.
CREATE UNIQUE INDEX idx_signing_keys_one_active_per_purpose
    ON signing_keys (purpose) WHERE is_active;

-- Legacy v0 row-key marker for pre-chain audit rows.
INSERT INTO signing_keys (kid, purpose, is_active, retired_at, notes)
VALUES ('v0', 'row', FALSE, NOW(),
        'Legacy pre-chain marker. No key material on file; historical rows only.');

-- ------------------------------------------------------------
-- 2. audit_logs — chain columns
-- ------------------------------------------------------------
ALTER TABLE audit_logs
    ADD COLUMN previous_log_hash CHAR(64),
    ADD COLUMN sequence_number   BIGINT,
    ADD COLUMN signing_key_id    VARCHAR(32);

-- Backfill existing rows: sequence 0 + legacy v0 key.
UPDATE audit_logs
SET signing_key_id  = 'v0',
    sequence_number = 0
WHERE signing_key_id IS NULL;

ALTER TABLE audit_logs
    ALTER COLUMN sequence_number SET NOT NULL,
    ALTER COLUMN signing_key_id  SET NOT NULL;

-- Index for chain walks; partial so only real chain rows are scanned.
CREATE INDEX idx_audit_chain ON audit_logs (tenant_id, sequence_number)
    WHERE sequence_number > 0;

-- Note: a FK from audit_logs.signing_key_id to signing_keys(kid) is
-- intentionally omitted. audit_logs is partitioned by range(created_at)
-- and maintaining cross-partition FKs is operationally painful. Integrity
-- is enforced by (a) the writer validating the kid is active at insert
-- time and (b) the chain verifier rejecting any row whose kid is missing.

-- ------------------------------------------------------------
-- 3. chain_heads — per-tenant chain tip (serialization lock)
-- ------------------------------------------------------------
-- The writer takes SELECT ... FOR UPDATE on the tenant's chain_heads row
-- for the duration of one audit insert. Postgres row-level locking gives
-- us atomic chain extension without any explicit advisory-lock dance.
CREATE TABLE chain_heads (
    tenant_id             VARCHAR(32) PRIMARY KEY REFERENCES tenants(id),
    last_sequence_number  BIGINT NOT NULL DEFAULT 0,
    last_log_signature    CHAR(64),
    last_row_created_at   TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed chain heads for every existing tenant so the first chain write
-- doesn't race against head creation.
INSERT INTO chain_heads (tenant_id)
SELECT id FROM tenants
ON CONFLICT DO NOTHING;

-- ------------------------------------------------------------
-- 4. audit_roots — nightly Merkle anchors (Phase 5.2)
-- ------------------------------------------------------------
CREATE TABLE audit_roots (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              VARCHAR(32) NOT NULL REFERENCES tenants(id),
    period_start           TIMESTAMPTZ NOT NULL,
    period_end             TIMESTAMPTZ NOT NULL,
    row_count              BIGINT NOT NULL,
    first_sequence_number  BIGINT NOT NULL,
    last_sequence_number   BIGINT NOT NULL,
    merkle_root            CHAR(64) NOT NULL,
    signed_root            CHAR(64) NOT NULL,
    anchor_key_id          VARCHAR(32) NOT NULL REFERENCES signing_keys(kid),
    s3_url                 TEXT,
    s3_object_version      TEXT,
    retention_until        TIMESTAMPTZ NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, period_start, period_end),
    CHECK (period_end > period_start),
    CHECK (last_sequence_number >= first_sequence_number),
    CHECK (row_count = last_sequence_number - first_sequence_number + 1)
);

CREATE INDEX idx_audit_roots_tenant_period
    ON audit_roots (tenant_id, period_end DESC);

-- ------------------------------------------------------------
-- 5. Row-Level Security
-- ------------------------------------------------------------
ALTER TABLE chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_roots ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_chain_heads ON chain_heads
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_audit_roots ON audit_roots
    USING (tenant_id = current_setting('app.current_tenant_id', true));

-- signing_keys is cluster-level operational metadata; no tenant scoping.
-- Access is gated at the application layer (admin role only).

COMMIT;

-- ============================================================
-- Post-migration bootstrap (runs at audit-service startup):
--   1. Hash the loaded AGCMS_SIGNING_KEY; UPSERT ('v1','row', hash, TRUE).
--   2. Hash the loaded AGCMS_ANCHOR_KEY; UPSERT ('a1','anchor', hash, TRUE).
--   3. If an existing active key's hash mismatches, fail fast — someone
--      rotated the key without going through the rotation endpoint.
-- See agcms-audit/agcms/audit/keys.py (Phase 5.5).
-- ============================================================
