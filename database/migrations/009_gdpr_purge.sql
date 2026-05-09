-- ============================================================
-- AGCMS Migration 009 — GDPR Article 17 (right to erasure)
-- Phase 6.6: purge subject PII from audit logs while keeping
--            the tamper-evident hash chain verifiable.
-- ============================================================
--
-- Design: "tombstone with witness."
--   1. Subject PII fields on targeted audit_logs rows are overwritten
--      with fixed sentinel strings ('[REDACTED]').
--   2. The row is re-signed. The new log_signature covers the redacted
--      shape PLUS two new signing fields:
--        * redaction_record_id       (UUID pointing at the approval)
--        * pre_redaction_signature   (the signature prior to redaction)
--   3. Chain continuity: downstream rows are NOT rewritten. The chain
--      verifier, when it encounters a row whose pre_redaction_signature
--      is not NULL, uses that value (the original signature) when
--      checking the NEXT row's previous_log_hash. Linkage preserved.
--   4. Integrity of the redaction itself: every redaction_records row
--      is HMAC-signed by the audit service using the active row key.
--      Tampering with pre_redaction_signature or the row contents by
--      a DB-level attacker is still detectable because the redaction
--      record's approval_signature pins the original/redacted pair
--      and the purge approval linkage.

BEGIN;

-- ------------------------------------------------------------
-- 1. gdpr_purge_requests — the 2-admin approval workflow
-- ------------------------------------------------------------
-- A purge is not executable until a second admin (different from the
-- requester) approves within the 24-hour window. After 24h without
-- approval, the row flips to 'expired'.
--
-- approval_signature: HMAC over the immutable request fields using the
-- active row-signing key. Makes the approval itself tamper-evident.
CREATE TABLE IF NOT EXISTS gdpr_purge_requests (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_user_id      VARCHAR(256) NOT NULL,
    subject_tenant_user_id UUID REFERENCES tenant_users(id),
    requested_by         UUID NOT NULL REFERENCES tenant_users(id),
    requested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approval_expires_at  TIMESTAMPTZ NOT NULL,
    approved_by          UUID REFERENCES tenant_users(id),
    approved_at          TIMESTAMPTZ,
    rejected_by          UUID REFERENCES tenant_users(id),
    rejected_at          TIMESTAMPTZ,
    executed_at          TIMESTAMPTZ,
    rows_redacted        BIGINT,
    state                VARCHAR(16) NOT NULL DEFAULT 'pending'
                         CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'executed')),
    reason               TEXT NOT NULL,
    approval_signature   CHAR(64),
    CHECK (requested_by <> approved_by OR approved_by IS NULL)
);

CREATE INDEX idx_gdpr_purge_requests_tenant
    ON gdpr_purge_requests (tenant_id, requested_at DESC);
CREATE INDEX idx_gdpr_purge_requests_state
    ON gdpr_purge_requests (tenant_id, state, approval_expires_at)
    WHERE state IN ('pending', 'approved');

-- ------------------------------------------------------------
-- 2. redaction_records — per-row proof of lawful redaction
-- ------------------------------------------------------------
-- One row per audit_log row that was redacted. Stores the original
-- signature (the chain-linkage anchor for the next row) plus the
-- post-redaction signature, both covered by record_signature so a
-- DB-level attacker cannot fabricate a redaction.
CREATE TABLE IF NOT EXISTS redaction_records (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purge_request_id        UUID NOT NULL REFERENCES gdpr_purge_requests(id) ON DELETE RESTRICT,
    tenant_id               VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    audit_interaction_id    UUID NOT NULL,
    audit_sequence_number   BIGINT NOT NULL,
    audit_created_at        TIMESTAMPTZ NOT NULL,
    original_signature      CHAR(64) NOT NULL,
    redacted_signature      CHAR(64) NOT NULL,
    signing_key_id          VARCHAR(32) NOT NULL REFERENCES signing_keys(kid),
    record_signature        CHAR(64) NOT NULL,
    redacted_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (audit_interaction_id)
);

CREATE INDEX idx_redaction_records_purge
    ON redaction_records (purge_request_id);
CREATE INDEX idx_redaction_records_tenant
    ON redaction_records (tenant_id, redacted_at DESC);

-- ------------------------------------------------------------
-- 3. audit_logs — redaction columns
-- ------------------------------------------------------------
-- redaction_record_id     — FK to the approval chain that authorized
--                           this row's redaction (NULL for un-redacted).
-- pre_redaction_signature — the signature BEFORE redaction; used by
--                           the chain verifier for linkage continuity.
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS redaction_record_id UUID,
    ADD COLUMN IF NOT EXISTS pre_redaction_signature CHAR(64);

-- Partial index so un-redacted rows do not pay a scan penalty.
CREATE INDEX IF NOT EXISTS idx_audit_redacted
    ON audit_logs (tenant_id, redaction_record_id)
    WHERE redaction_record_id IS NOT NULL;

-- ------------------------------------------------------------
-- 4. Row-Level Security
-- ------------------------------------------------------------
ALTER TABLE gdpr_purge_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_gdpr_purge_requests ON gdpr_purge_requests
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_redaction_records ON redaction_records
    USING (tenant_id = current_setting('app.current_tenant_id', true));

COMMIT;
