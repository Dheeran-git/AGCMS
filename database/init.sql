-- ============================================================
-- AGCMS — Full Database Schema
-- AI Governance and Compliance Monitoring System
-- PostgreSQL 16 · Multi-tenant with Row-Level Security
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- 1. TENANTS
-- ============================================================
CREATE TABLE tenants (
    id              VARCHAR(32) PRIMARY KEY,
    name            VARCHAR(256) NOT NULL,
    plan            VARCHAR(32) NOT NULL CHECK (plan IN ('starter', 'business', 'enterprise')),
    admin_email     VARCHAR(256) NOT NULL,
    api_key_hash    CHAR(64) NOT NULL UNIQUE,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    settings        JSONB NOT NULL DEFAULT '{}',
    workos_org_id   VARCHAR(100),
    sso_enforced    BOOLEAN NOT NULL DEFAULT FALSE,
    onboarding_state JSONB NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(onboarding_state) = 'object'),
    demo_mode_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    -- Phase 10.3 BYOK: customer-managed KMS key. NULL = platform KEK.
    kms_key_arn      TEXT,
    kms_key_provider VARCHAR(16)
        CHECK (kms_key_provider IN ('aws', 'gcp', 'azure', NULL))
);

CREATE INDEX idx_tenants_byok_enabled
    ON tenants (id) WHERE kms_key_arn IS NOT NULL;

CREATE UNIQUE INDEX idx_tenants_workos_org_id
    ON tenants (workos_org_id) WHERE workos_org_id IS NOT NULL;

-- ============================================================
-- 2. TENANT USERS
-- ============================================================
CREATE TABLE tenant_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(32) NOT NULL REFERENCES tenants(id),
    external_id     VARCHAR(256) NOT NULL,
    email           VARCHAR(256),
    department      VARCHAR(128),
    role            VARCHAR(32) NOT NULL CHECK (role IN ('admin', 'compliance', 'user')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sso_subject     VARCHAR(200),
    auth_provider   VARCHAR(32),  -- 'workos' | 'api_key' | NULL
    revoked_before  TIMESTAMPTZ,  -- Phase 6.5: bulk session revocation pivot
    UNIQUE(tenant_id, external_id)
);

CREATE UNIQUE INDEX idx_tenant_users_sso_subject
    ON tenant_users (tenant_id, sso_subject)
    WHERE sso_subject IS NOT NULL;

-- Per-user multi-factor authentication. One row per enrolled user.
-- totp_secret is plaintext in this phase; wrapped with envelope
-- encryption in Phase 6.3.
CREATE TABLE user_mfa (
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
CREATE INDEX idx_user_mfa_enabled ON user_mfa (enabled) WHERE enabled = TRUE;

-- ============================================================
-- 2a. API KEYS (scoped per-tenant keys, Phase 6.4)
-- ============================================================
CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL DEFAULT 'default',
    key_hash        CHAR(64) NOT NULL UNIQUE,
    scopes          TEXT[] NOT NULL DEFAULT ARRAY['ingest']::TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID,
    notes           TEXT,
    CHECK (array_length(scopes, 1) >= 1)
);
CREATE INDEX idx_api_keys_tenant_active
    ON api_keys (tenant_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX idx_api_keys_tenant_name_active
    ON api_keys (tenant_id, name) WHERE revoked_at IS NULL;

-- ============================================================
-- 2b. TENANT KEYS (per-tenant DEK registry, Phase 6.3)
-- ============================================================
-- One active DEK per tenant; rotation keeps prior rows with
-- retired_at set until all ciphertexts with that kid are rewritten.
CREATE TABLE tenant_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid             BYTEA NOT NULL,
    wrapped_dek     BYTEA NOT NULL,
    kek_id          VARCHAR(64) NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at      TIMESTAMPTZ,
    CHECK (octet_length(kid) = 16),
    CHECK (octet_length(wrapped_dek) >= 28)
);

CREATE UNIQUE INDEX idx_tenant_keys_one_active
    ON tenant_keys (tenant_id) WHERE is_active;

CREATE INDEX idx_tenant_keys_kid ON tenant_keys (tenant_id, kid);

-- ============================================================
-- 2c. AUTH SESSIONS (per-access-token rows, revocation surface, Phase 6.5)
-- ============================================================
CREATE TABLE auth_sessions (
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
CREATE INDEX idx_auth_sessions_user_active
    ON auth_sessions (tenant_user_id, issued_at DESC)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_tenant
    ON auth_sessions (tenant_id, issued_at DESC);
CREATE INDEX idx_auth_sessions_expiry
    ON auth_sessions (expires_at) WHERE revoked_at IS NULL;

-- ============================================================
-- 3. POLICIES (versioned, one active per tenant)
-- ============================================================
CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(32) NOT NULL REFERENCES tenants(id),
    config          JSONB NOT NULL,
    version         VARCHAR(16) NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      UUID REFERENCES tenant_users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    notes           TEXT
);

CREATE INDEX idx_policies_tenant_active ON policies (tenant_id) WHERE is_active = TRUE;

-- ============================================================
-- 4. AUDIT LOGS (partitioned by month, hash-chained per tenant)
-- ============================================================
CREATE TABLE audit_logs (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    interaction_id      UUID NOT NULL,
    tenant_id           VARCHAR(32) NOT NULL,
    user_id             VARCHAR(256) NOT NULL,
    department          VARCHAR(128),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    llm_provider        VARCHAR(64) NOT NULL,
    llm_model           VARCHAR(128),
    prompt_hash         CHAR(64) NOT NULL,
    sanitized_hash      CHAR(64),
    pii_detected        BOOLEAN NOT NULL DEFAULT FALSE,
    pii_entity_types    TEXT[],
    pii_risk_level      VARCHAR(16),
    injection_score     NUMERIC(4,3),
    injection_type      VARCHAR(32),
    enforcement_action  VARCHAR(16) NOT NULL,
    enforcement_reason  TEXT,
    triggered_policies  TEXT[],
    response_violated   BOOLEAN DEFAULT FALSE,
    response_violations JSONB,
    total_latency_ms    INTEGER,
    pii_latency_ms      INTEGER,
    injection_latency_ms INTEGER,
    response_latency_ms  INTEGER,
    llm_latency_ms       INTEGER,
    log_signature       CHAR(64) NOT NULL,
    schema_version      VARCHAR(8) NOT NULL DEFAULT '2.0',
    -- Phase 5.1 chain columns: every chain row (sequence_number >= 1)
    -- includes the previous row's log_signature in its signing payload.
    previous_log_hash   CHAR(64),
    sequence_number     BIGINT NOT NULL DEFAULT 0,
    signing_key_id      VARCHAR(32) NOT NULL DEFAULT 'v1',
    -- Phase 6.6 redaction columns: NULL for normal rows; set when a
    -- GDPR Art. 17 purge has tombstoned PII on this row. The chain
    -- verifier uses pre_redaction_signature (when present) as the
    -- linkage target for the next row's previous_log_hash.
    redaction_record_id     UUID,
    pre_redaction_signature CHAR(64),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Default partition (catches any date not covered by monthly partitions)
CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT;

-- Monthly partitions for 2026
CREATE TABLE audit_logs_2026_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE audit_logs_2026_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit_logs_2026_03 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE audit_logs_2026_04 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE audit_logs_2026_05 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_logs_2026_06 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');
CREATE TABLE audit_logs_2026_07 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
CREATE TABLE audit_logs_2026_08 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-08-01') TO ('2026-09-01');
CREATE TABLE audit_logs_2026_09 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE audit_logs_2026_10 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE audit_logs_2026_11 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');
CREATE TABLE audit_logs_2026_12 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-12-01') TO ('2027-01-01');

-- Indexes for dashboard queries
CREATE INDEX idx_audit_tenant_created ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs (tenant_id, user_id, created_at DESC);
CREATE INDEX idx_audit_violations ON audit_logs (tenant_id, enforcement_action)
    WHERE enforcement_action != 'ALLOW';
CREATE INDEX idx_audit_injection ON audit_logs (tenant_id, injection_type)
    WHERE injection_score > 0.5;
CREATE INDEX idx_audit_interaction ON audit_logs (interaction_id, created_at);
CREATE INDEX idx_audit_chain ON audit_logs (tenant_id, sequence_number)
    WHERE sequence_number > 0;
CREATE INDEX idx_audit_redacted ON audit_logs (tenant_id, redaction_record_id)
    WHERE redaction_record_id IS NOT NULL;

-- ============================================================
-- 4a. SIGNING KEYS (kid-indexed registry for row + anchor signing)
-- ============================================================
CREATE TABLE signing_keys (
    kid         VARCHAR(32) PRIMARY KEY,
    purpose     VARCHAR(16) NOT NULL CHECK (purpose IN ('row', 'anchor')),
    key_hash    CHAR(64),
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at  TIMESTAMPTZ,
    notes       TEXT
);

CREATE UNIQUE INDEX idx_signing_keys_one_active_per_purpose
    ON signing_keys (purpose) WHERE is_active;

-- Signing-key rotation workflow (dual-approval).
-- Key material is never stored here — only the SHA-256 fingerprint.
CREATE TABLE signing_key_rotations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose         VARCHAR(16) NOT NULL CHECK (purpose IN ('row', 'anchor')),
    new_kid         VARCHAR(32) NOT NULL,
    new_key_hash    CHAR(64)    NOT NULL,
    old_kid         VARCHAR(32) NOT NULL,
    state           VARCHAR(16) NOT NULL DEFAULT 'proposed'
                    CHECK (state IN ('proposed', 'approved', 'executed', 'cancelled')),
    proposed_by     VARCHAR(64) NOT NULL,
    approved_by     VARCHAR(64),
    executed_by     VARCHAR(64),
    cancelled_by    VARCHAR(64),
    reason          TEXT NOT NULL,
    proposed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at     TIMESTAMPTZ,
    executed_at     TIMESTAMPTZ,
    cancelled_at    TIMESTAMPTZ
);
CREATE UNIQUE INDEX idx_signing_key_rotations_one_open_per_purpose
    ON signing_key_rotations (purpose)
    WHERE state IN ('proposed', 'approved');
CREATE INDEX idx_signing_key_rotations_state_proposed_at
    ON signing_key_rotations (state, proposed_at DESC);

-- ============================================================
-- 4b. CHAIN HEADS (per-tenant chain tip, serialization lock)
-- ============================================================
CREATE TABLE chain_heads (
    tenant_id             VARCHAR(32) PRIMARY KEY REFERENCES tenants(id),
    last_sequence_number  BIGINT NOT NULL DEFAULT 0,
    last_log_signature    CHAR(64),
    last_row_created_at   TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 4c. AUDIT ROOTS (nightly Merkle-tree anchors)
-- ============================================================
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

-- ============================================================
-- 5. ESCALATIONS
-- ============================================================
CREATE TABLE escalations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interaction_id    UUID NOT NULL,
    tenant_id         VARCHAR(32) NOT NULL REFERENCES tenants(id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason            TEXT NOT NULL,
    status            VARCHAR(16) NOT NULL DEFAULT 'PENDING'
                      CHECK (status IN ('PENDING', 'REVIEWED', 'DISMISSED', 'ACTIONED')),
    severity          VARCHAR(16) NOT NULL DEFAULT 'warning'
                      CHECK (severity IN ('info', 'warning', 'critical')),
    reviewed_by       UUID REFERENCES tenant_users(id),
    reviewed_at       TIMESTAMPTZ,
    notes             TEXT,
    -- Phase 7.6 incident-workflow fields
    assignee_user_id  UUID REFERENCES tenant_users(id),
    acknowledged_at   TIMESTAMPTZ,
    acknowledged_by   UUID REFERENCES tenant_users(id),
    resolved_at       TIMESTAMPTZ,
    resolved_by       UUID REFERENCES tenant_users(id),
    resolution_notes  TEXT,
    sla_breached      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_escalations_tenant_status ON escalations (tenant_id, status)
    WHERE status = 'PENDING';
CREATE INDEX idx_escalations_open_by_severity
    ON escalations (tenant_id, severity, created_at)
    WHERE resolved_at IS NULL;
CREATE INDEX idx_escalations_assignee
    ON escalations (assignee_user_id)
    WHERE assignee_user_id IS NOT NULL AND resolved_at IS NULL;

-- ============================================================
-- 6. RATE LIMIT TRACKING
-- ============================================================
CREATE TABLE rate_limit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       VARCHAR(32) NOT NULL,
    user_id         VARCHAR(256),
    window_start    TIMESTAMPTZ NOT NULL,
    request_count   INTEGER NOT NULL DEFAULT 1,
    limit_hit       BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_rate_limit_tenant_window ON rate_limit_events (tenant_id, window_start DESC);

-- ============================================================
-- 6a. GDPR ARTICLE 17 — PURGE WORKFLOW (Phase 6.6)
-- ============================================================
-- Two-admin approval for erasure of data-subject PII from audit logs.
-- See migration 009_gdpr_purge.sql for the full design note.
CREATE TABLE gdpr_purge_requests (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id              VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_user_id        VARCHAR(256) NOT NULL,
    subject_tenant_user_id UUID REFERENCES tenant_users(id),
    requested_by           UUID NOT NULL REFERENCES tenant_users(id),
    requested_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approval_expires_at    TIMESTAMPTZ NOT NULL,
    approved_by            UUID REFERENCES tenant_users(id),
    approved_at            TIMESTAMPTZ,
    rejected_by            UUID REFERENCES tenant_users(id),
    rejected_at            TIMESTAMPTZ,
    executed_at            TIMESTAMPTZ,
    rows_redacted          BIGINT,
    state                  VARCHAR(16) NOT NULL DEFAULT 'pending'
                           CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'executed')),
    reason                 TEXT NOT NULL,
    approval_signature     CHAR(64),
    CHECK (requested_by <> approved_by OR approved_by IS NULL)
);

CREATE INDEX idx_gdpr_purge_requests_tenant
    ON gdpr_purge_requests (tenant_id, requested_at DESC);
CREATE INDEX idx_gdpr_purge_requests_state
    ON gdpr_purge_requests (tenant_id, state, approval_expires_at)
    WHERE state IN ('pending', 'approved');

-- One redaction_records row per audit_log row that was tombstoned.
CREATE TABLE redaction_records (
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

-- ============================================================
-- 7. ROW-LEVEL SECURITY
-- ============================================================
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_roots ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gdpr_purge_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_records ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_policies ON policies
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_escalations ON escalations
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_users ON tenant_users
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_chain_heads ON chain_heads
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_audit_roots ON audit_roots
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_tenant_keys ON tenant_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_api_keys ON api_keys
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_auth_sessions ON auth_sessions
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_gdpr_purge_requests ON gdpr_purge_requests
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_redaction_records ON redaction_records
    USING (tenant_id = current_setting('app.current_tenant_id', true));

-- signing_keys is cluster-level operational metadata; no tenant scoping.

-- ============================================================
-- 8. SEED DATA (Development)
-- ============================================================

-- Default tenant for Phase 1 development
-- API key: agcms_test_key_for_development
-- Hash: SHA-256 of the above string
INSERT INTO tenants (id, name, plan, admin_email, api_key_hash, is_active)
VALUES (
    'default',
    'Default Organization',
    'business',
    'admin@agcms.local',
    encode(digest('agcms_test_key_for_development', 'sha256'), 'hex'),
    TRUE
);

-- Dev API key, scoped all-access to keep existing tests + playground working.
INSERT INTO api_keys (tenant_id, name, key_hash, scopes, notes)
VALUES (
    'default',
    'dev',
    encode(digest('agcms_test_key_for_development', 'sha256'), 'hex'),
    ARRAY['ingest', 'read:audit', 'read:policy', 'write:policy', 'admin']::TEXT[],
    'Phase 1 dev key — all scopes, never revoke in development'
);

-- Default admin user
INSERT INTO tenant_users (tenant_id, external_id, email, department, role)
VALUES (
    'default',
    'admin',
    'admin@agcms.local',
    'Engineering',
    'admin'
);

-- Initial active signing keys. key_hash is populated at audit-service
-- startup (see agcms-audit/agcms/audit/keys.py) from the live key material
-- in AGCMS_SIGNING_KEY / AGCMS_ANCHOR_KEY. Leaving NULL here avoids
-- committing key fingerprints to source control.
INSERT INTO signing_keys (kid, purpose, is_active, notes) VALUES
    ('v1', 'row',    TRUE, 'Initial active row-signing key. Material in AGCMS_SIGNING_KEY.'),
    ('a1', 'anchor', TRUE, 'Initial active Merkle anchor key. Material in AGCMS_ANCHOR_KEY.');

-- Legacy marker for any rows written before chain enforcement.
INSERT INTO signing_keys (kid, purpose, is_active, retired_at, notes) VALUES
    ('v0', 'row', FALSE, NOW(),
     'Legacy pre-chain marker. No key material on file; historical rows only.');

-- Chain head for the default tenant (sequence starts at 0; first real row is 1).
INSERT INTO chain_heads (tenant_id) VALUES ('default');

-- Default policy
INSERT INTO policies (tenant_id, config, version, is_active, notes)
VALUES (
    'default',
    '{
        "pii": {
            "enabled": true,
            "action_on_detection": "REDACT",
            "critical_action": "BLOCK",
            "risk_threshold": "MEDIUM",
            "custom_patterns": {}
        },
        "injection": {
            "enabled": true,
            "block_threshold": 0.65,
            "action_on_detection": "BLOCK",
            "log_all_attempts": true
        },
        "response_compliance": {
            "enabled": true,
            "restricted_topics": [],
            "system_prompt_keywords": [],
            "action_on_violation": "REDACT"
        },
        "rate_limits": {
            "requests_per_minute": 60,
            "requests_per_day": 10000
        },
        "audit": {
            "retention_days": 365,
            "export_formats": ["json", "csv"],
            "pii_in_logs": false
        }
    }'::jsonb,
    '1.0.0',
    TRUE,
    'Default Phase 1 policy'
);

-- Verification
SELECT 'AGCMS schema initialized successfully' AS status,
       (SELECT count(*) FROM tenants) AS tenants,
       (SELECT count(*) FROM policies) AS policies;
