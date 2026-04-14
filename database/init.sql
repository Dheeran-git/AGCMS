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
    settings        JSONB NOT NULL DEFAULT '{}'
);

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
    UNIQUE(tenant_id, external_id)
);

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
-- 4. AUDIT LOGS (partitioned by month)
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
    schema_version      VARCHAR(8) NOT NULL DEFAULT '1.0',
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

-- ============================================================
-- 5. ESCALATIONS
-- ============================================================
CREATE TABLE escalations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interaction_id  UUID NOT NULL,
    tenant_id       VARCHAR(32) NOT NULL REFERENCES tenants(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason          TEXT NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'REVIEWED', 'DISMISSED', 'ACTIONED')),
    reviewed_by     UUID REFERENCES tenant_users(id),
    reviewed_at     TIMESTAMPTZ,
    notes           TEXT
);

CREATE INDEX idx_escalations_tenant_status ON escalations (tenant_id, status)
    WHERE status = 'PENDING';

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
-- 7. ROW-LEVEL SECURITY
-- ============================================================
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE escalations ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_audit ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_policies ON policies
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_escalations ON escalations
    USING (tenant_id = current_setting('app.current_tenant_id', true));

CREATE POLICY tenant_isolation_users ON tenant_users
    USING (tenant_id = current_setting('app.current_tenant_id', true));

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

-- Default admin user
INSERT INTO tenant_users (tenant_id, external_id, email, department, role)
VALUES (
    'default',
    'admin',
    'admin@agcms.local',
    'Engineering',
    'admin'
);

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
