-- Phase 7.5: notification providers + rules.
--
-- Tenants configure outbound channels (Slack / PagerDuty / webhook /
-- SMTP / Splunk HEC) and routing rules ("notify Slack #compliance on
-- every BLOCK; page on-call on audit-chain breaks").
--
-- ``notification_providers.config`` is a JSONB blob holding only the
-- kind-specific settings (webhook URL, SMTP host, HEC token, etc.) so
-- the table doesn't need a column per provider variant. Secrets in
-- ``config`` are encrypted at-rest in the same envelope-encryption
-- scheme used elsewhere; the dispatcher decrypts on read.

CREATE TABLE notification_providers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind        VARCHAR(32) NOT NULL
                CHECK (kind IN ('slack', 'pagerduty', 'webhook', 'email', 'splunk_hec')),
    name        VARCHAR(128) NOT NULL,
    config      JSONB NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_notif_providers_tenant ON notification_providers (tenant_id);

CREATE TABLE notification_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id   UUID NOT NULL REFERENCES notification_providers(id) ON DELETE CASCADE,
    trigger_event VARCHAR(32) NOT NULL
                  CHECK (trigger_event IN (
                      'violation', 'escalation', 'audit_chain_break', 'rate_limit_breach'
                  )),
    severity_min  VARCHAR(16) NOT NULL DEFAULT 'info'
                  CHECK (severity_min IN ('info', 'warning', 'critical')),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_rules_dispatch
    ON notification_rules (tenant_id, trigger_event, enabled);

CREATE TABLE notification_deliveries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     VARCHAR(32) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id       UUID REFERENCES notification_rules(id) ON DELETE SET NULL,
    provider_kind VARCHAR(32) NOT NULL,
    trigger_event VARCHAR(32) NOT NULL,
    severity      VARCHAR(16) NOT NULL,
    status        VARCHAR(16) NOT NULL CHECK (status IN ('sent', 'failed', 'retrying')),
    attempts      INTEGER NOT NULL DEFAULT 1,
    error         TEXT,
    payload       JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notif_deliveries_tenant_time
    ON notification_deliveries (tenant_id, created_at DESC);
