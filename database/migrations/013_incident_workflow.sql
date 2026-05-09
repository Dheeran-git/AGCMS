-- Phase 7.6 — incident-workflow columns on escalations.
--
-- Adds fields the Alerts page needs to drive an acknowledge → assign →
-- resolve flow with SLA timers. ``severity`` lets us pick a per-tier SLA
-- without re-classifying via reason text. ``sla_breached`` is denormalized
-- so the index can serve "what's overdue right now?" without a window
-- scan; the gateway updates it lazily on read.

ALTER TABLE escalations
    ADD COLUMN IF NOT EXISTS severity         VARCHAR(16) NOT NULL DEFAULT 'warning'
                             CHECK (severity IN ('info', 'warning', 'critical')),
    ADD COLUMN IF NOT EXISTS assignee_user_id UUID REFERENCES tenant_users(id),
    ADD COLUMN IF NOT EXISTS acknowledged_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS acknowledged_by  UUID REFERENCES tenant_users(id),
    ADD COLUMN IF NOT EXISTS resolved_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resolved_by      UUID REFERENCES tenant_users(id),
    ADD COLUMN IF NOT EXISTS resolution_notes TEXT,
    ADD COLUMN IF NOT EXISTS sla_breached     BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_escalations_open_by_severity
    ON escalations (tenant_id, severity, created_at)
    WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_escalations_assignee
    ON escalations (assignee_user_id)
    WHERE assignee_user_id IS NOT NULL AND resolved_at IS NULL;
