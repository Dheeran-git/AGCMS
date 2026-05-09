-- Migration 004 — WorkOS SSO support (Phase 6.1)
--
-- Tenants map 1:1 to a WorkOS Organization. Each tenant admin configures
-- their IdP (Okta, Azure AD, Google Workspace, etc.) inside the WorkOS
-- Organization once; AGCMS never sees raw IdP credentials.
--
-- Users authenticated via SSO are identified by their WorkOS profile.id
-- (stored as ``sso_subject``). A single tenant_users row can carry an
-- sso_subject + an external_id, or either alone (API-key-only users have
-- no sso_subject; SSO-provisioned users have no API key).

BEGIN;

ALTER TABLE tenants
    ADD COLUMN workos_org_id  VARCHAR(100),
    ADD COLUMN sso_enforced   BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX idx_tenants_workos_org_id
    ON tenants (workos_org_id) WHERE workos_org_id IS NOT NULL;

ALTER TABLE tenant_users
    ADD COLUMN sso_subject   VARCHAR(200),
    ADD COLUMN auth_provider VARCHAR(32);  -- 'workos' | 'api_key' | NULL

CREATE UNIQUE INDEX idx_tenant_users_sso_subject
    ON tenant_users (tenant_id, sso_subject)
    WHERE sso_subject IS NOT NULL;

COMMIT;
