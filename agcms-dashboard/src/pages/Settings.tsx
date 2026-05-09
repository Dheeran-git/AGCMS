import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  KeyRound,
  Activity,
  Gauge,
  Server,
  Shield,
  Smartphone,
  Monitor,
  Eraser,
  Sparkles,
  Bell,
  Trash2,
  Send,
  Plus,
  History,
} from 'lucide-react';
import {
  fetchPolicy,
  fetchTenantUsage,
  fetchSSOStatus,
  fetchTenantSSO,
  updateTenantSSO,
  fetchMFAStatus,
  startMFAEnrollment,
  verifyMFAEnrollment,
  disableMFA,
  fetchMySessions,
  revokeSession,
  revokeAllSessions,
  fetchPurgeRequests,
  createPurgeRequest,
  approvePurgeRequest,
  rejectPurgeRequest,
  executePurgeRequest,
  fetchDemoStatus,
  seedDemoData,
  clearDemoData,
  fetchNotificationProviders,
  createNotificationProvider,
  deleteNotificationProvider,
  testNotificationProvider,
  fetchNotificationRules,
  createNotificationRule,
  deleteNotificationRule,
  fetchNotificationDeliveries,
  fetchChangelog,
  type ChangelogEntry,
  type MFAEnrollResponse,
  type AuthSession,
  type PurgeRequest,
  type PurgeRequestState,
  type ProviderKind,
  type TriggerEvent,
  type Severity,
  type NotificationProvider,
} from '../lib/api';
import { useAuthStore } from '../stores/auth';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { StatCard } from '../components/StatCard';

function MaskedValue({ value }: { value: string }) {
  if (!value) return <span className="text-fg-subtle">—</span>;
  const masked =
    value.slice(0, 6) + '•'.repeat(Math.max(0, value.length - 10)) + value.slice(-4);
  return <span className="font-mono text-fg-secondary">{masked}</span>;
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <tr className="border-b border-border-subtle last:border-0">
      <td className="py-3 pr-6 text-caption text-fg-muted w-52">{label}</td>
      <td className="py-3 text-caption text-fg-secondary">{children}</td>
    </tr>
  );
}

function SSOCard() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ['sso-status'], queryFn: fetchSSOStatus });
  const config = useQuery({
    queryKey: ['tenant-sso'],
    queryFn: fetchTenantSSO,
    enabled: status.data?.configured === true,
    retry: false,
  });

  const [orgId, setOrgId] = useState('');
  const [enforced, setEnforced] = useState(false);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (config.data) {
      setOrgId(config.data.workos_org_id ?? '');
      setEnforced(config.data.sso_enforced);
      setDirty(false);
    }
  }, [config.data]);

  const save = useMutation({
    mutationFn: () =>
      updateTenantSSO({
        workos_org_id: orgId.trim() || '',
        sso_enforced: enforced,
      }),
    onSuccess: () => {
      setDirty(false);
      void qc.invalidateQueries({ queryKey: ['tenant-sso'] });
    },
  });

  const testLoginHref = orgId.trim()
    ? `/api/v1/auth/sso/authorize?org=${encodeURIComponent(orgId.trim())}`
    : undefined;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-accent-bright" />
          Single Sign-On (WorkOS)
        </CardTitle>
        <CardDescription>
          Link this tenant to a WorkOS organization to let users sign in via
          their corporate IdP (Okta, Azure AD, Google Workspace, etc.).
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          <span className="text-caption text-fg-muted">Deployment:</span>
          {status.isLoading ? (
            <Badge variant="subtle">checking…</Badge>
          ) : status.data?.configured ? (
            <Badge variant="success">SSO configured</Badge>
          ) : (
            <Badge variant="warning">SSO not configured on server</Badge>
          )}
        </div>

        {!status.data?.configured && (
          <p className="text-small text-fg-muted italic">
            The server admin must set <code>WORKOS_API_KEY</code>,
            {' '}<code>WORKOS_CLIENT_ID</code>, and
            {' '}<code>WORKOS_REDIRECT_URI</code> before tenants can enable SSO.
          </p>
        )}

        {status.data?.configured && (
          <>
            <table className="w-full">
              <tbody>
                <Row label="WorkOS Org ID">
                  <Input
                    placeholder="org_01HX..."
                    value={orgId}
                    disabled={config.isLoading}
                    onChange={(e) => {
                      setOrgId(e.target.value);
                      setDirty(true);
                    }}
                  />
                </Row>
                <Row label="Enforce SSO">
                  <label className="inline-flex items-center gap-2 text-fg-primary">
                    <input
                      type="checkbox"
                      checked={enforced}
                      disabled={config.isLoading}
                      onChange={(e) => {
                        setEnforced(e.target.checked);
                        setDirty(true);
                      }}
                    />
                    <span className="text-caption">
                      Require SSO for this tenant (block API-key login)
                    </span>
                  </label>
                </Row>
              </tbody>
            </table>

            {save.isError && (
              <p className="text-small text-status-danger">
                {(save.error as Error).message}
              </p>
            )}

            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                size="sm"
                disabled={!dirty || save.isPending}
                onClick={() => save.mutate()}
              >
                {save.isPending ? 'Saving…' : 'Save'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                asChild
                disabled={!testLoginHref}
              >
                <a href={testLoginHref ?? '#'} target="_blank" rel="noreferrer">
                  Test SSO login
                </a>
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function MFACard() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ['mfa-status'], queryFn: fetchMFAStatus });
  const [enrollment, setEnrollment] = useState<MFAEnrollResponse | null>(null);
  const [verifyCode, setVerifyCode] = useState('');

  const start = useMutation({
    mutationFn: startMFAEnrollment,
    onSuccess: (data) => setEnrollment(data),
  });

  const verify = useMutation({
    mutationFn: (code: string) => verifyMFAEnrollment(code),
    onSuccess: () => {
      setEnrollment(null);
      setVerifyCode('');
      void qc.invalidateQueries({ queryKey: ['mfa-status'] });
    },
  });

  const disable = useMutation({
    mutationFn: disableMFA,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['mfa-status'] });
    },
  });

  const s = status.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Smartphone className="h-4 w-4 text-accent-bright" />
          Multi-Factor Authentication (TOTP)
        </CardTitle>
        <CardDescription>
          Require a 6-digit code from an authenticator app on every
          sign-in. Strongly recommended for admin and compliance roles.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          <span className="text-caption text-fg-muted">Status:</span>
          {status.isLoading ? (
            <Badge variant="subtle">checking…</Badge>
          ) : s?.enabled ? (
            <Badge variant="success">Enabled</Badge>
          ) : s?.enrolled ? (
            <Badge variant="warning">Pending verification</Badge>
          ) : (
            <Badge variant="subtle">Not enrolled</Badge>
          )}
        </div>

        {/* Not enrolled — show Enable button */}
        {!enrollment && !s?.enabled && (
          <Button
            variant="primary"
            size="sm"
            disabled={start.isPending}
            onClick={() => start.mutate()}
          >
            {start.isPending ? 'Starting…' : 'Enable MFA'}
          </Button>
        )}

        {/* Enrollment in progress — show QR + recovery codes */}
        {enrollment && (
          <div className="space-y-4">
            <div className="flex gap-4 items-start">
              <img
                src={enrollment.qr_png_data_url}
                alt="TOTP QR code"
                className="h-40 w-40 bg-white p-2 rounded border border-border"
              />
              <div className="flex-1 space-y-2">
                <p className="text-small text-fg-muted">
                  Scan this QR code with Google Authenticator, Authy, 1Password, or
                  Microsoft Authenticator. Or paste this URI:
                </p>
                <textarea
                  readOnly
                  value={enrollment.provisioning_uri}
                  className="w-full h-16 bg-translucent-1 border border-border rounded px-2 py-1 text-label font-mono text-fg-secondary"
                />
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-caption text-fg-primary">
                Save these recovery codes NOW — they will not be shown again:
              </p>
              <div className="grid grid-cols-2 gap-2 font-mono text-caption bg-translucent-1 p-3 rounded border border-border">
                {enrollment.recovery_codes.map((c) => (
                  <span key={c} className="text-fg-primary">{c}</span>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Input
                placeholder="6-digit code"
                value={verifyCode}
                maxLength={6}
                onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ''))}
                className="w-36"
              />
              <Button
                variant="primary"
                size="sm"
                disabled={verifyCode.length !== 6 || verify.isPending}
                onClick={() => verify.mutate(verifyCode)}
              >
                {verify.isPending ? 'Verifying…' : 'Verify & enable'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setEnrollment(null);
                  setVerifyCode('');
                }}
              >
                Cancel
              </Button>
            </div>
            {verify.isError && (
              <p className="text-small text-status-danger">
                {(verify.error as Error).message}
              </p>
            )}
          </div>
        )}

        {/* Enabled — show Disable */}
        {!enrollment && s?.enabled && (
          <>
            <Button
              variant="danger"
              size="sm"
              disabled={disable.isPending}
              onClick={() => disable.mutate()}
            >
              {disable.isPending ? 'Disabling…' : 'Disable MFA'}
            </Button>
            {disable.isError && (
              <p className="text-small text-status-danger">
                {(disable.error as Error).message}
              </p>
            )}
          </>
        )}

        {start.isError && (
          <p className="text-small text-status-danger">
            {(start.error as Error).message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function formatUA(ua: string | null): string {
  if (!ua) return 'Unknown device';
  // Compact parse: pull the primary browser / OS hint, skip the fine print.
  const m = ua.match(/(Firefox|Chrome|Safari|Edge|Opera)\/\S+/);
  const os = ua.match(/\((.*?)\)/)?.[1]?.split(';')[0]?.trim();
  if (m && os) return `${m[1]} · ${os}`;
  if (m) return m[1];
  return ua.slice(0, 40);
}

function sessionStatus(s: AuthSession): { label: string; variant: 'success' | 'subtle' | 'danger' | 'warning' } {
  if (s.revoked_at) return { label: 'Revoked', variant: 'danger' };
  if (new Date(s.expires_at).getTime() < Date.now()) {
    return { label: 'Expired', variant: 'subtle' };
  }
  if (s.current) return { label: 'This device', variant: 'success' };
  return { label: 'Active', variant: 'warning' };
}

function SessionsCard() {
  const qc = useQueryClient();
  const sessions = useQuery({
    queryKey: ['my-sessions'],
    queryFn: fetchMySessions,
    refetchInterval: 30_000,
  });

  const revoke = useMutation({
    mutationFn: (jti: string) => revokeSession(jti),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['my-sessions'] }),
  });

  const revokeAll = useMutation({
    mutationFn: revokeAllSessions,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['my-sessions'] }),
  });

  const rows = sessions.data?.sessions ?? [];
  const activeCount = rows.filter(
    (r) => !r.revoked_at && new Date(r.expires_at).getTime() > Date.now()
  ).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Monitor className="h-4 w-4 text-accent-bright" />
          Active sessions
        </CardTitle>
        <CardDescription>
          Every device signed in with your account. Revoke any that look
          unfamiliar; "revoke all" also signs out this browser.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="text-caption text-fg-muted">
            {sessions.isLoading
              ? 'Loading sessions…'
              : `${activeCount} active · ${rows.length} total (last 50)`}
          </div>
          <Button
            variant="danger"
            size="sm"
            disabled={revokeAll.isPending || activeCount <= 1}
            onClick={() => {
              if (confirm('Sign out of every session, including this one?')) {
                revokeAll.mutate();
              }
            }}
          >
            {revokeAll.isPending ? 'Revoking…' : 'Revoke all'}
          </Button>
        </div>

        {rows.length === 0 && !sessions.isLoading && (
          <p className="text-small text-fg-muted italic">
            No session rows yet — your current token pre-dates session
            tracking. Sign out and back in to start recording sessions.
          </p>
        )}

        {rows.length > 0 && (
          <div className="rounded border border-border-subtle overflow-hidden">
            <table className="w-full text-caption">
              <thead className="bg-translucent-1 text-fg-muted">
                <tr>
                  <th className="text-left py-2 px-3 font-normal">Device</th>
                  <th className="text-left py-2 px-3 font-normal">Sign-in</th>
                  <th className="text-left py-2 px-3 font-normal">IP</th>
                  <th className="text-left py-2 px-3 font-normal">Issued</th>
                  <th className="text-left py-2 px-3 font-normal">Status</th>
                  <th className="text-right py-2 px-3 font-normal">Action</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const status = sessionStatus(r);
                  const canRevoke = !r.revoked_at;
                  return (
                    <tr
                      key={r.jti}
                      className="border-t border-border-subtle"
                    >
                      <td className="py-2 px-3 text-fg-secondary">
                        {formatUA(r.user_agent)}
                      </td>
                      <td className="py-2 px-3 font-mono text-fg-secondary">
                        {r.issued_via}
                      </td>
                      <td className="py-2 px-3 font-mono text-fg-secondary">
                        {r.ip_address ?? '—'}
                      </td>
                      <td className="py-2 px-3 text-fg-secondary">
                        {new Date(r.issued_at).toLocaleString()}
                      </td>
                      <td className="py-2 px-3">
                        <Badge variant={status.variant}>{status.label}</Badge>
                      </td>
                      <td className="py-2 px-3 text-right">
                        {canRevoke && !r.current && (
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={revoke.isPending}
                            onClick={() => revoke.mutate(r.jti)}
                          >
                            Revoke
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {(revoke.isError || revokeAll.isError) && (
          <p className="text-small text-status-danger">
            {((revoke.error ?? revokeAll.error) as Error).message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function purgeStateBadge(
  state: PurgeRequestState
): { label: string; variant: 'success' | 'subtle' | 'danger' | 'warning' } {
  switch (state) {
    case 'pending':
      return { label: 'Pending approval', variant: 'warning' };
    case 'approved':
      return { label: 'Approved', variant: 'success' };
    case 'rejected':
      return { label: 'Rejected', variant: 'danger' };
    case 'expired':
      return { label: 'Expired', variant: 'subtle' };
    case 'executed':
      return { label: 'Executed', variant: 'success' };
    default:
      return { label: state, variant: 'subtle' };
  }
}

function GDPRCard() {
  const qc = useQueryClient();
  const [subject, setSubject] = useState('');
  const [reason, setReason] = useState('');

  const requests = useQuery({
    queryKey: ['gdpr-purge-requests'],
    queryFn: fetchPurgeRequests,
    refetchInterval: 30_000,
  });

  const create = useMutation({
    mutationFn: () => createPurgeRequest(subject.trim(), reason.trim()),
    onSuccess: () => {
      setSubject('');
      setReason('');
      qc.invalidateQueries({ queryKey: ['gdpr-purge-requests'] });
    },
  });

  const approve = useMutation({
    mutationFn: (id: string) => approvePurgeRequest(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['gdpr-purge-requests'] }),
  });

  const reject = useMutation({
    mutationFn: (id: string) => rejectPurgeRequest(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['gdpr-purge-requests'] }),
  });

  const execute = useMutation({
    mutationFn: (id: string) => executePurgeRequest(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['gdpr-purge-requests'] }),
  });

  const rows: PurgeRequest[] = requests.data?.requests ?? [];
  const submitDisabled =
    create.isPending || subject.trim().length === 0 || reason.trim().length < 10;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Eraser className="h-4 w-4 text-accent-bright" />
          Data subject requests (GDPR Art. 17)
        </CardTitle>
        <CardDescription>
          File a right-to-erasure request. A second admin must approve within 24
          hours before the purge can run. Audit rows are tombstoned, not deleted —
          the tamper-evident chain remains verifiable.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-3 md:grid-cols-[1fr_2fr_auto] items-end">
          <div>
            <label className="text-small text-fg-muted mb-1 block">
              Subject user ID
            </label>
            <Input
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="alice@example.com"
            />
          </div>
          <div>
            <label className="text-small text-fg-muted mb-1 block">
              Reason (audit trail)
            </label>
            <Input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="DSR-42 — subject requested erasure under GDPR Art. 17"
            />
          </div>
          <Button
            onClick={() => create.mutate()}
            disabled={submitDisabled}
          >
            File request
          </Button>
        </div>

        {create.isError && (
          <p className="text-small text-status-danger">
            {(create.error as Error).message}
          </p>
        )}

        {requests.isLoading ? (
          <p className="text-small text-fg-muted">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="text-small text-fg-muted italic">No purge requests yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-small">
              <thead>
                <tr className="border-b border-border-subtle text-fg-muted">
                  <th className="text-left py-2 px-3 font-normal">Subject</th>
                  <th className="text-left py-2 px-3 font-normal">Filed</th>
                  <th className="text-left py-2 px-3 font-normal">State</th>
                  <th className="text-left py-2 px-3 font-normal">Rows</th>
                  <th className="text-right py-2 px-3 font-normal">Action</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const badge = purgeStateBadge(r.state);
                  return (
                    <tr key={r.id} className="border-b border-border-subtle">
                      <td className="py-2 px-3 font-mono text-fg-primary truncate max-w-[220px]">
                        {r.subject_user_id}
                      </td>
                      <td className="py-2 px-3 text-fg-muted">
                        {new Date(r.requested_at).toLocaleString()}
                      </td>
                      <td className="py-2 px-3">
                        <Badge variant={badge.variant}>{badge.label}</Badge>
                      </td>
                      <td className="py-2 px-3 font-mono">
                        {r.rows_redacted ?? '—'}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <div className="flex justify-end gap-2">
                          {r.state === 'pending' && (
                            <>
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={approve.isPending}
                                onClick={() => approve.mutate(r.id)}
                              >
                                Approve
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={reject.isPending}
                                onClick={() => reject.mutate(r.id)}
                              >
                                Reject
                              </Button>
                            </>
                          )}
                          {r.state === 'approved' && (
                            <Button
                              size="sm"
                              disabled={execute.isPending}
                              onClick={() => {
                                if (
                                  confirm(
                                    `Execute erasure for ${r.subject_user_id}? ` +
                                      'PII on matching audit rows will be overwritten. ' +
                                      'This cannot be undone.'
                                  )
                                ) {
                                  execute.mutate(r.id);
                                }
                              }}
                            >
                              Execute purge
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {(approve.isError || reject.isError || execute.isError) && (
          <p className="text-small text-status-danger">
            {(
              (approve.error ?? reject.error ?? execute.error) as Error
            ).message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function DemoCard() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ['demo-status'], queryFn: fetchDemoStatus });
  const seed = useMutation({
    mutationFn: seedDemoData,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['demo-status'] });
      void qc.invalidateQueries({ queryKey: ['violations'] });
      void qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });
  const clear = useMutation({
    mutationFn: clearDemoData,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['demo-status'] });
      void qc.invalidateQueries({ queryKey: ['violations'] });
      void qc.invalidateQueries({ queryKey: ['stats'] });
    },
  });

  const enabled = status.data?.demo_mode_enabled ?? false;
  const rowCount = status.data?.demo_audit_rows ?? 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-accent-bright" />
          Demo / sample data
          {enabled && <Badge variant="accent">Active</Badge>}
        </CardTitle>
        <CardDescription>
          Populates this tenant with 2,000 audit rows, 15 demo users across 4 departments,
          and 20 escalations — purpose-built for sales demos. Demo audit rows are tagged
          <code className="mx-1 rounded bg-translucent-1 px-1 font-mono text-micro">DEMO-1.0</code>
          and excluded from the tamper-evident chain.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {status.isLoading ? (
          <p className="text-small text-fg-muted">Loading…</p>
        ) : (
          <table className="w-full mb-4">
            <tbody>
              <Row label="Demo mode">
                <Badge variant={enabled ? 'success' : 'subtle'}>
                  {enabled ? 'Enabled' : 'Disabled'}
                </Badge>
              </Row>
              <Row label="Demo audit rows">
                <span className="font-mono text-fg-primary">{rowCount.toLocaleString()}</span>
              </Row>
            </tbody>
          </table>
        )}
        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            onClick={() => seed.mutate()}
            disabled={seed.isPending}
          >
            <Sparkles className="h-3.5 w-3.5" />
            {seed.isPending ? 'Seeding…' : enabled ? 'Re-seed demo data' : 'Seed demo data'}
          </Button>
          {enabled && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => clear.mutate()}
              disabled={clear.isPending}
            >
              <Eraser className="h-3.5 w-3.5" />
              {clear.isPending ? 'Clearing…' : 'Clear demo data'}
            </Button>
          )}
        </div>
        {seed.isSuccess && (
          <p className="mt-3 text-small text-status-success">
            Seeded {seed.data.seeded.audit_rows} audit rows, {seed.data.seeded.users} users,{' '}
            {seed.data.seeded.escalations} escalations.
          </p>
        )}
        {clear.isSuccess && (
          <p className="mt-3 text-small text-fg-secondary">
            Cleared {clear.data.cleared.audit_rows} audit rows, {clear.data.cleared.users} users,{' '}
            {clear.data.cleared.escalations} escalations.
          </p>
        )}
        {(seed.isError || clear.isError) && (
          <p className="mt-3 text-small text-status-danger">
            {((seed.error ?? clear.error) as Error).message}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

const PROVIDER_KIND_OPTIONS: { value: ProviderKind; label: string; helper: string }[] = [
  { value: 'slack', label: 'Slack', helper: 'Posts to a Slack incoming webhook URL.' },
  { value: 'pagerduty', label: 'PagerDuty', helper: 'Triggers via Events API v2 (routing key).' },
  { value: 'webhook', label: 'Webhook', helper: 'POSTs HMAC-SHA256-signed JSON to your URL.' },
  { value: 'email', label: 'Email (SMTP)', helper: 'Sends via your SMTP relay.' },
  { value: 'splunk_hec', label: 'Splunk HEC', helper: 'Streams events to Splunk HTTP Event Collector.' },
];

const TRIGGER_OPTIONS: { value: TriggerEvent; label: string }[] = [
  { value: 'violation', label: 'Policy violation' },
  { value: 'escalation', label: 'Escalation' },
  { value: 'audit_chain_break', label: 'Audit chain break' },
  { value: 'rate_limit_breach', label: 'Rate-limit breach' },
];

const SEVERITY_OPTIONS: { value: Severity; label: string }[] = [
  { value: 'info', label: 'Info' },
  { value: 'warning', label: 'Warning' },
  { value: 'critical', label: 'Critical' },
];

function configFieldsFor(kind: ProviderKind): { key: string; label: string; placeholder: string; type?: string }[] {
  switch (kind) {
    case 'slack':
      return [{ key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/…' }];
    case 'pagerduty':
      return [{ key: 'routing_key', label: 'Integration / routing key', placeholder: 'a1b2c3d4…', type: 'password' }];
    case 'webhook':
      return [
        { key: 'url', label: 'URL', placeholder: 'https://example.com/agcms-webhook' },
        { key: 'signing_secret', label: 'Signing secret', placeholder: 'shared HMAC secret', type: 'password' },
      ];
    case 'email':
      return [
        { key: 'host', label: 'SMTP host', placeholder: 'smtp.sendgrid.net' },
        { key: 'port', label: 'Port', placeholder: '587' },
        { key: 'username', label: 'Username', placeholder: 'apikey' },
        { key: 'password', label: 'Password', placeholder: '••••', type: 'password' },
        { key: 'from_addr', label: 'From address', placeholder: 'alerts@yourcorp.com' },
        { key: 'to_addr', label: 'To address', placeholder: 'compliance@yourcorp.com' },
      ];
    case 'splunk_hec':
      return [
        { key: 'url', label: 'HEC URL', placeholder: 'https://splunk:8088/services/collector' },
        { key: 'token', label: 'HEC token', placeholder: 'a1b2…', type: 'password' },
      ];
  }
}

function NewProviderForm({ onCreated }: { onCreated: (p: NotificationProvider) => void }) {
  const [kind, setKind] = useState<ProviderKind>('slack');
  const [name, setName] = useState('');
  const [config, setConfig] = useState<Record<string, string>>({});
  const create = useMutation({
    mutationFn: () =>
      createNotificationProvider({
        kind,
        name,
        config: Object.fromEntries(
          Object.entries(config).filter(([, v]) => v.trim().length > 0),
        ),
      }),
    onSuccess: (p) => {
      onCreated(p);
      setName('');
      setConfig({});
    },
  });
  const fields = configFieldsFor(kind);
  const helper = PROVIDER_KIND_OPTIONS.find((o) => o.value === kind)?.helper;

  return (
    <div className="rounded-md border border-translucent-2 bg-translucent-1 p-4 mb-4">
      <h4 className="text-small font-semibold text-fg-primary mb-3">Add provider</h4>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
        <label className="block text-micro text-fg-muted">
          Kind
          <select
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as ProviderKind);
              setConfig({});
            }}
            className="mt-1 w-full rounded-md border border-translucent-3 bg-bg-primary px-2 py-1.5 text-small text-fg-primary"
          >
            {PROVIDER_KIND_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </label>
        <label className="block text-micro text-fg-muted">
          Display name
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. #compliance-alerts"
            className="mt-1"
          />
        </label>
      </div>
      {helper && <p className="text-micro text-fg-muted mb-3">{helper}</p>}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {fields.map((f) => (
          <label key={f.key} className="block text-micro text-fg-muted">
            {f.label}
            <Input
              type={f.type ?? 'text'}
              value={config[f.key] ?? ''}
              onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })}
              placeholder={f.placeholder}
              className="mt-1"
            />
          </label>
        ))}
      </div>
      <div className="mt-4 flex items-center gap-3">
        <Button
          variant="primary"
          size="sm"
          onClick={() => create.mutate()}
          disabled={create.isPending || !name.trim()}
        >
          <Plus className="h-3.5 w-3.5" />
          {create.isPending ? 'Creating…' : 'Create provider'}
        </Button>
        {create.isError && (
          <span className="text-micro text-status-danger">
            {(create.error as Error).message}
          </span>
        )}
      </div>
    </div>
  );
}

function NewRuleForm({
  providers,
  onCreated,
}: {
  providers: NotificationProvider[];
  onCreated: () => void;
}) {
  const [providerId, setProviderId] = useState('');
  const [trigger, setTrigger] = useState<TriggerEvent>('violation');
  const [severity, setSeverity] = useState<Severity>('warning');
  useEffect(() => {
    if (!providerId && providers.length > 0) setProviderId(providers[0].id);
  }, [providers, providerId]);
  const create = useMutation({
    mutationFn: () =>
      createNotificationRule({
        provider_id: providerId,
        trigger_event: trigger,
        severity_min: severity,
      }),
    onSuccess: () => onCreated(),
  });

  if (providers.length === 0) {
    return (
      <p className="text-small text-fg-muted italic mb-4">
        Add a provider above before creating routing rules.
      </p>
    );
  }

  return (
    <div className="rounded-md border border-translucent-2 bg-translucent-1 p-4 mb-4">
      <h4 className="text-small font-semibold text-fg-primary mb-3">Add routing rule</h4>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <label className="block text-micro text-fg-muted">
          Provider
          <select
            value={providerId}
            onChange={(e) => setProviderId(e.target.value)}
            className="mt-1 w-full rounded-md border border-translucent-3 bg-bg-primary px-2 py-1.5 text-small text-fg-primary"
          >
            {providers.map((p) => (
              <option key={p.id} value={p.id}>{p.kind} — {p.name}</option>
            ))}
          </select>
        </label>
        <label className="block text-micro text-fg-muted">
          Trigger event
          <select
            value={trigger}
            onChange={(e) => setTrigger(e.target.value as TriggerEvent)}
            className="mt-1 w-full rounded-md border border-translucent-3 bg-bg-primary px-2 py-1.5 text-small text-fg-primary"
          >
            {TRIGGER_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </label>
        <label className="block text-micro text-fg-muted">
          Minimum severity
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity)}
            className="mt-1 w-full rounded-md border border-translucent-3 bg-bg-primary px-2 py-1.5 text-small text-fg-primary"
          >
            {SEVERITY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="mt-4 flex items-center gap-3">
        <Button
          variant="primary"
          size="sm"
          onClick={() => create.mutate()}
          disabled={create.isPending || !providerId}
        >
          <Plus className="h-3.5 w-3.5" />
          {create.isPending ? 'Creating…' : 'Create rule'}
        </Button>
        {create.isError && (
          <span className="text-micro text-status-danger">
            {(create.error as Error).message}
          </span>
        )}
      </div>
    </div>
  );
}

function IntegrationsCard() {
  const qc = useQueryClient();
  const providers = useQuery({
    queryKey: ['notification-providers'],
    queryFn: fetchNotificationProviders,
  });
  const rules = useQuery({
    queryKey: ['notification-rules'],
    queryFn: fetchNotificationRules,
  });
  const deliveries = useQuery({
    queryKey: ['notification-deliveries'],
    queryFn: () => fetchNotificationDeliveries(20),
  });

  const removeProvider = useMutation({
    mutationFn: deleteNotificationProvider,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['notification-providers'] });
      void qc.invalidateQueries({ queryKey: ['notification-rules'] });
    },
  });
  const removeRule = useMutation({
    mutationFn: deleteNotificationRule,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['notification-rules'] }),
  });
  const testProvider = useMutation({
    mutationFn: testNotificationProvider,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['notification-deliveries'] }),
  });

  const providerList = providers.data?.providers ?? [];
  const ruleList = rules.data?.rules ?? [];
  const deliveryList = deliveries.data?.deliveries ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Bell className="h-4 w-4 text-accent-bright" />
          Integrations &amp; notifications
        </CardTitle>
        <CardDescription>
          Route violations, escalations, and audit-chain breaks to Slack, PagerDuty, your
          on-call webhook, SMTP, or Splunk HEC. Webhooks are signed with HMAC-SHA256 —
          receivers verify by recomputing over the raw body and comparing the
          <code className="mx-1 rounded bg-translucent-1 px-1 font-mono text-micro">X-AGCMS-Signature</code>
          header.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <NewProviderForm
          onCreated={() => qc.invalidateQueries({ queryKey: ['notification-providers'] })}
        />

        <h4 className="text-small font-semibold text-fg-primary mb-2">Providers</h4>
        {providers.isLoading ? (
          <p className="text-small text-fg-muted">Loading…</p>
        ) : providerList.length === 0 ? (
          <p className="text-small text-fg-muted italic mb-4">
            No providers configured yet. Add one above.
          </p>
        ) : (
          <table className="w-full mb-6 text-small">
            <thead>
              <tr className="text-left text-micro uppercase tracking-wide text-fg-muted">
                <th className="py-2">Kind</th>
                <th className="py-2">Name</th>
                <th className="py-2">Status</th>
                <th className="py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {providerList.map((p) => (
                <tr key={p.id} className="border-t border-translucent-2">
                  <td className="py-2"><Badge variant="subtle">{p.kind}</Badge></td>
                  <td className="py-2 text-fg-primary">{p.name}</td>
                  <td className="py-2">
                    <Badge variant={p.enabled ? 'success' : 'subtle'}>
                      {p.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </td>
                  <td className="py-2 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => testProvider.mutate(p.id)}
                      disabled={testProvider.isPending}
                    >
                      <Send className="h-3.5 w-3.5" />
                      Send test
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => removeProvider.mutate(p.id)}
                      disabled={removeProvider.isPending}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      Remove
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {testProvider.isError && (
          <p className="mb-3 text-micro text-status-danger">
            Test send failed: {(testProvider.error as Error).message}
          </p>
        )}
        {testProvider.isSuccess && (
          <p className="mb-3 text-micro text-status-success">
            Test sent — check the deliveries log below.
          </p>
        )}

        <NewRuleForm
          providers={providerList}
          onCreated={() => qc.invalidateQueries({ queryKey: ['notification-rules'] })}
        />

        <h4 className="text-small font-semibold text-fg-primary mb-2">Routing rules</h4>
        {rules.isLoading ? (
          <p className="text-small text-fg-muted">Loading…</p>
        ) : ruleList.length === 0 ? (
          <p className="text-small text-fg-muted italic mb-6">
            No routing rules yet. Without a rule, no events will be dispatched.
          </p>
        ) : (
          <table className="w-full mb-6 text-small">
            <thead>
              <tr className="text-left text-micro uppercase tracking-wide text-fg-muted">
                <th className="py-2">Provider</th>
                <th className="py-2">Trigger</th>
                <th className="py-2">Min severity</th>
                <th className="py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {ruleList.map((r) => {
                const provider = providerList.find((p) => p.id === r.provider_id);
                return (
                  <tr key={r.id} className="border-t border-translucent-2">
                    <td className="py-2 text-fg-primary">
                      {provider ? `${provider.kind} — ${provider.name}` : r.provider_id}
                    </td>
                    <td className="py-2">{r.trigger_event}</td>
                    <td className="py-2">
                      <Badge
                        variant={
                          r.severity_min === 'critical'
                            ? 'danger'
                            : r.severity_min === 'warning'
                              ? 'warning'
                              : 'subtle'
                        }
                      >
                        {r.severity_min}
                      </Badge>
                    </td>
                    <td className="py-2 text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeRule.mutate(r.id)}
                        disabled={removeRule.isPending}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Remove
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        <h4 className="text-small font-semibold text-fg-primary mb-2">Recent deliveries</h4>
        {deliveries.isLoading ? (
          <p className="text-small text-fg-muted">Loading…</p>
        ) : deliveryList.length === 0 ? (
          <p className="text-small text-fg-muted italic">
            No notifications dispatched yet.
          </p>
        ) : (
          <table className="w-full text-small">
            <thead>
              <tr className="text-left text-micro uppercase tracking-wide text-fg-muted">
                <th className="py-2">Time</th>
                <th className="py-2">Provider</th>
                <th className="py-2">Event</th>
                <th className="py-2">Severity</th>
                <th className="py-2">Status</th>
                <th className="py-2">Attempts</th>
              </tr>
            </thead>
            <tbody>
              {deliveryList.map((d) => (
                <tr key={d.id} className="border-t border-translucent-2">
                  <td className="py-2 text-fg-muted font-mono text-micro">
                    {new Date(d.created_at).toLocaleString()}
                  </td>
                  <td className="py-2"><Badge variant="subtle">{d.provider_kind}</Badge></td>
                  <td className="py-2">{d.trigger_event}</td>
                  <td className="py-2">
                    <Badge
                      variant={
                        d.severity === 'critical'
                          ? 'danger'
                          : d.severity === 'warning'
                            ? 'warning'
                            : 'subtle'
                      }
                    >
                      {d.severity}
                    </Badge>
                  </td>
                  <td className="py-2">
                    <Badge variant={d.status === 'sent' ? 'success' : 'danger'}>
                      {d.status}
                    </Badge>
                  </td>
                  <td className="py-2 font-mono text-micro">{d.attempts}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );
}

function ChangelogCard() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['changelog'],
    queryFn: fetchChangelog,
    staleTime: 60_000,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <History className="h-4 w-4 text-accent-bright" />
          Product changelog
        </CardTitle>
        <CardDescription>
          What's shipped recently. The same feed powers the public landing site.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <p className="text-small text-fg-muted">Loading…</p>
        ) : isError ? (
          <p className="text-small text-fg-muted italic">Changelog unavailable.</p>
        ) : !data || data.length === 0 ? (
          <p className="text-small text-fg-muted italic">No releases recorded yet.</p>
        ) : (
          <ol className="space-y-5">
            {data.slice(0, 5).map((entry: ChangelogEntry) => (
              <li key={entry.version} className="border-l-2 border-border-subtle pl-4">
                <header className="flex items-baseline gap-2 mb-2">
                  <span className="font-mono text-small text-fg-primary">v{entry.version}</span>
                  {entry.date && (
                    <Badge variant="subtle" className="text-micro">
                      {entry.date}
                    </Badge>
                  )}
                </header>
                <div className="space-y-3">
                  {entry.sections.map((section) => (
                    <div key={section.label}>
                      <div className="text-micro uppercase tracking-wider text-fg-subtle mb-1">
                        {section.label}
                      </div>
                      <ul className="list-disc pl-5 space-y-0.5 text-small text-fg-secondary">
                        {section.items.map((item, i) => (
                          <li key={i}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}

const SERVICE_ENDPOINTS: [string, string][] = [
  ['Gateway', 'http://localhost:8000'],
  ['PII Service', 'http://localhost:8001'],
  ['Injection Service', 'http://localhost:8002'],
  ['Response Compliance', 'http://localhost:8003'],
  ['Policy Service', 'http://localhost:8004'],
  ['Audit Service', 'http://localhost:8005'],
  ['Auth Service', 'http://localhost:8006'],
  ['Tenant Service', 'http://localhost:8007'],
];

export function Settings() {
  const token = useAuthStore((s) => s.token);

  const usage = useQuery({
    queryKey: ['tenant-usage'],
    queryFn: fetchTenantUsage,
  });

  const policy = useQuery({
    queryKey: ['policy'],
    queryFn: fetchPolicy,
    refetchInterval: 60_000,
  });

  const rateLimits = policy.data?.config?.rate_limits as
    | { requests_per_minute?: number; requests_per_day?: number }
    | undefined;

  const usageData = usage.data;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary">Settings</h1>
        <p className="mt-1 text-small text-fg-muted">
          System configuration and tenant quota — read-only.
        </p>
      </header>

      {/* Usage tiles */}
      {usageData && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Requests today"
            value={usageData.requests_today.toLocaleString()}
            variant="accent"
            icon={<Activity className="h-4 w-4" />}
          />
          <StatCard
            title="Requests this month"
            value={usageData.requests_this_month.toLocaleString()}
            variant="default"
          />
          <StatCard
            title="Blocked today"
            value={usageData.blocked_today.toLocaleString()}
            variant="danger"
          />
          <StatCard
            title="Detections today"
            value={(usageData.pii_detections_today + usageData.injection_detections_today).toLocaleString()}
            subtitle={`${usageData.pii_detections_today} PII · ${usageData.injection_detections_today} injection`}
            variant="warning"
          />
        </div>
      )}

      {/* Authentication + Rate limits */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-4 w-4 text-accent-bright" />
              Authentication
            </CardTitle>
            <CardDescription>Active session and method.</CardDescription>
          </CardHeader>
          <CardContent>
            <table className="w-full">
              <tbody>
                <Row label="Active token">
                  <MaskedValue value={token} />
                </Row>
                <Row label="Auth method">
                  <Badge variant="info">
                    {token.startsWith('agcms_') ? 'API Key (dev fast-path)' : 'JWT Bearer'}
                  </Badge>
                </Row>
                <Row label="Role">
                  <Badge variant="accent">admin</Badge>
                </Row>
              </tbody>
            </table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Gauge className="h-4 w-4 text-accent-bright" />
              Rate limits
            </CardTitle>
            <CardDescription>Sourced from the active policy.</CardDescription>
          </CardHeader>
          <CardContent>
            {policy.isLoading ? (
              <p className="text-small text-fg-muted">Loading…</p>
            ) : (
              <table className="w-full">
                <tbody>
                  <Row label="Requests / minute">
                    <span className="font-mono text-fg-primary">
                      {rateLimits?.requests_per_minute ?? '—'}
                    </span>
                  </Row>
                  <Row label="Requests / day">
                    <span className="font-mono text-fg-primary">
                      {rateLimits?.requests_per_day?.toLocaleString() ?? '—'}
                    </span>
                  </Row>
                  <Row label="Policy version">
                    <Badge variant="subtle">v{policy.data?.version ?? '—'}</Badge>
                  </Row>
                  <Row label="Last updated">
                    <span className="font-mono text-fg-secondary">
                      {policy.data?.created_at
                        ? new Date(policy.data.created_at).toLocaleString()
                        : '—'}
                    </span>
                  </Row>
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Single Sign-On */}
      <SSOCard />

      {/* Multi-Factor Authentication */}
      <MFACard />

      {/* Active sessions */}
      <SessionsCard />

      {/* GDPR Article 17 — right to erasure */}
      <GDPRCard />

      {/* Demo / sample data — Settings → Advanced */}
      <DemoCard />

      {/* Integrations & notifications — Phase 7.5 */}
      <IntegrationsCard />

      {/* Product changelog — Phase 8.6 */}
      <ChangelogCard />

      {/* Tenant usage detail */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-accent-bright" />
            Tenant usage
          </CardTitle>
          <CardDescription>Real-time counters from the tenant service.</CardDescription>
        </CardHeader>
        <CardContent>
          {usage.isLoading ? (
            <p className="text-small text-fg-muted">Loading…</p>
          ) : usage.isError ? (
            <p className="text-small text-fg-muted italic">
              Tenant service unavailable — quota data not accessible.
            </p>
          ) : usageData ? (
            <table className="w-full">
              <tbody>
                <Row label="Tenant ID">
                  <span className="font-mono text-fg-primary">{usageData.tenant_id}</span>
                </Row>
                <Row label="Requests today">
                  <span className="font-mono">{usageData.requests_today.toLocaleString()}</span>
                </Row>
                <Row label="Requests this month">
                  <span className="font-mono">{usageData.requests_this_month.toLocaleString()}</span>
                </Row>
                <Row label="Blocked today">
                  <span className="font-mono text-status-danger">
                    {usageData.blocked_today.toLocaleString()}
                  </span>
                </Row>
                <Row label="PII detections today">
                  <span className="font-mono text-status-warning">
                    {usageData.pii_detections_today.toLocaleString()}
                  </span>
                </Row>
                <Row label="Injection detections today">
                  <span className="font-mono text-status-warning">
                    {usageData.injection_detections_today.toLocaleString()}
                  </span>
                </Row>
              </tbody>
            </table>
          ) : null}
        </CardContent>
      </Card>

      {/* Service endpoints */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-4 w-4 text-accent-bright" />
            Service endpoints
          </CardTitle>
          <CardDescription>Internal services backing the gateway.</CardDescription>
        </CardHeader>
        <CardContent>
          <table className="w-full">
            <tbody>
              {SERVICE_ENDPOINTS.map(([name, url]) => (
                <Row key={name} label={name}>
                  <span className="font-mono text-fg-secondary">{url}</span>
                </Row>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
