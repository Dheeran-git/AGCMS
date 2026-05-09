import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  Lock,
  KeyRound,
  Server,
  ScrollText,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Database,
  GitBranch,
  ClipboardList,
  Eye,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { TrustChain } from '../components/TrustChain';
import { fetchEscalations, type Escalation } from '../lib/api';

// Static demo blocks — illustrative only; the live chain lives on /audit.
const DEMO_TRUST_BLOCKS = [
  { label: '#04827', caption: 'a8f3…2b1', verified: true },
  { label: '#04828', caption: 'd6e1…0a4', verified: true },
  { label: '#04829', caption: '8b3a…4f7', verified: true },
  { label: '#04830', caption: '9e2d…1b6', verified: true },
  { label: '#04831', caption: 'pending', verified: false },
];

interface PostureItem {
  label: string;
  status: 'live' | 'observed' | 'planned';
  detail: string;
  icon: typeof ShieldCheck;
}

const SECURITY_POSTURE: PostureItem[] = [
  {
    label: 'SOC 2 Type II',
    status: 'observed',
    detail: 'Observation period in progress (auditor: Vanta). Type II report targeted Q3.',
    icon: ShieldCheck,
  },
  {
    label: 'Penetration test',
    status: 'planned',
    detail: 'Engagement scheduled with Cure53 prior to first paying customer (week 14).',
    icon: AlertTriangle,
  },
  {
    label: 'Encryption at rest',
    status: 'live',
    detail: 'Per-tenant DEK envelope-encrypted via KMS. PII columns + signing keys at rest.',
    icon: Lock,
  },
  {
    label: 'Encryption in transit',
    status: 'live',
    detail: 'TLS 1.3 enforced on all ingress. Cert-manager + Let’s Encrypt rotation.',
    icon: Lock,
  },
  {
    label: 'SSO (SAML / OIDC)',
    status: 'live',
    detail: 'Via WorkOS — Okta, Azure AD, Google Workspace, Ping, OneLogin, JumpCloud (40+).',
    icon: KeyRound,
  },
  {
    label: 'MFA enforcement',
    status: 'live',
    detail: 'TOTP required for admin + compliance roles by tenant policy.',
    icon: KeyRound,
  },
  {
    label: 'Audit chain integrity',
    status: 'live',
    detail: 'Per-tenant hash chain + nightly Merkle root anchored to S3 Object Lock.',
    icon: GitBranch,
  },
  {
    label: 'Key rotation',
    status: 'live',
    detail: 'Row + anchor signing keys versioned by KID; historical rows verify across rotations.',
    icon: KeyRound,
  },
];

const SUBPROCESSORS: { name: string; purpose: string; region: string }[] = [
  { name: 'Amazon Web Services', purpose: 'Compute, storage, KMS, S3 Object Lock', region: 'US-East / EU-West' },
  { name: 'WorkOS', purpose: 'Single Sign-On (SAML / OIDC)', region: 'US' },
  { name: 'Stripe', purpose: 'Subscription billing', region: 'US' },
  { name: 'Vanta', purpose: 'SOC 2 continuous monitoring', region: 'US' },
  { name: 'Better Stack', purpose: 'Public status page + uptime monitoring', region: 'EU' },
  { name: 'Anthropic / OpenAI / Groq', purpose: 'Outbound LLM providers (configurable per tenant)', region: 'US' },
];

function statusVariant(s: PostureItem['status']) {
  if (s === 'live') return 'success' as const;
  if (s === 'observed') return 'info' as const;
  return 'subtle' as const;
}

function statusLabel(s: PostureItem['status']) {
  if (s === 'live') return 'In production';
  if (s === 'observed') return 'In audit';
  return 'Planned';
}

function recentIncidents(escalations: Escalation[]): Escalation[] {
  // Surface critical-severity escalations from the last 30 days as a public-ish
  // incident history (still tenant-scoped — this card lives behind login).
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  return escalations
    .filter((e) => e.severity === 'critical' && new Date(e.created_at).getTime() > cutoff)
    .slice(0, 5);
}

export function TrustCenter() {
  const escalations = useQuery({
    queryKey: ['escalations-all'],
    queryFn: () => fetchEscalations(),
  });

  const incidents = recentIncidents(escalations.data?.escalations ?? []);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-accent-bright" />
          Trust Center
        </h1>
        <p className="mt-1 text-small text-fg-muted">
          Security posture, data handling, subprocessors, and audit-trail integrity —
          everything an auditor or buyer asks before approving deployment.
        </p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-accent-bright" />
              Security posture
            </CardTitle>
            <CardDescription>
              Current state of compliance controls and certifications.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y divide-border-subtle">
              {SECURITY_POSTURE.map((item) => {
                const Icon = item.icon;
                return (
                  <li key={item.label} className="py-3 flex items-start gap-3">
                    <Icon className="h-4 w-4 text-fg-muted mt-0.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-caption text-fg-primary font-medium">{item.label}</span>
                        <Badge variant={statusVariant(item.status)}>{statusLabel(item.status)}</Badge>
                      </div>
                      <p className="mt-1 text-label text-fg-muted">{item.detail}</p>
                    </div>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-accent-bright" />
              Audit-trail integrity
            </CardTitle>
            <CardDescription>
              How AGCMS proves that audit logs cannot be silently tampered with.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-small text-fg-secondary">
            <TrustChain blocks={DEMO_TRUST_BLOCKS} className="!p-4 !border-border-subtle" />
            <p>
              Every audit row is signed with HMAC-SHA256 and includes the previous row's
              signature, forming a per-tenant hash chain. Truncation, reordering, or
              substitution all break the chain.
            </p>
            <p>
              A nightly Merkle root over each tenant's day's signatures is signed with a
              dedicated anchor key and persisted to{' '}
              <code className="rounded bg-translucent-1 px-1 font-mono text-micro">
                s3://agcms-anchors/&lt;tenant&gt;/&lt;date&gt;.json
              </code>{' '}
              under S3 Object Lock (Compliance mode, 7-year retention by default).
            </p>
            <p>
              Bundles can be exported on demand — the bundle ZIP contains{' '}
              <code className="rounded bg-translucent-1 px-1 font-mono text-micro">verify.py</code>,
              a self-contained verifier (no AGCMS dependencies). Auditors run it on a
              clean machine; no AGCMS credentials required.
            </p>
            <div className="flex flex-wrap gap-3 pt-2">
              <Button asChild size="sm" variant="primary">
                <Link to="/audit">
                  <ScrollText className="h-3.5 w-3.5" />
                  View live chain
                </Link>
              </Button>
              <Button asChild size="sm" variant="outline">
                <Link to="/trust/verify">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Public verifier
                  <ExternalLink className="h-3 w-3 opacity-60" />
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-4 w-4 text-accent-bright" />
            Data handling
          </CardTitle>
          <CardDescription>
            Where data lives, how it's classified, and how it leaves AGCMS.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-small text-fg-secondary">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-md border border-translucent-2 bg-translucent-1 p-3">
              <h4 className="text-caption text-fg-primary font-semibold flex items-center gap-2">
                <Lock className="h-3.5 w-3.5" /> Data at rest
              </h4>
              <p className="mt-1 text-label text-fg-muted">
                PostgreSQL with row-level security per tenant. PII columns
                (raw prompt text, masked text, user email/name) envelope-encrypted with
                per-tenant DEKs wrapped by AWS KMS KEKs.
              </p>
            </div>
            <div className="rounded-md border border-translucent-2 bg-translucent-1 p-3">
              <h4 className="text-caption text-fg-primary font-semibold flex items-center gap-2">
                <Server className="h-3.5 w-3.5" /> Data in transit
              </h4>
              <p className="mt-1 text-label text-fg-muted">
                TLS 1.3 on all ingress. Internal mesh uses cert-manager-issued mTLS;
                outbound LLM calls verify the provider's certificate chain.
              </p>
            </div>
            <div className="rounded-md border border-translucent-2 bg-translucent-1 p-3">
              <h4 className="text-caption text-fg-primary font-semibold flex items-center gap-2">
                <Eye className="h-3.5 w-3.5" /> Access controls
              </h4>
              <p className="mt-1 text-label text-fg-muted">
                RBAC (admin / compliance / user). Scoped API keys.
                Per-session JWT with revocation. MFA enforced for privileged roles.
              </p>
            </div>
            <div className="rounded-md border border-translucent-2 bg-translucent-1 p-3">
              <h4 className="text-caption text-fg-primary font-semibold flex items-center gap-2">
                <ClipboardList className="h-3.5 w-3.5" /> Data subject rights
              </h4>
              <p className="mt-1 text-label text-fg-muted">
                GDPR Article 15 (access), 17 (erasure with two-admin approval), 30
                (record-of-processing report). All purges leave a tombstone in the
                audit chain so integrity is preserved.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-4 w-4 text-accent-bright" />
            Subprocessors
          </CardTitle>
          <CardDescription>
            Third-party services AGCMS uses to deliver the platform.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <table className="w-full text-small">
            <thead>
              <tr className="text-left text-micro uppercase tracking-wide text-fg-muted">
                <th className="py-2">Vendor</th>
                <th className="py-2">Purpose</th>
                <th className="py-2">Region</th>
              </tr>
            </thead>
            <tbody>
              {SUBPROCESSORS.map((s) => (
                <tr key={s.name} className="border-t border-translucent-2">
                  <td className="py-2 text-fg-primary font-medium">{s.name}</td>
                  <td className="py-2 text-fg-secondary">{s.purpose}</td>
                  <td className="py-2 text-fg-muted font-mono text-micro">{s.region}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-accent-bright" />
            Incident history (last 30 days)
          </CardTitle>
          <CardDescription>
            Critical-severity escalations from this tenant. Public uptime metrics live
            on the status page.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {escalations.isLoading ? (
            <p className="text-small text-fg-muted">Loading…</p>
          ) : incidents.length === 0 ? (
            <div className="text-center py-6 border border-dashed border-border-subtle rounded-md">
              <CheckCircle2 className="mx-auto h-6 w-6 text-status-success mb-2" strokeWidth={1.5} />
              <p className="text-caption text-fg-secondary">No critical incidents in the last 30 days.</p>
            </div>
          ) : (
            <ul className="divide-y divide-border-subtle">
              {incidents.map((i) => (
                <li key={i.id} className="py-3 flex items-start gap-3">
                  <Badge variant="danger">critical</Badge>
                  <div className="flex-1 min-w-0">
                    <p className="text-caption text-fg-primary truncate">{i.reason}</p>
                    <p className="text-label text-fg-muted mt-0.5 font-mono">
                      {new Date(i.created_at).toLocaleString()}
                      {i.resolved_at ? ' · resolved' : ' · open'}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
