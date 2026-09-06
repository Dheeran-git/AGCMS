import { useQuery } from '@tanstack/react-query';
import { KeyRound, Activity, Gauge, Server } from 'lucide-react';
import { fetchPolicy, fetchTenantUsage } from '../lib/api';
import { useAuthStore } from '../stores/auth';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
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
