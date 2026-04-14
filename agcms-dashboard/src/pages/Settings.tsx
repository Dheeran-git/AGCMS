import { useQuery } from '@tanstack/react-query';
import { fetchPolicy, fetchTenantUsage } from '../lib/api';
import { useAuthStore } from '../stores/auth';

function MaskedValue({ value, reveal = false }: { value: string; reveal?: boolean }) {
  if (!value) return <span className="text-gray-300">—</span>;
  if (reveal) return <span className="font-mono text-gray-700">{value}</span>;
  const masked = value.slice(0, 6) + '•'.repeat(Math.max(0, value.length - 10)) + value.slice(-4);
  return <span className="font-mono text-gray-700">{masked}</span>;
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <tr className="border-b border-gray-50 last:border-0">
      <td className="py-3 pr-6 text-sm text-gray-500 w-48">{label}</td>
      <td className="py-3 text-sm">{children}</td>
    </tr>
  );
}

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
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-sm text-gray-500 mt-1">
          System configuration and tenant quota — read-only
        </p>
      </div>

      {/* Auth */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Authentication</h2>
        <table className="w-full">
          <tbody>
            <Row label="Active Token">
              <MaskedValue value={token} />
            </Row>
            <Row label="Auth Method">
              <span className="px-2 py-0.5 bg-indigo-50 text-indigo-700 text-xs rounded-full">
                {token.startsWith('agcms_') ? 'API Key (dev fast-path)' : 'JWT Bearer'}
              </span>
            </Row>
            <Row label="Role">
              <span className="px-2 py-0.5 bg-purple-50 text-purple-700 text-xs rounded-full">
                admin
              </span>
            </Row>
          </tbody>
        </table>
      </div>

      {/* Tenant usage */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Tenant Quota</h2>
        {usage.isLoading ? (
          <p className="text-gray-400 text-sm">Loading…</p>
        ) : usage.isError ? (
          <p className="text-gray-400 text-sm italic">
            Tenant service unavailable — quota data not accessible.
          </p>
        ) : usageData ? (
          <div>
            <table className="w-full mb-4">
              <tbody>
                <Row label="Tenant ID">
                  <span className="font-mono text-gray-700">{usageData.tenant_id}</span>
                </Row>
                <Row label="Plan">
                  <span className="capitalize">{usageData.plan}</span>
                </Row>
                <Row label="Requests Used">
                  <span>{usageData.requests_used.toLocaleString()} / {usageData.quota.toLocaleString()}</span>
                </Row>
                <Row label="Reset Date">
                  <span>{usageData.reset_date ? new Date(usageData.reset_date).toLocaleDateString() : '—'}</span>
                </Row>
              </tbody>
            </table>
            {/* Usage bar */}
            <div className="mt-2">
              <div className="flex justify-between text-xs text-gray-500 mb-1">
                <span>Usage</span>
                <span>
                  {usageData.quota > 0
                    ? `${Math.round((usageData.requests_used / usageData.quota) * 100)}%`
                    : '—'}
                </span>
              </div>
              <div className="w-full bg-gray-100 rounded-full h-2">
                <div
                  className="bg-indigo-500 h-2 rounded-full"
                  style={{
                    width: `${Math.min(100, usageData.quota > 0 ? (usageData.requests_used / usageData.quota) * 100 : 0)}%`,
                  }}
                />
              </div>
            </div>
          </div>
        ) : null}
      </div>

      {/* Rate limits from active policy */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Rate Limits (Active Policy)</h2>
        {policy.isLoading ? (
          <p className="text-gray-400 text-sm">Loading…</p>
        ) : (
          <table className="w-full">
            <tbody>
              <Row label="Requests / minute">
                <span className="font-mono">{rateLimits?.requests_per_minute ?? '—'}</span>
              </Row>
              <Row label="Requests / day">
                <span className="font-mono">{rateLimits?.requests_per_day?.toLocaleString() ?? '—'}</span>
              </Row>
              <Row label="Policy version">
                <span className="font-mono">v{policy.data?.version ?? '—'}</span>
              </Row>
              <Row label="Last updated">
                <span>
                  {policy.data?.created_at
                    ? new Date(policy.data.created_at).toLocaleString()
                    : '—'}
                </span>
              </Row>
            </tbody>
          </table>
        )}
      </div>

      {/* Service endpoints */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-base font-semibold text-gray-900 mb-4">Service Endpoints</h2>
        <table className="w-full">
          <tbody>
            {[
              ['Gateway', 'http://localhost:8000'],
              ['PII Service', 'http://localhost:8001'],
              ['Injection Service', 'http://localhost:8002'],
              ['Response Compliance', 'http://localhost:8003'],
              ['Policy Service', 'http://localhost:8004'],
              ['Audit Service', 'http://localhost:8005'],
              ['Auth Service', 'http://localhost:8006'],
              ['Tenant Service', 'http://localhost:8007'],
            ].map(([name, url]) => (
              <Row key={name} label={name}>
                <span className="font-mono text-xs text-gray-600">{url}</span>
              </Row>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
