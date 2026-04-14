import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  fetchAuditLogs,
  exportAuditLogs,
  verifyAuditLog,
  type AuditLog,
} from '../lib/api';

const PAGE_SIZE = 25;

const ACTION_OPTIONS = ['', 'ALLOW', 'REDACT', 'BLOCK', 'ESCALATE'];

export function Audit() {
  const [offset, setOffset] = useState(0);
  const [actionFilter, setActionFilter] = useState('');
  const [startFilter, setStartFilter] = useState('');
  const [endFilter, setEndFilter] = useState('');
  const [verifyResults, setVerifyResults] = useState<Record<string, boolean | 'loading'>>({});

  const logs = useQuery({
    queryKey: ['audit-logs', offset, actionFilter, startFilter, endFilter],
    queryFn: () =>
      fetchAuditLogs({
        limit: PAGE_SIZE,
        offset,
        action: actionFilter || undefined,
        start: startFilter || undefined,
        end: endFilter || undefined,
      }),
    refetchInterval: 30_000,
  });

  const verify = useMutation({
    mutationFn: (id: string) => verifyAuditLog(id),
    onMutate: (id) => {
      setVerifyResults((r) => ({ ...r, [id]: 'loading' }));
    },
    onSuccess: (data) => {
      setVerifyResults((r) => ({ ...r, [data.interaction_id]: data.verified }));
    },
  });

  const total = logs.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  function resetFilters() {
    setOffset(0);
    setActionFilter('');
    setStartFilter('');
    setEndFilter('');
  }

  function actionBadge(action: string) {
    const cls: Record<string, string> = {
      ALLOW: 'bg-green-100 text-green-700',
      REDACT: 'bg-yellow-100 text-yellow-700',
      BLOCK: 'bg-red-100 text-red-700',
      ESCALATE: 'bg-orange-100 text-orange-700',
    };
    return (
      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls[action] ?? 'bg-gray-100 text-gray-600'}`}>
        {action}
      </span>
    );
  }

  function verifyBadge(id: string) {
    const result = verifyResults[id];
    if (result === undefined) return null;
    if (result === 'loading') return <span className="text-xs text-gray-400">Checking…</span>;
    return result ? (
      <span className="text-xs text-green-600 font-medium">✓ Verified</span>
    ) : (
      <span className="text-xs text-red-600 font-medium">✗ Tampered</span>
    );
  }

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Audit Explorer</h1>
        <p className="text-sm text-gray-500 mt-1">Browse and verify HMAC-signed audit logs</p>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6 flex flex-wrap gap-3 items-end">
        <div>
          <label className="block text-xs text-gray-500 mb-1">Action</label>
          <select
            value={actionFilter}
            onChange={(e) => { setActionFilter(e.target.value); setOffset(0); }}
            className="border border-gray-300 rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {ACTION_OPTIONS.map((a) => (
              <option key={a} value={a}>{a || 'All actions'}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">From</label>
          <input
            type="datetime-local"
            value={startFilter}
            onChange={(e) => { setStartFilter(e.target.value); setOffset(0); }}
            className="border border-gray-300 rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <div>
          <label className="block text-xs text-gray-500 mb-1">To</label>
          <input
            type="datetime-local"
            value={endFilter}
            onChange={(e) => { setEndFilter(e.target.value); setOffset(0); }}
            className="border border-gray-300 rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <button
          onClick={resetFilters}
          className="px-3 py-1.5 bg-gray-100 text-gray-600 text-sm rounded-md hover:bg-gray-200"
        >
          Reset
        </button>
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => void exportAuditLogs('json')}
            className="px-3 py-1.5 bg-indigo-50 text-indigo-700 text-sm rounded-md hover:bg-indigo-100"
          >
            Export JSON
          </button>
          <button
            onClick={() => void exportAuditLogs('csv')}
            className="px-3 py-1.5 bg-indigo-50 text-indigo-700 text-sm rounded-md hover:bg-indigo-100"
          >
            Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">
            Logs{' '}
            {!logs.isLoading && (
              <span className="text-sm text-gray-400 font-normal ml-1">
                ({total.toLocaleString()} total)
              </span>
            )}
          </h2>
          <span className="text-sm text-gray-400">
            Page {currentPage} of {totalPages}
          </span>
        </div>

        {logs.isLoading ? (
          <div className="px-6 py-12 text-center text-gray-400 text-sm">Loading…</div>
        ) : logs.isError ? (
          <div className="px-6 py-12 text-center text-red-500 text-sm">
            Error: {String(logs.error)}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-4 py-3">Interaction ID</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">User</th>
                  <th className="px-4 py-3">Dept</th>
                  <th className="px-4 py-3">PII</th>
                  <th className="px-4 py-3">Inj. Score</th>
                  <th className="px-4 py-3">Latency</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">HMAC</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {(logs.data?.logs ?? []).map((row: AuditLog) => (
                  <tr key={row.interaction_id} className="hover:bg-gray-50">
                    <td className="px-4 py-3 font-mono text-xs text-gray-500">
                      {row.interaction_id.slice(0, 8)}…
                    </td>
                    <td className="px-4 py-3">{actionBadge(row.enforcement_action)}</td>
                    <td className="px-4 py-3 text-xs text-gray-600">{row.user_id}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">{row.department ?? '—'}</td>
                    <td className="px-4 py-3">
                      {row.pii_detected ? (
                        <span className="text-xs text-yellow-600">
                          {row.pii_entity_types.join(', ') || 'Yes'}
                        </span>
                      ) : (
                        <span className="text-xs text-gray-300">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-600">
                      {row.injection_score != null ? row.injection_score.toFixed(2) : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {row.total_latency_ms != null ? `${row.total_latency_ms}ms` : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {new Date(row.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      {verifyBadge(row.interaction_id) ?? (
                        <button
                          onClick={() => verify.mutate(row.interaction_id)}
                          className="text-xs text-indigo-500 hover:underline"
                        >
                          Verify
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(logs.data?.logs ?? []).length === 0 && (
              <p className="px-6 py-8 text-center text-gray-400 text-sm">No audit logs found.</p>
            )}
          </div>
        )}

        {/* Pagination */}
        <div className="px-6 py-4 border-t border-gray-100 flex items-center justify-between">
          <button
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0}
            className="px-3 py-1.5 text-sm bg-gray-100 text-gray-600 rounded-md hover:bg-gray-200 disabled:opacity-40"
          >
            ← Prev
          </button>
          <span className="text-sm text-gray-500">
            Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <button
            onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={offset + PAGE_SIZE >= total}
            className="px-3 py-1.5 text-sm bg-gray-100 text-gray-600 rounded-md hover:bg-gray-200 disabled:opacity-40"
          >
            Next →
          </button>
        </div>
      </div>
    </div>
  );
}
