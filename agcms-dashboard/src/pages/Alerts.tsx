import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchEscalations, updateEscalation, type Escalation } from '../lib/api';

const STATUS_OPTIONS = ['PENDING', 'REVIEWED', 'DISMISSED', 'ACTIONED'] as const;
type EscStatus = typeof STATUS_OPTIONS[number];

function statusBadge(status: string) {
  const cls: Record<string, string> = {
    PENDING: 'bg-orange-100 text-orange-700',
    REVIEWED: 'bg-blue-100 text-blue-700',
    DISMISSED: 'bg-gray-100 text-gray-500',
    ACTIONED: 'bg-green-100 text-green-700',
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${cls[status] ?? 'bg-gray-100 text-gray-600'}`}>
      {status}
    </span>
  );
}

export function Alerts() {
  const qc = useQueryClient();
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const [newStatus, setNewStatus] = useState<EscStatus>('REVIEWED');

  const all = useQuery({
    queryKey: ['escalations-all'],
    queryFn: () => fetchEscalations(),
    refetchInterval: 15_000,
  });

  const pending = useQuery({
    queryKey: ['escalations-pending'],
    queryFn: () => fetchEscalations('PENDING'),
    refetchInterval: 15_000,
  });

  const update = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      updateEscalation(id, status),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['escalations-all'] });
      void qc.invalidateQueries({ queryKey: ['escalations-pending'] });
      setUpdatingId(null);
    },
  });

  const pendingList = pending.data?.escalations ?? [];
  const allList = all.data?.escalations ?? [];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Alerts &amp; Escalations</h1>
        <p className="text-sm text-gray-500 mt-1">Review and resolve escalated governance events</p>
      </div>

      {/* Pending count */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
        <div className="bg-white rounded-lg border border-gray-200 p-5">
          <p className="text-xs text-gray-500 uppercase tracking-wider">Pending Review</p>
          <p className={`text-3xl font-bold mt-1 ${pendingList.length > 0 ? 'text-orange-500' : 'text-gray-700'}`}>
            {pending.isLoading ? '…' : pendingList.length}
          </p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-5">
          <p className="text-xs text-gray-500 uppercase tracking-wider">Total Escalations</p>
          <p className="text-3xl font-bold mt-1 text-gray-700">
            {all.isLoading ? '…' : allList.length}
          </p>
        </div>
        <div className="bg-white rounded-lg border border-gray-200 p-5">
          <p className="text-xs text-gray-500 uppercase tracking-wider">Resolved</p>
          <p className="text-3xl font-bold mt-1 text-gray-700">
            {all.isLoading
              ? '…'
              : allList.filter((e) => e.status !== 'PENDING').length}
          </p>
        </div>
      </div>

      {/* Pending escalations */}
      {pendingList.length > 0 && (
        <div className="bg-orange-50 border border-orange-200 rounded-lg mb-8">
          <div className="px-6 py-4 border-b border-orange-100">
            <h2 className="text-lg font-semibold text-orange-800">
              Pending Escalations ({pendingList.length})
            </h2>
          </div>
          <div className="divide-y divide-orange-100">
            {pendingList.map((esc) => (
              <div key={esc.id} className="px-6 py-4 flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">{esc.reason}</p>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {new Date(esc.created_at).toLocaleString()}
                    {esc.interaction_id && (
                      <span className="ml-2 font-mono">({esc.interaction_id.slice(0, 8)}…)</span>
                    )}
                  </p>
                </div>
                <div className="flex-shrink-0">
                  {updatingId === esc.id ? (
                    <div className="flex items-center gap-2">
                      <select
                        value={newStatus}
                        onChange={(e) => setNewStatus(e.target.value as EscStatus)}
                        className="border border-gray-300 rounded-md text-sm px-2 py-1 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                      >
                        {STATUS_OPTIONS.filter((s) => s !== 'PENDING').map((s) => (
                          <option key={s} value={s}>{s}</option>
                        ))}
                      </select>
                      <button
                        onClick={() => update.mutate({ id: esc.id, status: newStatus })}
                        disabled={update.isPending}
                        className="px-2 py-1 bg-indigo-600 text-white text-xs rounded-md hover:bg-indigo-700 disabled:opacity-50"
                      >
                        Save
                      </button>
                      <button
                        onClick={() => setUpdatingId(null)}
                        className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded-md hover:bg-gray-200"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => { setUpdatingId(esc.id); setNewStatus('REVIEWED'); }}
                      className="px-3 py-1.5 bg-white border border-orange-300 text-orange-700 text-sm rounded-md hover:bg-orange-50"
                    >
                      Update Status
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All escalations table */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">All Escalations</h2>
        </div>
        {all.isLoading ? (
          <div className="px-6 py-12 text-center text-gray-400 text-sm">Loading…</div>
        ) : all.isError ? (
          <div className="px-6 py-12 text-center text-red-500 text-sm">
            Error: {String(all.error)}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-6 py-3">ID</th>
                  <th className="px-6 py-3">Reason</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3">Reviewed</th>
                  <th className="px-6 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {allList.map((esc: Escalation) => (
                  <tr key={esc.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 font-mono text-xs text-gray-400">
                      {esc.id.slice(0, 8)}…
                    </td>
                    <td className="px-6 py-3 text-gray-700 max-w-xs truncate">{esc.reason}</td>
                    <td className="px-6 py-3">{statusBadge(esc.status)}</td>
                    <td className="px-6 py-3 text-xs text-gray-400">
                      {new Date(esc.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-3 text-xs text-gray-400">
                      {esc.reviewed_at ? new Date(esc.reviewed_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-6 py-3">
                      {esc.status === 'PENDING' && (
                        updatingId === esc.id ? (
                          <div className="flex items-center gap-2">
                            <select
                              value={newStatus}
                              onChange={(e) => setNewStatus(e.target.value as EscStatus)}
                              className="border border-gray-300 rounded text-xs px-1.5 py-1 focus:outline-none"
                            >
                              {STATUS_OPTIONS.filter((s) => s !== 'PENDING').map((s) => (
                                <option key={s} value={s}>{s}</option>
                              ))}
                            </select>
                            <button
                              onClick={() => update.mutate({ id: esc.id, status: newStatus })}
                              disabled={update.isPending}
                              className="text-xs text-indigo-600 hover:underline disabled:opacity-50"
                            >
                              Save
                            </button>
                            <button
                              onClick={() => setUpdatingId(null)}
                              className="text-xs text-gray-400 hover:underline"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => { setUpdatingId(esc.id); setNewStatus('REVIEWED'); }}
                            className="text-xs text-gray-400 hover:text-indigo-600"
                          >
                            Update
                          </button>
                        )
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {allList.length === 0 && (
              <p className="px-6 py-8 text-center text-gray-400 text-sm">No escalations found.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
