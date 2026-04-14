import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchPolicy, updatePolicy, fetchPolicyVersions, type PolicyConfig } from '../lib/api';

export function Policy() {
  const qc = useQueryClient();
  const [editJson, setEditJson] = useState<string | null>(null);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [deployNotes, setDeployNotes] = useState('');
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const policy = useQuery({
    queryKey: ['policy'],
    queryFn: fetchPolicy,
    refetchInterval: 30_000,
  });

  const versions = useQuery({
    queryKey: ['policy-versions'],
    queryFn: fetchPolicyVersions,
  });

  const deploy = useMutation({
    mutationFn: ({ config, notes }: { config: PolicyConfig; notes: string }) =>
      updatePolicy(config, notes || undefined),
    onSuccess: (data) => {
      void qc.invalidateQueries({ queryKey: ['policy'] });
      void qc.invalidateQueries({ queryKey: ['policy-versions'] });
      setEditJson(null);
      setDeployNotes('');
      setJsonError(null);
      setSuccessMsg(`Policy v${data.version} deployed successfully`);
      setTimeout(() => setSuccessMsg(null), 4000);
    },
    onError: (err) => {
      setJsonError(String(err));
    },
  });

  function startEdit() {
    if (policy.data) {
      setEditJson(JSON.stringify(policy.data.config, null, 2));
      setJsonError(null);
    }
  }

  function handleDeploy() {
    if (!editJson) return;
    let parsed: PolicyConfig;
    try {
      parsed = JSON.parse(editJson) as PolicyConfig;
    } catch (e) {
      setJsonError(`JSON parse error: ${String(e)}`);
      return;
    }
    deploy.mutate({ config: parsed, notes: deployNotes });
  }

  const active = policy.data;

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Policy Manager</h1>
        <p className="text-sm text-gray-500 mt-1">View and deploy tenant governance policies</p>
      </div>

      {successMsg && (
        <div className="mb-4 px-4 py-3 bg-green-50 border border-green-200 rounded-lg text-green-700 text-sm">
          {successMsg}
        </div>
      )}

      {/* Active policy panel */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-8">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Active Policy</h2>
            {active && (
              <p className="text-xs text-gray-400 mt-0.5">
                v{active.version} — deployed {new Date(active.created_at).toLocaleString()}
                {active.notes && <span className="ml-2 italic">"{active.notes}"</span>}
              </p>
            )}
          </div>
          {active && !editJson && (
            <button
              onClick={startEdit}
              className="px-3 py-1.5 bg-indigo-600 text-white text-sm rounded-md hover:bg-indigo-700"
            >
              Edit &amp; Deploy
            </button>
          )}
        </div>

        {policy.isLoading ? (
          <div className="text-gray-400 text-sm">Loading…</div>
        ) : policy.isError ? (
          <div className="text-red-500 text-sm">Error: {String(policy.error)}</div>
        ) : editJson !== null ? (
          <div>
            <textarea
              value={editJson}
              onChange={(e) => {
                setEditJson(e.target.value);
                setJsonError(null);
              }}
              rows={20}
              className="w-full font-mono text-xs border border-gray-300 rounded-md p-3 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            {jsonError && (
              <p className="mt-1 text-red-500 text-xs">{jsonError}</p>
            )}
            <div className="mt-3 flex items-center gap-3">
              <input
                type="text"
                placeholder="Deploy notes (optional)"
                value={deployNotes}
                onChange={(e) => setDeployNotes(e.target.value)}
                className="flex-1 border border-gray-300 rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
              <button
                onClick={handleDeploy}
                disabled={deploy.isPending}
                className="px-4 py-1.5 bg-indigo-600 text-white text-sm rounded-md hover:bg-indigo-700 disabled:opacity-50"
              >
                {deploy.isPending ? 'Deploying…' : 'Deploy'}
              </button>
              <button
                onClick={() => { setEditJson(null); setJsonError(null); }}
                className="px-4 py-1.5 bg-gray-100 text-gray-700 text-sm rounded-md hover:bg-gray-200"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <pre className="bg-gray-50 rounded-md p-4 text-xs font-mono text-gray-700 overflow-auto max-h-96">
            {JSON.stringify(active?.config ?? {}, null, 2)}
          </pre>
        )}
      </div>

      {/* Version history */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">Version History</h2>
        </div>
        {versions.isLoading ? (
          <div className="px-6 py-8 text-center text-gray-400 text-sm">Loading…</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-6 py-3">Version</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3">Notes</th>
                  <th className="px-6 py-3">Deployed</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {(versions.data?.versions ?? []).map((v) => (
                  <tr key={v.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 font-mono text-gray-800">v{v.version}</td>
                    <td className="px-6 py-3">
                      {v.is_active ? (
                        <span className="px-2 py-0.5 bg-green-100 text-green-700 text-xs rounded-full">
                          Active
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 bg-gray-100 text-gray-400 text-xs rounded-full">
                          Archived
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-3 text-gray-500 italic text-xs">
                      {v.notes ?? '—'}
                    </td>
                    <td className="px-6 py-3 text-gray-400 text-xs">
                      {new Date(v.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(versions.data?.versions ?? []).length === 0 && (
              <p className="px-6 py-8 text-center text-gray-400 text-sm">No versions found.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
