import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts';
import { fetchUsers, deleteUser, fetchStatsDepartments } from '../lib/api';

export function Users() {
  const qc = useQueryClient();
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const users = useQuery({
    queryKey: ['users'],
    queryFn: fetchUsers,
    refetchInterval: 30_000,
  });

  const departments = useQuery({
    queryKey: ['stats-departments'],
    queryFn: fetchStatsDepartments,
    refetchInterval: 60_000,
  });

  const softDelete = useMutation({
    mutationFn: (userId: string) => deleteUser(userId),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['users'] });
      setDeletingId(null);
    },
  });

  const activeUsers = users.data?.users.filter((u) => u.is_active) ?? [];
  const allUsers = users.data?.users ?? [];

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Users &amp; Departments</h1>
        <p className="text-sm text-gray-500 mt-1">Tenant user roster and department activity</p>
      </div>

      {/* Department bar chart */}
      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-8">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">
          Requests by Department (Last 7 days)
        </h2>
        {departments.isLoading ? (
          <div className="h-48 flex items-center justify-center text-gray-400 text-sm">Loading…</div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={departments.data?.departments ?? []}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="department" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip />
              <Bar dataKey="total" fill="#6366f1" name="Total" radius={[3, 3, 0, 0]} />
              <Bar dataKey="violations" fill="#f87171" name="Violations" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* User table */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">
            Users{' '}
            <span className="ml-2 px-2 py-0.5 bg-gray-100 text-gray-600 text-xs rounded-full">
              {activeUsers.length} active / {allUsers.length} total
            </span>
          </h2>
        </div>

        {users.isLoading ? (
          <div className="px-6 py-12 text-center text-gray-400 text-sm">Loading users…</div>
        ) : users.isError ? (
          <div className="px-6 py-12 text-center text-red-500 text-sm">
            Failed to load users: {String(users.error)}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-6 py-3">External ID</th>
                  <th className="px-6 py-3">Email</th>
                  <th className="px-6 py-3">Role</th>
                  <th className="px-6 py-3">Department</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {allUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 font-mono text-xs text-gray-700">{u.external_id}</td>
                    <td className="px-6 py-3 text-gray-600">{u.email ?? '—'}</td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                        u.role === 'admin'
                          ? 'bg-purple-100 text-purple-700'
                          : u.role === 'compliance'
                          ? 'bg-blue-100 text-blue-700'
                          : 'bg-gray-100 text-gray-600'
                      }`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-gray-600">{u.department ?? '—'}</td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${
                        u.is_active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-400'
                      }`}>
                        {u.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-gray-400 text-xs">
                      {new Date(u.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-3">
                      {u.is_active && (
                        deletingId === u.id ? (
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => softDelete.mutate(u.id)}
                              disabled={softDelete.isPending}
                              className="text-xs text-red-600 hover:underline disabled:opacity-50"
                            >
                              Confirm
                            </button>
                            <button
                              onClick={() => setDeletingId(null)}
                              className="text-xs text-gray-400 hover:underline"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setDeletingId(u.id)}
                            className="text-xs text-gray-400 hover:text-red-500"
                          >
                            Deactivate
                          </button>
                        )
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {allUsers.length === 0 && (
              <p className="px-6 py-8 text-center text-gray-400 text-sm">No users found.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
