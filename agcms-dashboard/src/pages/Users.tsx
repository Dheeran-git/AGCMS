import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
  type TooltipProps,
} from 'recharts';
import { Users as UsersIcon, Building2 } from 'lucide-react';
import { fetchUsers, deleteUser, fetchStatsDepartments } from '../lib/api';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Table, THead, TBody, Tr, Th, Td } from '../components/ui/table';
import { chartColors } from '../lib/chart-theme';

function roleVariant(role: string): 'accent' | 'info' | 'subtle' {
  if (role === 'admin') return 'accent';
  if (role === 'compliance') return 'info';
  return 'subtle';
}

function ChartTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-surface border border-border rounded-md shadow-elev-4 px-3 py-2 min-w-[140px]">
      <div className="text-micro text-fg-muted font-mono mb-1">{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey as string} className="flex items-center gap-2 text-label">
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: p.color }}
            aria-hidden
          />
          <span className="text-fg-muted capitalize">{p.name}</span>
          <span className="ml-auto text-fg-primary font-mono">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

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
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary">Users & Departments</h1>
        <p className="mt-1 text-small text-fg-muted">
          Tenant user roster and department activity.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-4 w-4 text-accent-bright" />
            Requests by department
          </CardTitle>
          <CardDescription>Last 7 days · total vs. violations.</CardDescription>
        </CardHeader>
        <CardContent>
          {departments.isLoading ? (
            <div className="h-52 flex items-center justify-center text-small text-fg-muted">
              Loading…
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={departments.data?.departments ?? []}
                margin={{ top: 8, right: 12, left: -12, bottom: 0 }}
              >
                <CartesianGrid vertical={false} stroke={chartColors.grid} />
                <XAxis
                  dataKey="department"
                  stroke={chartColors.subtle}
                  tick={{ fontSize: 11, fill: chartColors.muted }}
                  tickLine={false}
                  axisLine={{ stroke: chartColors.axis }}
                />
                <YAxis
                  stroke={chartColors.subtle}
                  tick={{ fontSize: 11, fill: chartColors.muted }}
                  tickLine={false}
                  axisLine={false}
                  width={40}
                />
                <Tooltip
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  content={<ChartTooltip />}
                />
                <Legend
                  wrapperStyle={{ fontSize: 12, paddingTop: 8 }}
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => (
                    <span style={{ color: chartColors.muted }}>{value}</span>
                  )}
                />
                <Bar
                  dataKey="total"
                  fill={chartColors.primary}
                  name="Total"
                  radius={[3, 3, 0, 0]}
                />
                <Bar
                  dataKey="violations"
                  fill={chartColors.danger}
                  name="Violations"
                  radius={[3, 3, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <UsersIcon className="h-4 w-4 text-accent-bright" />
              Users
            </CardTitle>
            <CardDescription className="mt-1">
              {activeUsers.length} active · {allUsers.length} total
            </CardDescription>
          </div>
          <Badge variant="subtle">
            {activeUsers.length} / {allUsers.length}
          </Badge>
        </CardHeader>
        <CardContent className="px-0">
          {users.isLoading ? (
            <p className="px-6 py-10 text-center text-small text-fg-muted">Loading users…</p>
          ) : users.isError ? (
            <p className="px-6 py-10 text-center text-small text-status-danger">
              Failed to load users: {String(users.error)}
            </p>
          ) : allUsers.length === 0 ? (
            <p className="px-6 py-10 text-center text-small text-fg-muted italic">
              No users found.
            </p>
          ) : (
            <Table>
              <THead>
                <Tr>
                  <Th>External ID</Th>
                  <Th>Email</Th>
                  <Th>Role</Th>
                  <Th>Department</Th>
                  <Th>Status</Th>
                  <Th>Created</Th>
                  <Th />
                </Tr>
              </THead>
              <TBody>
                {allUsers.map((u) => (
                  <Tr key={u.id}>
                    <Td className="font-mono text-label text-fg-primary">{u.external_id}</Td>
                    <Td>{u.email ?? '—'}</Td>
                    <Td>
                      <Badge variant={roleVariant(u.role)}>{u.role}</Badge>
                    </Td>
                    <Td>{u.department ?? '—'}</Td>
                    <Td>
                      <Badge variant={u.is_active ? 'success' : 'subtle'}>
                        {u.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                    </Td>
                    <Td className="font-mono text-label text-fg-subtle whitespace-nowrap">
                      {new Date(u.created_at).toLocaleDateString()}
                    </Td>
                    <Td>
                      {u.is_active &&
                        (deletingId === u.id ? (
                          <div className="flex items-center gap-2">
                            <Button
                              size="sm"
                              variant="danger"
                              onClick={() => softDelete.mutate(u.id)}
                              disabled={softDelete.isPending}
                            >
                              Confirm
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setDeletingId(null)}
                            >
                              Cancel
                            </Button>
                          </div>
                        ) : (
                          <Button
                            size="sm"
                            variant="bare"
                            onClick={() => setDeletingId(u.id)}
                          >
                            Deactivate
                          </Button>
                        ))}
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
