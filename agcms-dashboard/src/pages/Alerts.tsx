import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertOctagon,
  Inbox,
  CheckCircle2,
  Clock,
  TimerOff,
  UserCog,
  Hand,
  ShieldCheck,
} from 'lucide-react';
import {
  fetchEscalations,
  acknowledgeEscalation,
  assignEscalation,
  resolveEscalation,
  fetchUsers,
  type Escalation,
  type User,
} from '../lib/api';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { StatCard } from '../components/StatCard';
import { Table, THead, TBody, Tr, Th, Td } from '../components/ui/table';

type BadgeVariant = 'neutral' | 'subtle' | 'info' | 'success' | 'warning' | 'danger' | 'accent';

function severityVariant(sev: string): BadgeVariant {
  if (sev === 'critical') return 'danger';
  if (sev === 'warning') return 'warning';
  return 'info';
}

function lifecycleStage(esc: Escalation): 'open' | 'acknowledged' | 'resolved' {
  if (esc.resolved_at) return 'resolved';
  if (esc.acknowledged_at) return 'acknowledged';
  return 'open';
}

function lifecycleVariant(stage: 'open' | 'acknowledged' | 'resolved'): BadgeVariant {
  if (stage === 'resolved') return 'success';
  if (stage === 'acknowledged') return 'info';
  return 'warning';
}

function fmtDuration(ms: number): string {
  const s = Math.floor(Math.abs(ms) / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

function slaState(esc: Escalation): {
  remainingMs: number;
  label: string;
  variant: BadgeVariant;
} {
  if (esc.resolved_at) {
    const elapsed = new Date(esc.resolved_at).getTime() - new Date(esc.created_at).getTime();
    return { remainingMs: 0, label: `Resolved in ${fmtDuration(elapsed)}`, variant: 'success' };
  }
  const targetMs = esc.sla_target_minutes * 60 * 1000;
  const elapsed = Date.now() - new Date(esc.created_at).getTime();
  const remaining = targetMs - elapsed;
  if (remaining < 0) {
    return { remainingMs: remaining, label: `${fmtDuration(remaining)} over SLA`, variant: 'danger' };
  }
  if (remaining < targetMs * 0.25) {
    return { remainingMs: remaining, label: `${fmtDuration(remaining)} remaining`, variant: 'warning' };
  }
  return { remainingMs: remaining, label: `${fmtDuration(remaining)} remaining`, variant: 'info' };
}

function userLabel(users: User[], id: string | null): string {
  if (!id) return '—';
  const u = users.find((u) => u.id === id);
  if (!u) return id.slice(0, 8) + '…';
  return u.email || u.external_id || id.slice(0, 8) + '…';
}

function AssigneePicker({
  esc,
  users,
  onAssign,
  busy,
}: {
  esc: Escalation;
  users: User[];
  onAssign: (uid: string | null) => void;
  busy: boolean;
}) {
  return (
    <select
      value={esc.assignee_user_id ?? ''}
      onChange={(e) => onAssign(e.target.value || null)}
      disabled={busy}
      className="h-8 rounded-md bg-translucent-2 border border-border text-caption text-fg-primary px-2 focus-visible:outline-none focus-visible:shadow-focus"
    >
      <option value="">— Unassigned —</option>
      {users.map((u) => (
        <option key={u.id} value={u.id} className="bg-surface">
          {u.email || u.external_id}
        </option>
      ))}
    </select>
  );
}

function ResolveDialog({
  onSubmit,
  onCancel,
  busy,
}: {
  onSubmit: (notes: string) => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const [notes, setNotes] = useState('');
  return (
    <div className="flex items-start gap-2 mt-2">
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Resolution notes (required) — what was done, who confirmed."
        className="flex-1 min-h-[60px] rounded-md bg-translucent-2 border border-border text-caption text-fg-primary px-2 py-1.5 focus-visible:outline-none focus-visible:shadow-focus"
      />
      <div className="flex flex-col gap-1">
        <Button
          size="sm"
          variant="primary"
          onClick={() => onSubmit(notes.trim())}
          disabled={busy || notes.trim().length === 0}
        >
          <ShieldCheck className="h-3.5 w-3.5" />
          Resolve
        </Button>
        <Button size="sm" variant="ghost" onClick={onCancel} disabled={busy}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

export function Alerts() {
  const qc = useQueryClient();
  const [resolvingId, setResolvingId] = useState<string | null>(null);

  const all = useQuery({
    queryKey: ['escalations-all'],
    queryFn: () => fetchEscalations(),
    refetchInterval: 15_000,
  });
  const usersQ = useQuery({ queryKey: ['users'], queryFn: fetchUsers });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['escalations-all'] });
  };

  const ack = useMutation({
    mutationFn: (id: string) => acknowledgeEscalation(id),
    onSuccess: invalidate,
  });
  const assign = useMutation({
    mutationFn: ({ id, uid }: { id: string; uid: string | null }) => assignEscalation(id, uid),
    onSuccess: invalidate,
  });
  const resolve = useMutation({
    mutationFn: ({ id, notes }: { id: string; notes: string }) => resolveEscalation(id, notes),
    onSuccess: () => {
      invalidate();
      setResolvingId(null);
    },
  });

  const escList = all.data?.escalations ?? [];
  const userList = usersQ.data?.users ?? [];

  const counters = useMemo(() => {
    const open = escList.filter((e) => !e.resolved_at);
    const acked = open.filter((e) => e.acknowledged_at);
    const breached = open.filter((e) => slaState(e).remainingMs < 0);
    const resolved = escList.filter((e) => e.resolved_at);
    return {
      open: open.length,
      acked: acked.length,
      breached: breached.length,
      resolved: resolved.length,
    };
  }, [escList]);

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary">Alerts &amp; Escalations</h1>
        <p className="mt-1 text-small text-fg-muted">
          Acknowledge, assign, and resolve compliance escalations. SLA timers are
          tier-based: critical 30m · warning 4h · info 24h.
        </p>
      </header>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Open"
          value={all.isLoading ? '…' : counters.open}
          variant={counters.open > 0 ? 'warning' : 'default'}
          icon={<AlertOctagon className="h-4 w-4" />}
        />
        <StatCard
          title="Acknowledged"
          value={all.isLoading ? '…' : counters.acked}
          variant="default"
          icon={<Hand className="h-4 w-4" />}
        />
        <StatCard
          title="Over SLA"
          value={all.isLoading ? '…' : counters.breached}
          variant={counters.breached > 0 ? 'danger' : 'default'}
          icon={<TimerOff className="h-4 w-4" />}
        />
        <StatCard
          title="Resolved"
          value={all.isLoading ? '…' : counters.resolved}
          variant="success"
          icon={<CheckCircle2 className="h-4 w-4" />}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Inbox className="h-4 w-4 text-accent-bright" />
            Incidents
          </CardTitle>
          <CardDescription>
            Each row shows the SLA timer counted from creation. Acknowledge to
            stop the cold-clock; resolve with mandatory notes to close.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-0">
          {all.isLoading ? (
            <p className="px-6 py-10 text-center text-small text-fg-muted">Loading…</p>
          ) : all.isError ? (
            <p className="px-6 py-10 text-center text-small text-status-danger">
              Error: {String(all.error)}
            </p>
          ) : escList.length === 0 ? (
            <p className="px-6 py-10 text-center text-small text-fg-muted italic">
              No escalations found.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <THead>
                  <Tr>
                    <Th>Severity</Th>
                    <Th>Reason</Th>
                    <Th>Stage</Th>
                    <Th>SLA</Th>
                    <Th>Assignee</Th>
                    <Th>Created</Th>
                    <Th>Actions</Th>
                  </Tr>
                </THead>
                <TBody>
                  {escList.map((esc) => {
                    const stage = lifecycleStage(esc);
                    const sla = slaState(esc);
                    return (
                      <>
                        <Tr key={esc.id}>
                          <Td>
                            <Badge variant={severityVariant(esc.severity)}>
                              {esc.severity}
                            </Badge>
                          </Td>
                          <Td className="text-fg-secondary max-w-md truncate">
                            {esc.reason}
                            {esc.resolution_notes && (
                              <p className="mt-1 text-label text-fg-subtle italic truncate">
                                ✓ {esc.resolution_notes}
                              </p>
                            )}
                          </Td>
                          <Td>
                            <Badge variant={lifecycleVariant(stage)}>{stage}</Badge>
                          </Td>
                          <Td>
                            <span className="inline-flex items-center gap-1 font-mono text-label">
                              <Clock className="h-3 w-3" />
                              <Badge variant={sla.variant}>{sla.label}</Badge>
                            </span>
                          </Td>
                          <Td className="text-label text-fg-secondary">
                            {usersQ.isLoading ? (
                              <span className="text-fg-muted">…</span>
                            ) : stage === 'resolved' ? (
                              <span className="font-mono">
                                {userLabel(userList, esc.assignee_user_id)}
                              </span>
                            ) : (
                              <AssigneePicker
                                esc={esc}
                                users={userList}
                                onAssign={(uid) => assign.mutate({ id: esc.id, uid })}
                                busy={assign.isPending}
                              />
                            )}
                          </Td>
                          <Td className="font-mono text-label text-fg-subtle whitespace-nowrap">
                            {new Date(esc.created_at).toLocaleString()}
                          </Td>
                          <Td>
                            <div className="flex items-center gap-2">
                              {stage === 'open' && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => ack.mutate(esc.id)}
                                  disabled={ack.isPending}
                                >
                                  <Hand className="h-3.5 w-3.5" />
                                  Acknowledge
                                </Button>
                              )}
                              {stage !== 'resolved' && resolvingId !== esc.id && (
                                <Button
                                  size="sm"
                                  variant="primary"
                                  onClick={() => setResolvingId(esc.id)}
                                >
                                  <ShieldCheck className="h-3.5 w-3.5" />
                                  Resolve
                                </Button>
                              )}
                              {stage === 'resolved' && esc.resolved_by && (
                                <span className="text-label text-fg-subtle font-mono">
                                  by {userLabel(userList, esc.resolved_by)}
                                </span>
                              )}
                            </div>
                          </Td>
                        </Tr>
                        {resolvingId === esc.id && (
                          <Tr key={esc.id + '-resolve'}>
                            <Td colSpan={7}>
                              <ResolveDialog
                                busy={resolve.isPending}
                                onCancel={() => setResolvingId(null)}
                                onSubmit={(notes) => resolve.mutate({ id: esc.id, notes })}
                              />
                            </Td>
                          </Tr>
                        )}
                      </>
                    );
                  })}
                </TBody>
              </Table>
            </div>
          )}
          <div className="px-6 pt-4 text-label text-fg-subtle inline-flex items-center gap-2">
            <UserCog className="h-3 w-3" />
            Assignments are visible to all compliance reviewers in this tenant.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
