import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight, Download, RotateCcw, ShieldCheck, ShieldAlert } from 'lucide-react';
import {
  fetchAuditLogs,
  exportAuditLogs,
  verifyAuditLog,
  type AuditLog,
} from '../lib/api';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Table, THead, TBody, Tr, Th, Td } from '../components/ui/table';

const PAGE_SIZE = 25;

const ACTION_OPTIONS = ['', 'ALLOW', 'REDACT', 'BLOCK', 'ESCALATE'];

type ActionVariant = 'success' | 'warning' | 'danger' | 'neutral';

function actionVariant(action: string): ActionVariant {
  switch (action) {
    case 'ALLOW':
      return 'success';
    case 'REDACT':
      return 'warning';
    case 'BLOCK':
      return 'danger';
    case 'ESCALATE':
      return 'warning';
    default:
      return 'neutral';
  }
}

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

  function verifyCell(id: string) {
    const result = verifyResults[id];
    if (result === 'loading') {
      return <span className="text-label text-fg-muted">Checking…</span>;
    }
    if (result === true) {
      return (
        <Badge variant="success" className="gap-1">
          <ShieldCheck className="h-3 w-3" />
          Verified
        </Badge>
      );
    }
    if (result === false) {
      return (
        <Badge variant="danger" className="gap-1">
          <ShieldAlert className="h-3 w-3" />
          Tampered
        </Badge>
      );
    }
    return (
      <Button size="sm" variant="bare" onClick={() => verify.mutate(id)}>
        Verify
      </Button>
    );
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary">Audit Explorer</h1>
        <p className="mt-1 text-small text-fg-muted">
          Browse and verify HMAC-signed audit logs.
        </p>
      </header>

      {/* Filters */}
      <Card>
        <CardContent className="flex flex-wrap gap-3 items-end py-4">
          <div>
            <label className="block text-micro uppercase tracking-wider text-fg-muted mb-1.5">
              Action
            </label>
            <select
              value={actionFilter}
              onChange={(e) => {
                setActionFilter(e.target.value);
                setOffset(0);
              }}
              className="h-9 rounded-md bg-translucent-1 border border-border text-caption text-fg-primary px-3 focus-visible:outline-none focus-visible:shadow-focus"
            >
              {ACTION_OPTIONS.map((a) => (
                <option key={a} value={a} className="bg-surface">
                  {a || 'All actions'}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-micro uppercase tracking-wider text-fg-muted mb-1.5">
              From
            </label>
            <Input
              type="datetime-local"
              value={startFilter}
              onChange={(e) => {
                setStartFilter(e.target.value);
                setOffset(0);
              }}
              className="w-48"
            />
          </div>
          <div>
            <label className="block text-micro uppercase tracking-wider text-fg-muted mb-1.5">
              To
            </label>
            <Input
              type="datetime-local"
              value={endFilter}
              onChange={(e) => {
                setEndFilter(e.target.value);
                setOffset(0);
              }}
              className="w-48"
            />
          </div>
          <Button size="md" variant="ghost" onClick={resetFilters}>
            <RotateCcw className="h-3.5 w-3.5" />
            Reset
          </Button>
          <div className="ml-auto flex gap-2">
            <Button size="md" variant="subtle" onClick={() => void exportAuditLogs('json')}>
              <Download className="h-3.5 w-3.5" />
              Export JSON
            </Button>
            <Button size="md" variant="subtle" onClick={() => void exportAuditLogs('csv')}>
              <Download className="h-3.5 w-3.5" />
              Export CSV
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <CardTitle>
            Logs
            {!logs.isLoading && (
              <span className="text-small text-fg-muted font-normal ml-2">
                ({total.toLocaleString()} total)
              </span>
            )}
          </CardTitle>
          <span className="text-small text-fg-muted font-mono">
            Page {currentPage} of {totalPages}
          </span>
        </CardHeader>

        <CardContent className="px-0">
          {logs.isLoading ? (
            <p className="px-6 py-10 text-center text-small text-fg-muted">Loading…</p>
          ) : logs.isError ? (
            <p className="px-6 py-10 text-center text-small text-status-danger">
              Error: {String(logs.error)}
            </p>
          ) : (logs.data?.logs ?? []).length === 0 ? (
            <p className="px-6 py-10 text-center text-small text-fg-muted italic">
              No audit logs found.
            </p>
          ) : (
            <Table>
              <THead>
                <Tr>
                  <Th>Interaction</Th>
                  <Th>Action</Th>
                  <Th>User</Th>
                  <Th>Dept</Th>
                  <Th>PII</Th>
                  <Th>Inj.</Th>
                  <Th>Latency</Th>
                  <Th>Created</Th>
                  <Th>HMAC</Th>
                </Tr>
              </THead>
              <TBody>
                {(logs.data?.logs ?? []).map((row: AuditLog) => (
                  <Tr key={row.interaction_id}>
                    <Td className="font-mono text-label text-fg-primary">
                      {row.interaction_id.slice(0, 8)}…
                    </Td>
                    <Td>
                      <Badge variant={actionVariant(row.enforcement_action)}>
                        {row.enforcement_action}
                      </Badge>
                    </Td>
                    <Td className="text-label font-mono">{row.user_id}</Td>
                    <Td className="text-label text-fg-muted">{row.department ?? '—'}</Td>
                    <Td>
                      {row.pii_detected ? (
                        <span className="text-label text-status-warning">
                          {row.pii_entity_types.join(', ') || 'Yes'}
                        </span>
                      ) : (
                        <span className="text-label text-fg-subtle">—</span>
                      )}
                    </Td>
                    <Td className="font-mono text-label">
                      {row.injection_score != null ? row.injection_score.toFixed(2) : '—'}
                    </Td>
                    <Td className="font-mono text-label text-fg-muted">
                      {row.total_latency_ms != null ? `${row.total_latency_ms}ms` : '—'}
                    </Td>
                    <Td className="font-mono text-label text-fg-subtle whitespace-nowrap">
                      {new Date(row.created_at).toLocaleString()}
                    </Td>
                    <Td>{verifyCell(row.interaction_id)}</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>

        <CardFooter className="flex items-center justify-between border-t border-border-subtle">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
            disabled={offset === 0}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            Prev
          </Button>
          <span className="text-label text-fg-muted font-mono">
            {total === 0
              ? '0 results'
              : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${total}`}
          </span>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setOffset(offset + PAGE_SIZE)}
            disabled={offset + PAGE_SIZE >= total}
          >
            Next
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
