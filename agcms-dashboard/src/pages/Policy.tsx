import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, History, Pencil, Send, ScrollText } from 'lucide-react';
import {
  fetchPolicy,
  updatePolicy,
  fetchPolicyVersions,
  fetchPolicyPacks,
  type PolicyConfig,
} from '../lib/api';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Input } from '../components/ui/input';
import { Textarea } from '../components/ui/textarea';
import { Table, THead, TBody, Tr, Th, Td } from '../components/ui/table';
import { FrameworkMap, frameworkLabel } from '../components/FrameworkMap';

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

  const packs = useQuery({
    queryKey: ['policy-packs'],
    queryFn: fetchPolicyPacks,
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
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary">Policy Manager</h1>
        <p className="mt-1 text-small text-fg-muted">
          View and deploy tenant governance policies.
        </p>
      </header>

      {successMsg && (
        <div className="flex items-center gap-2 px-4 py-3 bg-status-success-soft border border-status-success/30 rounded-md text-caption text-status-success">
          <CheckCircle2 className="h-4 w-4" />
          {successMsg}
        </div>
      )}

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
          <div>
            <CardTitle>Active policy</CardTitle>
            {active && (
              <CardDescription className="mt-1">
                <Badge variant="accent" className="mr-2">
                  v{active.version}
                </Badge>
                Deployed {new Date(active.created_at).toLocaleString()}
                {active.notes && (
                  <span className="ml-2 italic text-fg-muted">"{active.notes}"</span>
                )}
              </CardDescription>
            )}
          </div>
          {active && editJson === null && (
            <Button variant="primary" size="sm" onClick={startEdit}>
              <Pencil className="h-3.5 w-3.5" />
              Edit & deploy
            </Button>
          )}
        </CardHeader>

        <CardContent>
          {policy.isLoading ? (
            <p className="text-small text-fg-muted">Loading…</p>
          ) : policy.isError ? (
            <p className="text-small text-status-danger">Error: {String(policy.error)}</p>
          ) : editJson !== null ? (
            <div className="space-y-3">
              <Textarea
                value={editJson}
                onChange={(e) => {
                  setEditJson(e.target.value);
                  setJsonError(null);
                }}
                rows={20}
                className="font-mono text-label leading-relaxed resize-y"
                spellCheck={false}
              />
              {jsonError && (
                <p className="text-label text-status-danger">{jsonError}</p>
              )}
              <div className="flex items-center gap-3">
                <Input
                  type="text"
                  placeholder="Deploy notes (optional)"
                  value={deployNotes}
                  onChange={(e) => setDeployNotes(e.target.value)}
                  className="flex-1"
                />
                <Button
                  variant="primary"
                  size="md"
                  onClick={handleDeploy}
                  disabled={deploy.isPending}
                >
                  <Send className="h-3.5 w-3.5" />
                  {deploy.isPending ? 'Deploying…' : 'Deploy'}
                </Button>
                <Button
                  variant="ghost"
                  size="md"
                  onClick={() => {
                    setEditJson(null);
                    setJsonError(null);
                  }}
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <pre className="bg-translucent-1 border border-border-subtle rounded-md p-4 text-label font-mono text-fg-secondary overflow-auto max-h-96 shadow-inset-recessed">
              {JSON.stringify(active?.config ?? {}, null, 2)}
            </pre>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ScrollText className="h-4 w-4 text-accent-bright" />
            Compliance frameworks
          </CardTitle>
          <CardDescription>
            Installed policy packs map every enforcement rule to a specific regulatory citation.
            Hover any chip to see the article text.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-0">
          {packs.isLoading ? (
            <p className="px-6 py-8 text-center text-small text-fg-muted">Loading…</p>
          ) : (packs.data?.packs ?? []).length === 0 ? (
            <p className="px-6 py-8 text-center text-small text-fg-muted italic">
              No packs installed.
            </p>
          ) : (
            <Table>
              <THead>
                <Tr>
                  <Th>Framework</Th>
                  <Th>Pack</Th>
                  <Th>Version</Th>
                  <Th>Rules</Th>
                  <Th>Citations</Th>
                </Tr>
              </THead>
              <TBody>
                {(packs.data?.packs ?? []).map((p) => (
                  <Tr key={p.id}>
                    <Td>
                      <Badge variant="accent">{frameworkLabel(p.framework)}</Badge>
                    </Td>
                    <Td className="text-fg-primary">{p.name}</Td>
                    <Td className="font-mono text-label text-fg-subtle">v{p.version}</Td>
                    <Td className="text-fg-secondary">{p.rule_count}</Td>
                    <Td>
                      <FrameworkMap
                        citations={p.citations}
                        emptyHint="—"
                      />
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <History className="h-4 w-4 text-accent-bright" />
            Version history
          </CardTitle>
        </CardHeader>
        <CardContent className="px-0">
          {versions.isLoading ? (
            <p className="px-6 py-8 text-center text-small text-fg-muted">Loading…</p>
          ) : (versions.data?.versions ?? []).length === 0 ? (
            <p className="px-6 py-8 text-center text-small text-fg-muted italic">
              No versions found.
            </p>
          ) : (
            <Table>
              <THead>
                <Tr>
                  <Th>Version</Th>
                  <Th>Status</Th>
                  <Th>Notes</Th>
                  <Th>Deployed</Th>
                </Tr>
              </THead>
              <TBody>
                {(versions.data?.versions ?? []).map((v) => (
                  <Tr key={v.id}>
                    <Td className="font-mono text-fg-primary">v{v.version}</Td>
                    <Td>
                      <Badge variant={v.is_active ? 'success' : 'subtle'}>
                        {v.is_active ? 'Active' : 'Archived'}
                      </Badge>
                    </Td>
                    <Td className="italic text-fg-muted">{v.notes ?? '—'}</Td>
                    <Td className="font-mono text-label text-fg-subtle whitespace-nowrap">
                      {new Date(v.created_at).toLocaleString()}
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
