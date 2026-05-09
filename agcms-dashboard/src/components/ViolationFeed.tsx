import { formatDistanceToNow } from 'date-fns';
import { ShieldCheck } from 'lucide-react';
import type { Violation } from '../lib/api';
import { Badge } from './ui/badge';
import { FrameworkMap } from './FrameworkMap';
import { citationsForViolation } from '../lib/citations';

interface ViolationFeedProps {
  violations: Violation[];
  loading?: boolean;
}

type ActionVariant = 'danger' | 'warning' | 'success' | 'neutral';

function actionVariant(action: string): ActionVariant {
  if (action === 'BLOCK') return 'danger';
  if (action === 'REDACT') return 'warning';
  if (action === 'ALLOW') return 'success';
  return 'neutral';
}

type SeverityKey = 'severity-critical' | 'severity-high' | 'severity-medium' | 'severity-low' | 'neutral';

function riskVariant(level: string | null): SeverityKey {
  switch (level) {
    case 'CRITICAL':
      return 'severity-critical';
    case 'HIGH':
      return 'severity-high';
    case 'MEDIUM':
      return 'severity-medium';
    case 'LOW':
      return 'severity-low';
    default:
      return 'neutral';
  }
}

export function ViolationFeed({ violations, loading }: ViolationFeedProps) {
  if (loading) {
    return (
      <div className="space-y-2">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-[82px] bg-translucent-1 border border-border-subtle rounded-lg animate-pulse" />
        ))}
      </div>
    );
  }

  if (violations.length === 0) {
    return (
      <div className="text-center py-10 border border-dashed border-border-subtle rounded-lg">
        <ShieldCheck className="mx-auto h-8 w-8 mb-3 text-fg-subtle" strokeWidth={1.25} />
        <p className="text-caption text-fg-secondary">All clear.</p>
        <p className="text-label text-fg-muted mt-1">
          No violations recorded in the selected window.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {violations.map((v) => (
        <div
          key={v.interaction_id}
          className="bg-translucent-1 border border-border-subtle rounded-lg p-3.5 hover:bg-translucent-2 hover:border-border transition-colors"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
                <Badge variant={actionVariant(v.action)}>{v.action}</Badge>
                {v.pii_risk_level && v.pii_risk_level !== 'NONE' && (
                  <Badge variant={riskVariant(v.pii_risk_level)}>PII · {v.pii_risk_level}</Badge>
                )}
                {v.injection_type && (
                  <Badge variant="accent">Injection · {v.injection_type}</Badge>
                )}
              </div>
              <p className="text-caption text-fg-secondary truncate">
                {v.reason || 'No reason provided'}
              </p>
              <div className="flex items-center gap-3 mt-1.5 text-label text-fg-subtle">
                <span>
                  <span className="text-fg-muted">user</span>{' '}
                  <span className="font-mono text-fg-secondary">{v.user_id}</span>
                </span>
                {v.department && (
                  <span>
                    <span className="text-fg-muted">dept</span> {v.department}
                  </span>
                )}
                {v.latency_ms != null && (
                  <span className="font-mono">{v.latency_ms} ms</span>
                )}
              </div>
            </div>
            <div className="text-label text-fg-subtle whitespace-nowrap shrink-0 font-mono">
              {v.created_at
                ? formatDistanceToNow(new Date(v.created_at), { addSuffix: true })
                : '—'}
            </div>
          </div>
          {v.pii_entity_types.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1">
              {v.pii_entity_types.map((t) => (
                <Badge key={t} variant="subtle">
                  {t}
                </Badge>
              ))}
            </div>
          )}
          {(() => {
            const cites = citationsForViolation({
              piiCategories: v.pii_entity_types,
              injectionDetected: !!v.injection_type,
            });
            return cites.length > 0 ? (
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <span className="text-micro text-fg-muted">Maps to:</span>
                <FrameworkMap citations={cites} />
              </div>
            ) : null;
          })()}
        </div>
      ))}
    </div>
  );
}
