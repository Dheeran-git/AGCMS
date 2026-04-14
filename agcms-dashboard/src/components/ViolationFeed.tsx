import { formatDistanceToNow } from 'date-fns';
import { cn } from '../lib/cn';
import type { Violation } from '../lib/api';

interface ViolationFeedProps {
  violations: Violation[];
  loading?: boolean;
}

const ACTION_STYLES: Record<string, string> = {
  BLOCK: 'bg-red-100 text-red-700',
  REDACT: 'bg-yellow-100 text-yellow-700',
  ALLOW: 'bg-green-100 text-green-700',
};

const RISK_STYLES: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700',
  HIGH: 'bg-orange-100 text-orange-700',
  MEDIUM: 'bg-yellow-100 text-yellow-700',
  LOW: 'bg-blue-100 text-blue-700',
  NONE: 'bg-gray-100 text-gray-700',
};

export function ViolationFeed({ violations, loading }: ViolationFeedProps) {
  if (loading) {
    return (
      <div className="animate-pulse space-y-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-20 bg-gray-100 rounded-lg" />
        ))}
      </div>
    );
  }

  if (violations.length === 0) {
    return (
      <div className="text-center py-12 text-gray-400">
        <svg className="mx-auto h-12 w-12 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p className="text-sm">No violations recorded yet.</p>
        <p className="text-xs mt-1">Route LLM requests through the gateway to see activity.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {violations.map((v) => (
        <div
          key={v.interaction_id}
          className="bg-white border border-gray-200 rounded-lg p-4 hover:border-gray-300 transition-colors"
        >
          <div className="flex items-start justify-between">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className={cn(
                  'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
                  ACTION_STYLES[v.action] || ACTION_STYLES.BLOCK
                )}>
                  {v.action}
                </span>
                {v.pii_risk_level && v.pii_risk_level !== 'NONE' && (
                  <span className={cn(
                    'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
                    RISK_STYLES[v.pii_risk_level] || RISK_STYLES.MEDIUM
                  )}>
                    PII: {v.pii_risk_level}
                  </span>
                )}
                {v.injection_type && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-700">
                    Injection: {v.injection_type}
                  </span>
                )}
              </div>
              <p className="text-sm text-gray-700 truncate">
                {v.reason || 'No reason provided'}
              </p>
              <div className="flex items-center gap-4 mt-2 text-xs text-gray-400">
                <span>User: {v.user_id}</span>
                {v.department && <span>Dept: {v.department}</span>}
                {v.latency_ms != null && <span>{v.latency_ms}ms</span>}
              </div>
            </div>
            <div className="text-xs text-gray-400 whitespace-nowrap ml-4">
              {v.created_at
                ? formatDistanceToNow(new Date(v.created_at), { addSuffix: true })
                : '--'}
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2">
            {v.pii_entity_types.map((t) => (
              <span key={t} className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-600 rounded">
                {t}
              </span>
            ))}
          </div>
          <p className="text-xs text-gray-300 mt-1 font-mono truncate">
            {v.interaction_id}
          </p>
        </div>
      ))}
    </div>
  );
}
