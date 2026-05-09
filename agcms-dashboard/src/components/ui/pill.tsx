import { cn } from '../../lib/cn';
import { StatusDot } from './badge';

/**
 * System health pill — used in the top bar to summarize platform state.
 *
 * Format: leading dot + label + (optional) mono " · 18,432 req" counter.
 * Reference: design-system/preview/status-pills.html.
 */
export function HealthPill({
  tone,
  label,
  count,
  className,
}: {
  tone: 'success' | 'warning' | 'danger';
  label: string;
  count?: number | string;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-2 h-8 px-3 rounded-md',
        'bg-translucent-1 border border-border-subtle',
        'text-label font-[510] text-fg-secondary',
        className,
      )}
    >
      <StatusDot tone={tone} pulsing={tone === 'success'} />
      <span>{label}</span>
      {count !== undefined && (
        <span className="font-mono text-fg-subtle">· {typeof count === 'number' ? count.toLocaleString() : count} req</span>
      )}
    </span>
  );
}

/**
 * Stream status pill — used inline next to live-data sections.
 *
 * Reference: design-system/preview/status-pills.html (lower row).
 */
export function StreamPill({
  tone,
  label,
  pulsing,
  className,
}: {
  tone: 'success' | 'warning' | 'neutral';
  label: string;
  pulsing?: boolean;
  className?: string;
}) {
  const toneClass = {
    success: 'bg-status-success-soft text-status-success border-status-success/30',
    warning: 'bg-status-warning-soft text-status-warning border-status-warning/30',
    neutral: 'bg-translucent-2 text-fg-secondary border-border-subtle',
  }[tone];

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full',
        'text-micro font-[510] border whitespace-nowrap',
        toneClass,
        className,
      )}
    >
      {pulsing && tone !== 'neutral' && <StatusDot tone={tone === 'success' ? 'success' : 'warning'} pulsing />}
      {label}
    </span>
  );
}
