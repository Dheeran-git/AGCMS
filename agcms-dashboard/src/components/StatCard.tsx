import { type ReactNode } from 'react';
import { cn } from '../lib/cn';

type Variant = 'default' | 'danger' | 'warning' | 'success' | 'accent';

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  variant?: Variant;
  icon?: ReactNode;
  trend?: { value: number; label?: string }; // +/- percentage
}

const ACCENT_BAR: Record<Variant, string> = {
  default: 'bg-accent-bright',
  accent:  'bg-accent-bright',
  danger:  'bg-status-danger',
  warning: 'bg-status-warning',
  success: 'bg-status-success',
};

const VALUE_TONE: Record<Variant, string> = {
  default: 'text-fg-primary',
  accent:  'text-fg-primary',
  danger:  'text-status-danger',
  warning: 'text-status-warning',
  success: 'text-status-success',
};

export function StatCard({ title, value, subtitle, variant = 'default', icon, trend }: StatCardProps) {
  const trendTone =
    trend === undefined
      ? ''
      : trend.value >= 0
      ? 'text-status-success'
      : 'text-status-danger';

  return (
    <div className="group relative bg-translucent-1 border border-border rounded-lg p-5 overflow-hidden transition-colors hover:bg-translucent-2">
      <div
        className={cn(
          'absolute top-0 left-0 right-0 h-px opacity-70',
          ACCENT_BAR[variant]
        )}
        aria-hidden="true"
      />
      <div className="flex items-start justify-between gap-2">
        <p className="text-micro uppercase tracking-wider text-fg-muted">{title}</p>
        {icon && <div className="text-fg-muted group-hover:text-fg-primary transition-colors">{icon}</div>}
      </div>
      <p className={cn('mt-3 text-[32px] leading-none tracking-[-0.704px] font-[590]', VALUE_TONE[variant])}>
        {value}
      </p>
      <div className="mt-2 flex items-center gap-2 text-label">
        {trend !== undefined && (
          <span className={cn('font-mono', trendTone)}>
            {trend.value >= 0 ? '+' : ''}
            {trend.value}%
          </span>
        )}
        {subtitle && <span className="text-fg-subtle">{subtitle}</span>}
      </div>
    </div>
  );
}
