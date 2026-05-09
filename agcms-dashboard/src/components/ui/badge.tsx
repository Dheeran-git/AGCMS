import { forwardRef, type HTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '../../lib/cn';

const badgeVariants = cva(
  'inline-flex items-center gap-1 text-label rounded-full whitespace-nowrap border px-2 py-0.5',
  {
    variants: {
      variant: {
        neutral:
          'bg-transparent text-fg-secondary border-[#23252a]',
        subtle:
          'bg-translucent-2 text-fg-primary border-border-subtle rounded-sm px-1.5 py-0 text-micro',
        info:
          'bg-status-info-soft text-status-info border-status-info/30',
        success:
          'bg-status-success-soft text-status-success border-status-success/30',
        warning:
          'bg-status-warning-soft text-status-warning border-status-warning/30',
        danger:
          'bg-status-danger-soft text-status-danger border-status-danger/30',
        accent:
          'bg-accent/15 text-accent-bright border-accent/30',
        'severity-low':
          'bg-status-info-soft text-status-info border-status-info/30',
        'severity-medium':
          'bg-status-warning-soft text-status-warning border-status-warning/30',
        'severity-high':
          'bg-status-danger-soft text-status-danger border-status-danger/30',
        'severity-critical':
          'bg-status-danger text-white border-status-danger',
      },
    },
    defaultVariants: {
      variant: 'neutral',
    },
  }
);

export interface BadgeProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant, ...props }, ref) => (
    <span ref={ref} className={cn(badgeVariants({ variant }), className)} {...props} />
  )
);
Badge.displayName = 'Badge';

// Tiny colored dot for status indicators (use with Badge or standalone)
export function StatusDot({
  tone,
  className,
  pulsing,
}: {
  tone: 'success' | 'warning' | 'danger' | 'info' | 'muted';
  className?: string;
  pulsing?: boolean;
}) {
  const toneClass = {
    success: 'bg-status-success',
    warning: 'bg-status-warning',
    danger: 'bg-status-danger',
    info: 'bg-status-info',
    muted: 'bg-fg-muted',
  }[tone];
  return (
    <span
      className={cn(
        'inline-block h-2 w-2 rounded-full',
        toneClass,
        pulsing && 'animate-pulse-dot',
        className
      )}
    />
  );
}
