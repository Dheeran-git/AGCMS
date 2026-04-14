import { cn } from '../lib/cn';

interface StatCardProps {
  title: string;
  value: number | string;
  subtitle?: string;
  variant?: 'default' | 'danger' | 'warning' | 'success';
}

const VARIANT_STYLES = {
  default: 'text-gray-900',
  danger: 'text-red-600',
  warning: 'text-yellow-600',
  success: 'text-green-600',
} as const;

export function StatCard({ title, value, subtitle, variant = 'default' }: StatCardProps) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <p className="text-sm font-medium text-gray-500">{title}</p>
      <p className={cn('text-3xl font-bold mt-1', VARIANT_STYLES[variant])}>
        {value}
      </p>
      {subtitle && (
        <p className="text-xs text-gray-400 mt-1">{subtitle}</p>
      )}
    </div>
  );
}
