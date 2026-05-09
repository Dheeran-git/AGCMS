import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  type TooltipProps,
} from 'recharts';
import { format } from 'date-fns';
import type { TimelinePoint } from '../lib/api';
import { chartColors } from '../lib/chart-theme';

interface RequestChartProps {
  data: TimelinePoint[];
  loading?: boolean;
}

const SERIES = [
  { key: 'total',      label: 'Total',     color: chartColors.primary },
  { key: 'violations', label: 'Violations', color: chartColors.danger },
  { key: 'pii',        label: 'PII',        color: chartColors.warning },
] as const;

function CustomTooltip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-surface border border-border rounded-lg shadow-elev-5 px-3 py-2.5 min-w-[160px]">
      <div className="text-micro text-fg-muted font-mono mb-1.5">{label}</div>
      {payload.map((p) => (
        <div key={p.dataKey as string} className="flex items-center gap-2 text-label">
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: p.color }}
            aria-hidden="true"
          />
          <span className="text-fg-muted capitalize">{p.name}</span>
          <span className="ml-auto text-fg-primary font-mono">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

export function RequestChart({ data, loading }: RequestChartProps) {
  if (loading) {
    return <div className="h-72 bg-translucent-1 border border-border-subtle rounded-lg animate-pulse" />;
  }

  if (data.length === 0) {
    return (
      <div className="h-72 flex items-center justify-center text-small text-fg-muted border border-dashed border-border-subtle rounded-lg">
        No traffic in the selected window.
      </div>
    );
  }

  const formatted = data.map((d) => ({
    ...d,
    label: format(new Date(d.hour), 'HH:mm'),
  }));

  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={formatted} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
        <defs>
          {SERIES.map((s) => (
            <linearGradient key={s.key} id={`fill-${s.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={s.color} stopOpacity={0} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid vertical={false} stroke={chartColors.grid} />
        <XAxis
          dataKey="label"
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
        <Tooltip content={<CustomTooltip />} cursor={{ stroke: chartColors.axis, strokeWidth: 1 }} />
        <Legend
          wrapperStyle={{ fontSize: 12, paddingTop: 8 }}
          iconType="circle"
          iconSize={8}
          formatter={(value) => <span style={{ color: chartColors.muted }}>{value}</span>}
        />
        {SERIES.map((s) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.label}
            stroke={s.color}
            fill={`url(#fill-${s.key})`}
            strokeWidth={1.75}
            activeDot={{ r: 4, strokeWidth: 0 }}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}
