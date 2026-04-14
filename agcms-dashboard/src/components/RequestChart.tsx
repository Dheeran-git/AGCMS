import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { format } from 'date-fns';
import type { TimelinePoint } from '../lib/api';

interface RequestChartProps {
  data: TimelinePoint[];
  loading?: boolean;
}

export function RequestChart({ data, loading }: RequestChartProps) {
  if (loading) {
    return <div className="h-64 bg-gray-50 animate-pulse rounded-lg" />;
  }

  if (data.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-sm text-gray-400">
        No data available for the selected period.
      </div>
    );
  }

  const formatted = data.map((d) => ({
    ...d,
    label: format(new Date(d.hour), 'HH:mm'),
  }));

  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={formatted} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
        <XAxis dataKey="label" tick={{ fontSize: 12 }} stroke="#9ca3af" />
        <YAxis tick={{ fontSize: 12 }} stroke="#9ca3af" />
        <Tooltip
          contentStyle={{ fontSize: 12, borderRadius: 8 }}
          labelFormatter={(label) => `Time: ${label}`}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Area
          type="monotone"
          dataKey="total"
          name="Total"
          stroke="#6366f1"
          fill="#6366f1"
          fillOpacity={0.1}
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="violations"
          name="Violations"
          stroke="#ef4444"
          fill="#ef4444"
          fillOpacity={0.1}
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="pii"
          name="PII Detected"
          stroke="#f59e0b"
          fill="#f59e0b"
          fillOpacity={0.1}
          strokeWidth={2}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
