import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  ShieldAlert,
  Eye,
  Timer,
  TrendingUp,
  AlertTriangle,
  Radio,
  RadioTower,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { fetchStats, fetchTimeline, type Violation } from '../lib/api';
import { StatCard } from '../components/StatCard';
import { RequestChart } from '../components/RequestChart';
import { ViolationFeed } from '../components/ViolationFeed';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { useEventStream } from '../hooks/useEventStream';

export function Overview() {
  const stats = useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    refetchInterval: 10_000,
  });
  const timeline = useQuery({
    queryKey: ['timeline'],
    queryFn: () => fetchTimeline(24),
    refetchInterval: 30_000,
  });

  const [liveViolations, setLiveViolations] = useState<Violation[]>([]);
  const stream = useEventStream<Violation | Violation[]>({
    url: '/api/v1/stream/violations',
    handlers: {
      snapshot: (rows) => {
        if (Array.isArray(rows)) setLiveViolations(rows.slice(0, 5));
      },
      violation: (row) => {
        if (Array.isArray(row)) return;
        setLiveViolations((prev) => [row, ...prev].slice(0, 5));
      },
    },
  });

  const formatValue = (v: number | null | undefined) =>
    v == null ? '—' : v.toLocaleString();

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-h1 text-fg-primary">Overview</h1>
        <p className="mt-1 text-small text-fg-muted">
          AI Governance & Compliance Monitoring System — last 24 hours.
        </p>
      </header>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total requests"
          value={formatValue(stats.data?.total_requests)}
          subtitle="Last 24h"
          variant="accent"
          icon={<Activity className="h-4 w-4" />}
        />
        <StatCard
          title="Violations"
          value={formatValue(stats.data?.violations)}
          subtitle="Blocked or redacted"
          variant="danger"
          icon={<ShieldAlert className="h-4 w-4" />}
        />
        <StatCard
          title="PII detections"
          value={formatValue(stats.data?.pii_detections)}
          subtitle="Personal data found"
          variant="warning"
          icon={<Eye className="h-4 w-4" />}
        />
        <StatCard
          title="Avg latency"
          value={
            stats.data?.avg_latency_ms != null ? `${stats.data.avg_latency_ms}ms` : '—'
          }
          subtitle="Processing time"
          variant="success"
          icon={<Timer className="h-4 w-4" />}
        />
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-accent-bright" />
              Request volume
            </CardTitle>
            <CardDescription className="mt-1">
              Total, violations, and PII detections across the last 24 hours.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <RequestChart
            data={timeline.data?.timeline ?? []}
            loading={timeline.isLoading}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-accent-bright" />
              Recent violations
              <StreamBadge status={stream.status} />
            </CardTitle>
            <CardDescription className="mt-1">
              Live feed — events stream in as they're enforced (no polling).
            </CardDescription>
          </div>
          <Button asChild size="sm" variant="ghost">
            <Link to="/violations">View all</Link>
          </Button>
        </CardHeader>
        <CardContent>
          <ViolationFeed
            violations={liveViolations}
            loading={stream.status === 'connecting' && liveViolations.length === 0}
          />
        </CardContent>
      </Card>
    </div>
  );
}

function StreamBadge({ status }: { status: 'connecting' | 'open' | 'reconnecting' | 'closed' }) {
  if (status === 'open') {
    return (
      <Badge variant="success" className="ml-1">
        <Radio className="h-3 w-3" />
        Live
      </Badge>
    );
  }
  if (status === 'reconnecting') {
    return (
      <Badge variant="warning" className="ml-1">
        <RadioTower className="h-3 w-3" />
        Reconnecting…
      </Badge>
    );
  }
  return (
    <Badge variant="subtle" className="ml-1">
      <RadioTower className="h-3 w-3" />
      {status === 'connecting' ? 'Connecting' : 'Offline'}
    </Badge>
  );
}
