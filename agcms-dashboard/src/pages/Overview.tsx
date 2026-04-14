import { useQuery } from '@tanstack/react-query';
import { fetchStats, fetchTimeline, fetchViolations } from '../lib/api';
import { StatCard } from '../components/StatCard';
import { RequestChart } from '../components/RequestChart';
import { ViolationFeed } from '../components/ViolationFeed';

export function Overview() {
  const stats = useQuery({ queryKey: ['stats'], queryFn: fetchStats, refetchInterval: 10_000 });
  const timeline = useQuery({ queryKey: ['timeline'], queryFn: () => fetchTimeline(24), refetchInterval: 30_000 });
  const recent = useQuery({ queryKey: ['violations-recent'], queryFn: () => fetchViolations(5, 0), refetchInterval: 10_000 });

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Overview</h1>
        <p className="text-sm text-gray-500 mt-1">
          AI Governance &amp; Compliance Monitoring System — Last 24 hours
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          title="Total Requests"
          value={stats.data?.total_requests ?? '--'}
          subtitle="Last 24h"
        />
        <StatCard
          title="Violations"
          value={stats.data?.violations ?? '--'}
          subtitle="Blocked or redacted"
          variant="danger"
        />
        <StatCard
          title="PII Detections"
          value={stats.data?.pii_detections ?? '--'}
          subtitle="Personal data found"
          variant="warning"
        />
        <StatCard
          title="Avg Latency"
          value={stats.data?.avg_latency_ms != null ? `${stats.data.avg_latency_ms}ms` : '--'}
          subtitle="Processing time"
          variant="success"
        />
      </div>

      <div className="bg-white rounded-lg border border-gray-200 p-6 mb-8">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Request Volume</h2>
        <RequestChart data={timeline.data?.timeline ?? []} loading={timeline.isLoading} />
      </div>

      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Recent Violations</h2>
        <ViolationFeed
          violations={recent.data?.violations ?? []}
          loading={recent.isLoading}
        />
      </div>
    </div>
  );
}
