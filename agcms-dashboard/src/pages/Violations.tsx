import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchViolations } from '../lib/api';
import { ViolationFeed } from '../components/ViolationFeed';

const PAGE_SIZE = 20;

export function Violations() {
  const [page, setPage] = useState(0);

  const { data, isLoading } = useQuery({
    queryKey: ['violations', page],
    queryFn: () => fetchViolations(PAGE_SIZE, page * PAGE_SIZE),
    refetchInterval: 15_000,
  });

  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Violations</h1>
          <p className="text-sm text-gray-500 mt-1">
            All blocked and redacted requests
            {total > 0 && <span className="ml-1">({total} total)</span>}
          </p>
        </div>
      </div>

      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <ViolationFeed
          violations={data?.violations ?? []}
          loading={isLoading}
        />

        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-6 pt-4 border-t border-gray-100">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <span className="text-sm text-gray-500">
              Page {page + 1} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1.5 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
