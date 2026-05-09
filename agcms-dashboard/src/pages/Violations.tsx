import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { fetchViolations } from '../lib/api';
import { ViolationFeed } from '../components/ViolationFeed';
import { Card, CardContent, CardFooter } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';

const PAGE_SIZE = 20;

export function Violations() {
  const [page, setPage] = useState(0);

  const { data, isLoading } = useQuery({
    queryKey: ['violations', page],
    queryFn: () => fetchViolations(PAGE_SIZE, page * PAGE_SIZE),
    refetchInterval: 15_000,
  });

  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-h1 text-fg-primary">Violations</h1>
          <p className="mt-1 text-small text-fg-muted">
            All blocked and redacted requests.
          </p>
        </div>
        {total > 0 && <Badge variant="subtle">{total.toLocaleString()} total</Badge>}
      </header>

      <Card>
        <CardContent>
          <ViolationFeed violations={data?.violations ?? []} loading={isLoading} />
        </CardContent>
        {totalPages > 1 && (
          <CardFooter className="justify-between">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              <ChevronLeft className="h-3.5 w-3.5" />
              Previous
            </Button>
            <span className="text-label text-fg-muted font-mono">
              Page {page + 1} of {totalPages}
            </span>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
            >
              Next
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </CardFooter>
        )}
      </Card>
    </div>
  );
}
