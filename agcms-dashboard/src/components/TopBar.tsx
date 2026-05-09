import { useLocation } from 'react-router-dom';
import { Menu, Search, User } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { Button } from './ui/button';
import { Kbd } from './ui/kbd';
import { StatusDot } from './ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './ui/dropdown-menu';
import { useDashboardStore } from '../stores/dashboard';
import { fetchStats } from '../lib/api';

const PAGE_TITLES: Record<string, string> = {
  '/': 'Overview',
  '/violations': 'Violations',
  '/playground': 'Playground',
  '/users': 'Users',
  '/policy': 'Policy',
  '/audit': 'Audit log',
  '/alerts': 'Alerts',
  '/reports': 'Reports',
  '/settings': 'Settings',
};

export function TopBar({ onOpenPalette }: { onOpenPalette: () => void }) {
  const location = useLocation();
  const toggleSidebar = useDashboardStore((s) => s.toggleSidebar);
  const title =
    PAGE_TITLES[location.pathname] ??
    Object.entries(PAGE_TITLES).find(([p]) => p !== '/' && location.pathname.startsWith(p))?.[1] ??
    'AGCMS';

  const { data: stats, isError } = useQuery({
    queryKey: ['topbar-stats'],
    queryFn: fetchStats,
    refetchInterval: 15000,
    staleTime: 10000,
  });

  const isHealthy = !isError;

  const isMac = typeof navigator !== 'undefined' && /Mac/.test(navigator.platform);

  return (
    <header className="sticky top-0 z-20 h-14 bg-panel/80 backdrop-blur-md border-b border-border-subtle">
      <div className="h-full flex items-center gap-3 px-5">
        <Button
          variant="bare"
          size="icon-sm"
          onClick={toggleSidebar}
          aria-label="Toggle sidebar"
          className="text-fg-muted hover:text-fg-primary"
        >
          <Menu className="h-4 w-4" />
        </Button>

        <div className="flex items-center gap-2">
          <span className="text-caption text-fg-primary">{title}</span>
        </div>

        <div className="flex-1" />

        {/* Command palette trigger */}
        <button
          onClick={onOpenPalette}
          className="group flex items-center gap-2 h-8 px-3 rounded-md bg-translucent-1 border border-border hover:bg-translucent-2 hover:border-border-strong transition-colors min-w-[240px]"
        >
          <Search className="h-3.5 w-3.5 text-fg-muted group-hover:text-fg-secondary" />
          <span className="text-label text-fg-muted group-hover:text-fg-secondary">
            Search or jump to…
          </span>
          <div className="ml-auto flex items-center gap-0.5">
            <Kbd>{isMac ? '⌘' : 'Ctrl'}</Kbd>
            <Kbd>K</Kbd>
          </div>
        </button>

        {/* System health */}
        <div className="hidden md:inline-flex items-center gap-2 h-8 px-2.5 rounded-md bg-translucent-1 border border-border-subtle">
          <StatusDot tone={isHealthy ? 'success' : 'danger'} pulsing />
          <span className="text-label text-fg-secondary">
            {isHealthy ? 'Healthy' : 'Degraded'}
          </span>
          {typeof stats?.total_requests === 'number' && (
            <span className="text-label text-fg-subtle font-mono">
              · {stats.total_requests.toLocaleString()} req
            </span>
          )}
        </div>

        {/* User menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="icon" size="icon-sm" aria-label="Account">
              <User className="h-3.5 w-3.5" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-[200px]">
            <DropdownMenuLabel>Signed in</DropdownMenuLabel>
            <DropdownMenuItem>
              <span className="text-fg-primary">admin@agcms</span>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem>Documentation</DropdownMenuItem>
            <DropdownMenuItem>Keyboard shortcuts</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-status-danger focus:text-status-danger">
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
