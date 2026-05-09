import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  Terminal,
  FileText,
  ScrollText,
  Bell,
  Users as UsersIcon,
  BarChart3,
  Settings as SettingsIcon,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '../lib/cn';
import { useDashboardStore } from '../stores/dashboard';
import { LogoMark } from './LogoMark';

type NavItem = { path: string; label: string; icon: LucideIcon };

const NAV_SECTIONS: { label: string; items: NavItem[] }[] = [
  {
    label: 'Monitoring',
    items: [
      { path: '/', label: 'Overview', icon: LayoutDashboard },
      { path: '/violations', label: 'Violations', icon: ShieldAlert },
      { path: '/playground', label: 'Playground', icon: Terminal },
    ],
  },
  {
    label: 'Governance',
    items: [
      { path: '/policy', label: 'Policy', icon: FileText },
      { path: '/audit', label: 'Audit', icon: ScrollText },
      { path: '/alerts', label: 'Alerts', icon: Bell },
      { path: '/trust', label: 'Trust Center', icon: ShieldCheck },
    ],
  },
  {
    label: 'Management',
    items: [
      { path: '/users', label: 'Users', icon: UsersIcon },
      { path: '/reports', label: 'Reports', icon: BarChart3 },
      { path: '/settings', label: 'Settings', icon: SettingsIcon },
    ],
  },
];

function isActive(pathname: string, path: string) {
  return path === '/' ? pathname === '/' : pathname.startsWith(path);
}

export function Sidebar() {
  const location = useLocation();
  const sidebarOpen = useDashboardStore((s) => s.sidebarOpen);

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 h-screen bg-panel border-r border-border-subtle text-fg-primary',
        'transition-[width] duration-200 ease-out z-30 flex flex-col',
        sidebarOpen ? 'w-60' : 'w-[60px]'
      )}
    >
      {/* Logomark */}
      <div className="flex items-center h-14 px-4 border-b border-border-subtle">
        <LogoMark size={26} />
        {sidebarOpen && (
          <div className="ml-2.5 flex flex-col leading-tight">
            <span className="text-caption font-[590] tracking-[-0.01em] text-fg-primary">
              AGCMS
            </span>
            <span className="text-micro text-fg-subtle">AI governance</span>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-5">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} className="space-y-0.5">
            {sidebarOpen && (
              <div className="px-2.5 pb-1.5 text-micro uppercase tracking-wider text-fg-subtle">
                {section.label}
              </div>
            )}
            {section.items.map((item) => {
              const active = isActive(location.pathname, item.path);
              const Icon = item.icon;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  title={!sidebarOpen ? item.label : undefined}
                  className={cn(
                    'group relative flex items-center gap-2.5 px-2.5 py-1.5 rounded-md text-caption transition-colors',
                    active
                      ? 'bg-translucent-2 text-fg-primary'
                      : 'text-fg-muted hover:text-fg-primary hover:bg-translucent-1'
                  )}
                >
                  {active && (
                    <span
                      className="absolute left-0 top-1 bottom-1 w-[2px] rounded-r-full bg-accent-bright"
                      aria-hidden="true"
                    />
                  )}
                  <Icon
                    className={cn(
                      'h-4 w-4 shrink-0 transition-colors',
                      active ? 'text-accent-bright' : 'text-fg-muted group-hover:text-fg-primary'
                    )}
                  />
                  {sidebarOpen && <span className="truncate">{item.label}</span>}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer — version / env */}
      {sidebarOpen && (
        <div className="px-3 py-3 border-t border-border-subtle text-micro text-fg-subtle flex items-center justify-between">
          <span className="font-mono">v1.0.0</span>
          <span className="inline-flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-status-success animate-pulse-dot" />
            live
          </span>
        </div>
      )}
    </aside>
  );
}
