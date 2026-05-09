import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
  type LucideIcon,
} from 'lucide-react';
import { Dialog, DialogPortal, DialogOverlay } from './ui/dialog';
import * as DialogPrimitive from '@radix-ui/react-dialog';
import {
  Command,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandShortcut,
} from './ui/command';
import { cn } from '../lib/cn';

type NavEntry = { path: string; label: string; icon: LucideIcon; hint?: string };

const NAV: { heading: string; entries: NavEntry[] }[] = [
  {
    heading: 'Monitoring',
    entries: [
      { path: '/', label: 'Overview', icon: LayoutDashboard, hint: 'Real-time stats and charts' },
      { path: '/violations', label: 'Violations', icon: ShieldAlert, hint: 'Blocked & flagged requests' },
      { path: '/playground', label: 'Playground', icon: Terminal, hint: 'Interactive LLM tester' },
    ],
  },
  {
    heading: 'Governance',
    entries: [
      { path: '/policy', label: 'Policy', icon: FileText, hint: 'Edit tenant policy' },
      { path: '/audit', label: 'Audit log', icon: ScrollText, hint: 'HMAC-signed event log' },
      { path: '/alerts', label: 'Alerts', icon: Bell, hint: 'Active escalations' },
    ],
  },
  {
    heading: 'Management',
    entries: [
      { path: '/users', label: 'Users', icon: UsersIcon },
      { path: '/reports', label: 'Reports', icon: BarChart3, hint: 'GDPR · EU AI Act' },
      { path: '/settings', label: 'Settings', icon: SettingsIcon },
    ],
  },
];

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const navigate = useNavigate();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogPortal>
        <DialogOverlay />
        <DialogPrimitive.Content
          className={cn(
            'fixed left-1/2 top-[15vh] z-50 -translate-x-1/2',
            'w-full max-w-[580px] bg-surface border border-border rounded-xl shadow-elev-5',
            'overflow-hidden animate-fade-in focus:outline-none'
          )}
        >
          <DialogPrimitive.Title className="sr-only">Command palette</DialogPrimitive.Title>
          <Command>
            <CommandInput placeholder="Jump to page, search violations, audit events…" />
            <CommandList>
              <CommandEmpty>No results.</CommandEmpty>
              {NAV.map((section) => (
                <CommandGroup key={section.heading} heading={section.heading}>
                  {section.entries.map((entry) => {
                    const Icon = entry.icon;
                    return (
                      <CommandItem
                        key={entry.path}
                        onSelect={() => {
                          navigate(entry.path);
                          onOpenChange(false);
                        }}
                      >
                        <Icon className="h-4 w-4 text-fg-muted shrink-0" />
                        <span className="text-fg-primary">{entry.label}</span>
                        {entry.hint && (
                          <span className="text-fg-muted text-label">— {entry.hint}</span>
                        )}
                        <CommandShortcut>↵</CommandShortcut>
                      </CommandItem>
                    );
                  })}
                </CommandGroup>
              ))}
            </CommandList>
          </Command>
        </DialogPrimitive.Content>
      </DialogPortal>
    </Dialog>
  );
}

// Hook to bind Cmd+K / Ctrl+K globally
export function useCommandPalette() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.key === 'k' || e.key === 'K') && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return { open, setOpen };
}
