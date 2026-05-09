import { type ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { Toaster } from 'sonner';
import { TooltipProvider } from './ui/tooltip';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { CommandPalette, useCommandPalette } from './CommandPalette';
import { OnboardingBanner } from './OnboardingBanner';
import { useDashboardStore } from '../stores/dashboard';
import { cn } from '../lib/cn';

export function AppLayout({ children }: { children: ReactNode }) {
  const sidebarOpen = useDashboardStore((s) => s.sidebarOpen);
  const palette = useCommandPalette();
  const location = useLocation();

  return (
    <TooltipProvider delayDuration={200}>
      <div className="min-h-screen bg-canvas text-fg-primary">
        <Sidebar />
        <div
          className={cn(
            'transition-[padding] duration-200 ease-out',
            sidebarOpen ? 'pl-60' : 'pl-[60px]'
          )}
        >
          <TopBar onOpenPalette={() => palette.setOpen(true)} />
          <OnboardingBanner />
          {/* keyed on pathname so the 320ms page-enter fires on every route change */}
          <main
            key={location.pathname}
            className="max-w-[1400px] mx-auto px-8 py-8 animate-fade-in"
          >
            {children}
          </main>
        </div>

        <CommandPalette open={palette.open} onOpenChange={palette.setOpen} />

        <Toaster
          position="bottom-right"
          theme="dark"
          toastOptions={{
            classNames: {
              toast: 'bg-surface border border-border text-fg-primary shadow-elev-5',
              title: 'text-caption text-fg-primary',
              description: 'text-label text-fg-muted',
            },
          }}
        />
      </div>
    </TooltipProvider>
  );
}
