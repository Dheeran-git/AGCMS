import { Link, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Sparkles, X } from 'lucide-react';
import { useState } from 'react';
import { fetchOnboardingState } from '../lib/api';
import { useAuthStore } from '../stores/auth';

const DISMISS_KEY = 'agcms.onboarding-banner.dismissed';

export function OnboardingBanner() {
  const token = useAuthStore((s) => s.token);
  const location = useLocation();
  const [dismissed, setDismissed] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.sessionStorage.getItem(DISMISS_KEY) === '1';
  });

  const { data } = useQuery({
    queryKey: ['onboarding-state'],
    queryFn: fetchOnboardingState,
    enabled: Boolean(token),
    staleTime: 60_000,
  });

  // Don't show on the onboarding page itself or when already done.
  if (!data || data.completed) return null;
  if (location.pathname === '/onboarding') return null;
  if (dismissed) return null;

  const stepCount = [
    data.state.tenant_profile,
    data.state.frameworks,
    data.state.policy_packs,
    data.state.first_call,
  ].filter(Boolean).length;

  return (
    <div className="border-b border-accent/30 bg-accent/10">
      <div className="max-w-[1400px] mx-auto px-8 py-2 flex items-center gap-3 text-caption">
        <Sparkles size={14} className="text-accent shrink-0" />
        <span className="text-fg-primary">
          Onboarding {stepCount}/4 complete.
        </span>
        <span className="text-fg-muted">
          Finish setup to unlock the full first-call walkthrough.
        </span>
        <Link
          to="/onboarding"
          className="ml-auto text-accent hover:text-accent-bright underline-offset-2 hover:underline"
        >
          Continue onboarding
        </Link>
        <button
          type="button"
          onClick={() => {
            window.sessionStorage.setItem(DISMISS_KEY, '1');
            setDismissed(true);
          }}
          className="text-fg-muted hover:text-fg-primary"
          aria-label="Dismiss"
        >
          <X size={14} />
        </button>
      </div>
    </div>
  );
}
