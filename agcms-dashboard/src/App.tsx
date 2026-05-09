import { useEffect } from 'react';
import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AppLayout } from './components/AppLayout';
import { Overview } from './pages/Overview';
import { Violations } from './pages/Violations';
import { Playground } from './pages/Playground';
import { Users } from './pages/Users';
import { Policy } from './pages/Policy';
import { Audit } from './pages/Audit';
import { Alerts } from './pages/Alerts';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { PublicVerifier } from './pages/PublicVerifier';
import { SSOComplete } from './pages/SSOComplete';
import { Onboarding } from './pages/Onboarding';
import { TrustCenter } from './pages/TrustCenter';
import { fetchOnboardingState } from './lib/api';
import { useAuthStore } from './stores/auth';

function OnboardingGate({ children }: { children: JSX.Element }) {
  const location = useLocation();
  const navigate = useNavigate();
  const token = useAuthStore((s) => s.token);

  const { data } = useQuery({
    queryKey: ['onboarding-state'],
    queryFn: fetchOnboardingState,
    // Only probe when logged in; the endpoint requires auth.
    enabled: Boolean(token),
    // First-login routing is one-shot, don't hammer the API.
    staleTime: 60_000,
  });

  useEffect(() => {
    if (!data) return;
    if (!data.completed && location.pathname !== '/onboarding') {
      navigate('/onboarding', { replace: true });
    }
  }, [data, location.pathname, navigate]);

  return children;
}

function AuthenticatedRoutes() {
  return (
    <OnboardingGate>
      <AppLayout>
        <Routes>
          <Route path="/onboarding" element={<Onboarding />} />
          <Route path="/" element={<Overview />} />
          <Route path="/violations" element={<Violations />} />
          <Route path="/playground" element={<Playground />} />
          <Route path="/users" element={<Users />} />
          <Route path="/policy" element={<Policy />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/trust" element={<TrustCenter />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppLayout>
    </OnboardingGate>
  );
}

function App() {
  return (
    <Routes>
      <Route path="/trust/verify" element={<PublicVerifier />} />
      <Route path="/auth/sso/complete" element={<SSOComplete />} />
      <Route path="*" element={<AuthenticatedRoutes />} />
    </Routes>
  );
}

export default App;
