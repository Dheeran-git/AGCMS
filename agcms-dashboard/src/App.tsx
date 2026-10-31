import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import { AppLayout } from './components/AppLayout';
import { SignIn } from './pages/SignIn';
import { useAuthStore } from './stores/auth';

// Each page is its own chunk, so the sign-in screen and the first page do not
// wait for every page's code (Recharts alone is several hundred kB).
const Overview = lazy(() => import('./pages/Overview').then((m) => ({ default: m.Overview })));
const Violations = lazy(() => import('./pages/Violations').then((m) => ({ default: m.Violations })));
const Playground = lazy(() => import('./pages/Playground').then((m) => ({ default: m.Playground })));
const Users = lazy(() => import('./pages/Users').then((m) => ({ default: m.Users })));
const Policy = lazy(() => import('./pages/Policy').then((m) => ({ default: m.Policy })));
const Audit = lazy(() => import('./pages/Audit').then((m) => ({ default: m.Audit })));
const Alerts = lazy(() => import('./pages/Alerts').then((m) => ({ default: m.Alerts })));
const Reports = lazy(() => import('./pages/Reports').then((m) => ({ default: m.Reports })));
const Settings = lazy(() => import('./pages/Settings').then((m) => ({ default: m.Settings })));

function App() {
  const signedIn = useAuthStore((s) => s.token !== null);
  if (!signedIn) return <SignIn />;

  return (
    <AppLayout>
      <Suspense fallback={<p className="text-sm text-fg-muted">Loading...</p>}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/violations" element={<Violations />} />
          <Route path="/playground" element={<Playground />} />
          <Route path="/users" element={<Users />} />
          <Route path="/policy" element={<Policy />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AppLayout>
  );
}

export default App;
