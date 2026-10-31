import { Routes, Route, Navigate } from 'react-router';
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
import { SignIn } from './pages/SignIn';
import { useAuthStore } from './stores/auth';

function App() {
  const signedIn = useAuthStore((s) => s.token !== null);
  if (!signedIn) return <SignIn />;

  return (
    <AppLayout>
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
    </AppLayout>
  );
}

export default App;
