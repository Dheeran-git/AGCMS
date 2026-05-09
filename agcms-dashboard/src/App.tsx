import { Routes, Route, Navigate } from 'react-router-dom';
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

function AuthenticatedRoutes() {
  return (
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
