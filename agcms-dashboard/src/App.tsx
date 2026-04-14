import { Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Overview } from './pages/Overview';
import { Violations } from './pages/Violations';
import { Playground } from './pages/Playground';
import { Users } from './pages/Users';
import { Policy } from './pages/Policy';
import { Audit } from './pages/Audit';
import { Alerts } from './pages/Alerts';
import { Reports } from './pages/Reports';
import { Settings } from './pages/Settings';
import { useDashboardStore } from './stores/dashboard';
import { cn } from './lib/cn';

function App() {
  const sidebarOpen = useDashboardStore((s) => s.sidebarOpen);
  const toggleSidebar = useDashboardStore((s) => s.toggleSidebar);

  return (
    <div className="min-h-screen bg-gray-50">
      <Sidebar />
      <div className={cn('transition-all duration-200', sidebarOpen ? 'ml-56' : 'ml-16')}>
        <header className="h-14 bg-white border-b border-gray-200 flex items-center justify-between px-6">
          <button
            onClick={toggleSidebar}
            className="p-1.5 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
            </svg>
          </button>
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
            System Healthy
          </span>
        </header>
        <main className="max-w-7xl mx-auto px-6 py-8">
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
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default App;
