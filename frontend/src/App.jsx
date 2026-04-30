import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Sidebar   from './components/layout/Sidebar';
import Navbar    from './components/layout/Navbar';
import Login     from './pages/Login';
import Dashboard          from './pages/Dashboard';
import Topology           from './pages/Topology';
import PolicyAudit        from './pages/PolicyAudit';
import ThreatIntelligence from './pages/ThreatIntelligence';
import Settings           from './pages/Settings';

/* ── Protected layout — only renders when logged in ── */
function AppLayout() {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;

  return (
    <div className="app-layout">
      <Sidebar />
      <div className="main-content">
        <Navbar />
        <main className="page-body">
          <Routes>
            <Route path="/"             element={<Dashboard />} />
            <Route path="/topology"     element={<Topology />} />
            <Route path="/policy-audit" element={<PolicyAudit />} />
            <Route path="/threats"      element={<ThreatIntelligence />} />
            <Route path="/settings"     element={<Settings />} />
            {/* Any unknown path goes back to dashboard */}
            <Route path="*"             element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

/* ── Login route — redirect to dashboard if already in ── */
function LoginRoute() {
  const { user } = useAuth();
  if (user) return <Navigate to="/" replace />;
  return <Login />;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginRoute />} />
          <Route path="/*"    element={<AppLayout />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
