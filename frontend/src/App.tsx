import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { TopNav } from './components/TopNav';
import { Dashboard } from './pages/Dashboard';
import { AnomalyDetection } from './pages/AnomalyDetection';
import { Topology } from './pages/Topology';
import { PolicyAudit } from './pages/PolicyAudit';
import { ThreatIntel } from './pages/ThreatIntel';

function App() {
  return (
    <Router>
      <div className="flex h-screen w-screen overflow-hidden bg-background text-text-primary">
        <Sidebar />

        <div className="flex-1 flex flex-col min-w-0">
          <TopNav />

          <main className="flex-1 overflow-x-hidden overflow-y-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/anomaly-detection" element={<AnomalyDetection />} />
              <Route path="/topology" element={<Topology />} />
              <Route path="/audit" element={<PolicyAudit />} />
              <Route path="/threats" element={<ThreatIntel />} />
              <Route path="/settings" element={<div className="p-8">Settings View</div>} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
