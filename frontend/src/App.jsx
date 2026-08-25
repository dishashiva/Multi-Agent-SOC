import { useEffect, useState, useCallback } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import Sidebar      from './Sidebar';
import { api }      from './api';
import { useSoc }   from './SocContext';

import Dashboard    from './pages/Dashboard';
import AgentStatus  from './pages/AgentStatus';
import LiveLogs     from './pages/LiveLogs';
import Incidents    from './pages/Incidents';
import Notifications from './pages/Notifications';
import AuditLog     from './pages/AuditLog';
import AiHealth     from './pages/AiHealth';
import Settings     from './pages/Settings';

const PAGE_TITLES = {
  '/':              'Dashboard Overview',
  '/agents':        'Agent Status & Pipeline',
  '/logs':          'Live Agent Logs',
  '/incidents':     'Incident Reports',
  '/notifications': 'Human Escalation Alerts',
  '/audit':         'System Audit Trail',
  '/health':        'AI Engine & API Health',
  '/settings':      'System Configuration',
};

export default function App() {
  const [status, setStatus] = useState(null);
  const { wsConnected }     = useSoc();
  const location            = useLocation();

  const refreshStatus = useCallback(async () => {
    try { setStatus(await api.status()); } catch { /* backend not running yet */ }
  }, []);

  useEffect(() => {
    refreshStatus();
    const t = setInterval(refreshStatus, 5000);
    return () => clearInterval(t);
  }, [refreshStatus]);

  const pageTitle = PAGE_TITLES[location.pathname] || 'SOC-in-a-Box';

  return (
    <div className="app-layout">
      <Sidebar status={status} />

      <div className="main-content">
        {/* Topbar */}
        <header className="topbar">
          <span className="topbar-title">{pageTitle}</span>
          <div className="topbar-status">
            <span className={`status-dot ${status?.running ? 'running' : 'idle'}`} />
            <span>{status?.running ? `Engine Active · ${status.watch_path}` : 'Engine Stopped'}</span>
          </div>
          <div className="topbar-status">
            <span className={`status-dot ${wsConnected ? 'running' : 'idle'}`} />
            <span>{wsConnected ? 'Live Feed Connected' : 'Feed Connecting…'}</span>
          </div>
        </header>

        {/* Pages */}
        <Routes>
          <Route path="/"              element={<Dashboard    status={status} />} />
          <Route path="/agents"        element={<AgentStatus  status={status} />} />
          <Route path="/logs"          element={<LiveLogs />} />
          <Route path="/incidents"     element={<Incidents />} />
          <Route path="/notifications" element={<Notifications />} />
          <Route path="/audit"         element={<AuditLog />} />
          <Route path="/health"        element={<AiHealth />} />
          <Route path="/settings"      element={<Settings status={status} onStatusChange={refreshStatus} />} />
        </Routes>
      </div>
    </div>
  );
}
