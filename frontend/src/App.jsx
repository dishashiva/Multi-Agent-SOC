import { useEffect, useState, useCallback } from 'react';
import { Routes, Route } from 'react-router-dom';
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
  '/':              'Dashboard',
  '/agents':        'Agent Status',
  '/logs':          'Live Logs',
  '/incidents':     'Incidents',
  '/notifications': 'Notifications',
  '/audit':         'Audit Log',
  '/health':        'AI Health',
  '/settings':      'Settings',
};

export default function App() {
  const [status, setStatus] = useState(null);
  const { wsConnected }     = useSoc();

  const refreshStatus = useCallback(async () => {
    try { setStatus(await api.status()); } catch { /* backend not running yet */ }
  }, []);

  useEffect(() => {
    refreshStatus();
    const t = setInterval(refreshStatus, 5000);
    return () => clearInterval(t);
  }, [refreshStatus]);

  const path = window.location.pathname;
  const pageTitle = PAGE_TITLES[path] || 'SOC-in-a-Box';

  return (
    <div className="app-layout">
      <Sidebar status={status} />

      <div className="main-content">
        {/* Topbar */}
        <header className="topbar">
          <span className="topbar-title">{pageTitle}</span>
          <div className="topbar-status">
            <span className={`status-dot ${status?.running ? 'running' : 'idle'}`} />
            <span>{status?.running ? `Engine Running · ${status.watch_path}` : 'Engine Stopped'}</span>
          </div>
          <div className="topbar-status" style={{ marginLeft: 16 }}>
            <span className={`status-dot ${wsConnected ? 'running' : 'idle'}`} />
            <span>{wsConnected ? 'Live' : 'Connecting…'}</span>
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
