import { NavLink, useLocation } from 'react-router-dom';
import { useSoc } from './SocContext';

const NAV = [
  { to: '/',            icon: '⬡',  label: 'Dashboard' },
  { to: '/agents',      icon: '🤖', label: 'Agent Status' },
  { to: '/logs',        icon: '📋', label: 'Live Logs' },
  { to: '/incidents',   icon: '🚨', label: 'Incidents' },
  { to: '/notifications', icon: '🔔', label: 'Notifications', badge: true },
  { to: '/audit',       icon: '🗂️', label: 'Audit Log' },
  { to: '/health',      icon: '💡', label: 'AI Health' },
  { to: '/settings',    icon: '⚙️', label: 'Settings' },
];

export default function Sidebar({ status }) {
  const { wsConnected, notifications } = useSoc();
  const unread = notifications.filter(n => !n._read).length;

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <h1>SOC-in-a-Box</h1>
        <div className="logo-sub">v2.0 · Multi-Agent SOC</div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Monitoring</div>
        {NAV.slice(0, 4).map(n => (
          <NavLink key={n.to} to={n.to} end={n.to === '/'} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
            <span className="nav-icon">{n.icon}</span>
            {n.label}
          </NavLink>
        ))}

        <div className="nav-section-label" style={{ marginTop: 8 }}>Management</div>
        {NAV.slice(4).map(n => (
          <NavLink key={n.to} to={n.to} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
            <span className="nav-icon">{n.icon}</span>
            {n.label}
            {n.badge && unread > 0 && <span className="nav-badge">{unread}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)' }}>
          <span className={`status-dot ${wsConnected ? 'running' : 'idle'}`} />
          {wsConnected ? 'Live stream active' : 'Connecting…'}
        </div>
        {status?.watch_path && (
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
            📁 {status.watch_path}
          </div>
        )}
      </div>
    </aside>
  );
}
