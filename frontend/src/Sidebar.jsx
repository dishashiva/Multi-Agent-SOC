import { NavLink } from 'react-router-dom';
import { useSoc } from './SocContext';
import {
  Shield,
  LayoutDashboard,
  Cpu,
  Terminal,
  AlertTriangle,
  Bell,
  History,
  HeartPulse,
  Settings,
  Folder,
} from './components/Icons';

const NAV = [
  { to: '/',              IconComponent: LayoutDashboard, label: 'Dashboard' },
  { to: '/agents',        IconComponent: Cpu,             label: 'Agent Status' },
  { to: '/logs',          IconComponent: Terminal,        label: 'Live Logs' },
  { to: '/incidents',     IconComponent: AlertTriangle,   label: 'Incidents' },
  { to: '/notifications', IconComponent: Bell,            label: 'Notifications', badge: true },
  { to: '/audit',         IconComponent: History,         label: 'Audit Log' },
  { to: '/health',        IconComponent: HeartPulse,      label: 'AI Health' },
  { to: '/settings',      IconComponent: Settings,        label: 'Settings' },
];

export default function Sidebar({ status }) {
  const { wsConnected, notifications } = useSoc();
  const unread = notifications.filter(n => !n._read).length;

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon-wrap">
          <Shield size={20} />
        </div>
        <div>
          <h1>SOC-in-a-Box</h1>
          <div className="logo-sub">Autonomous AI SOC</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Monitoring</div>
        {NAV.slice(0, 4).map(n => {
          const ItemIcon = n.IconComponent;
          return (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <span className="nav-icon">
                <ItemIcon size={16} />
              </span>
              {n.label}
            </NavLink>
          );
        })}

        <div className="nav-section-label" style={{ marginTop: 8 }}>Management</div>
        {NAV.slice(4).map(n => {
          const ItemIcon = n.IconComponent;
          return (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <span className="nav-icon">
                <ItemIcon size={16} />
              </span>
              {n.label}
              {n.badge && unread > 0 && <span className="nav-badge">{unread}</span>}
            </NavLink>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
          <span className={`status-dot ${wsConnected ? 'running' : 'idle'}`} />
          <span>{wsConnected ? 'Live stream active' : 'Connecting stream…'}</span>
        </div>
        {status?.watch_path && (
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', wordBreak: 'break-all', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Folder size={12} />
            <span>{status.watch_path}</span>
          </div>
        )}
      </div>
    </aside>
  );
}
