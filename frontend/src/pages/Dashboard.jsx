import { useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import { useSoc } from '../SocContext';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell,
} from 'recharts';

const SEV_COLORS = { CRITICAL: '#ff3b3b', HIGH: '#ff8c00', MEDIUM: '#ffd700', LOW: '#00d4ff', INFO: '#58a6ff' };

function formatUptime(s) {
  if (!s) return '—';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return `${h ? h + 'h ' : ''}${m ? m + 'm ' : ''}${sec}s`;
}

function Kpi({ label, value, sub, accent, icon }) {
  return (
    <div className={`kpi-card ${accent}`}>
      <div className="kpi-icon">{icon}</div>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value ?? '—'}</div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}

export default function Dashboard({ status }) {
  const { events, liveAlerts, notifications } = useSoc();
  const [stats, setStats]    = useState(null);
  const [chartData, setChartData] = useState([]);
  const [fixedIds, setFixedIds] = useState(new Set());
  const [starting, setStarting] = useState(false);
  const [fixingId, setFixingId] = useState(null);

  const load = useCallback(async () => {
    try { setStats(await api.auditStats()); } catch { /* ignore */ }
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, [load]);

  async function handleStart() {
    setStarting(true);
    try {
      await api.start({ watch_path: './logs' });
      window.location.reload();
    } catch (err) {
      alert('Failed to start engine: ' + err.message);
    } finally {
      setStarting(false);
    }
  }

  async function handleFix(id) {
    setFixingId(id);
    try {
      await api.fixIncident(id);
      setFixedIds(prev => new Set(prev).add(id));
    } catch (err) {
      alert('Failed to apply fix: ' + err.message);
    } finally {
      setFixingId(null);
    }
  }

  // Build event-timeline chart from live events
  useEffect(() => {
    const buckets = {};
    events.forEach(ev => {
      const t = new Date(ev.timestamp);
      const key = `${t.getHours()}:${String(t.getMinutes()).padStart(2, '0')}`;
      if (!buckets[key]) buckets[key] = { time: key, alerts: 0, actions: 0, normal: 0 };
      if (ev.type === 'ALERT')  buckets[key].alerts++;
      else if (ev.type === 'RESPONSE') buckets[key].actions++;
      else buckets[key].normal++;
    });
    setChartData(Object.values(buckets).slice(-20));
  }, [events]);

  const totalIncidents = stats?.by_agent?.RESPONDER ?? 0;
  const totalAlerts    = stats?.by_agent?.SENTRY     ?? 0;
  const running        = status?.running;
  const uptime         = formatUptime(status?.uptime_s);

  const sevData = Object.entries(stats?.by_severity ?? {}).map(([k, v]) => ({ name: k, count: v, color: SEV_COLORS[k] }));

  // High risk notifications needing fix
  const highRiskNotifs = notifications
    .map(n => n.data || n)
    .filter(n => n.incident_id && !fixedIds.has(n.incident_id));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Security Operations Dashboard</h2>
          <p>{running ? `Monitoring active · Uptime ${uptime}` : 'Engine is stopped — Click Start Engine below to begin live log monitoring'}</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {!running && (
            <button className="btn btn-primary" onClick={handleStart} disabled={starting}>
              {starting ? 'Starting…' : '▶ Start Engine'}
            </button>
          )}
          <span className={`status-dot ${running ? 'running' : 'idle'}`} />
          <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
            {running ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>
      </div>

      {/* High-Risk Action Required Banner */}
      {highRiskNotifs.length > 0 && (
        <div style={{
          background: 'rgba(255, 59, 59, 0.12)',
          border: '1px solid rgba(255, 59, 59, 0.4)',
          borderRadius: 8,
          padding: '16px 20px',
          marginBottom: 20,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <div style={{ color: '#ff3b3b', fontWeight: 600, fontSize: 15, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>🚨 HIGH RISK THREAT DETECTED</span>
              <span className="badge CRITICAL" style={{ fontSize: 10 }}>User Fix Required</span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-primary)', marginTop: 4 }}>
              Incident <strong>{highRiskNotifs[0].incident_id}</strong>: {highRiskNotifs[0].reason || highRiskNotifs[0].message || 'Privilege escalation / high risk action detected.'}
            </div>
          </div>
          <button
            className="btn btn-danger"
            style={{ padding: '8px 16px', fontSize: 13, flexShrink: 0 }}
            onClick={() => handleFix(highRiskNotifs[0].incident_id)}
            disabled={fixingId === highRiskNotifs[0].incident_id}
          >
            {fixingId === highRiskNotifs[0].incident_id ? 'Applying Fix…' : '🔧 Apply Fix Now'}
          </button>
        </div>
      )}

      {/* KPI Row */}
      <div className="kpi-grid">
        <Kpi label="Live Alerts" value={liveAlerts} sub="since page load" accent="crit" icon="🚨" />
        <Kpi label="Total Alerts" value={totalAlerts} sub="all time" accent="warn" icon="⚡" />
        <Kpi label="Incidents" value={totalIncidents} sub="investigations" accent="purple" icon="🔍" />
        <Kpi label="Uptime" value={running ? uptime : 'Offline'} sub="engine status" accent={running ? 'ok' : 'cyan'} icon="⏱️" />
        <Kpi label="Queue Depth" value={status ? (status.alert_queue + status.report_queue) : 0} sub="pending tasks" accent="cyan" icon="📦" />
        <Kpi label="Watch Path" value={status?.watch_path ? '✓ Active' : 'Not set'} sub={status?.watch_path || '—'} accent={status?.watch_path ? 'ok' : 'cyan'} icon="📁" />
      </div>

      {/* Activity Chart */}
      <div className="chart-card">
        <div className="card-title">Live Activity — Events per Minute</div>
        {chartData.length === 0 ? (
          <div className="empty-state" style={{ padding: 40 }}>
            <div className="empty-icon">📈</div>
            <div className="empty-text">Activity chart populates when the engine is running</div>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff3b3b" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ff3b3b" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gN" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(48,54,61,0.6)" />
              <XAxis dataKey="time" tick={{ fill: '#484f58', fontSize: 11 }} />
              <YAxis tick={{ fill: '#484f58', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#1c2330', border: '1px solid #30363d', borderRadius: 8, color: '#e6edf3' }}
                labelStyle={{ color: '#8b949e' }}
              />
              <Area type="monotone" dataKey="alerts" stroke="#ff3b3b" fill="url(#gA)" strokeWidth={2} name="Alerts" />
              <Area type="monotone" dataKey="normal" stroke="#00d4ff" fill="url(#gN)" strokeWidth={1.5} name="Normal" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Two-col row: severity breakdown + recent events */}
      <div className="section-grid two-col">
        <div className="card">
          <div className="card-title">Threats by Severity</div>
          {sevData.length === 0
            ? <div className="empty-state" style={{ padding: 30 }}><div className="empty-icon">🎯</div><div className="empty-text">No events yet</div></div>
            : (
            <ResponsiveContainer width="100%" height={180}>
              <BarChart data={sevData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(48,54,61,0.6)" />
                <XAxis dataKey="name" tick={{ fill: '#484f58', fontSize: 11 }} />
                <YAxis tick={{ fill: '#484f58', fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#1c2330', border: '1px solid #30363d', borderRadius: 8, color: '#e6edf3' }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {sevData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="card-title">Recent Live Events</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 220, overflowY: 'auto' }}>
            {events.slice(0, 12).map((ev, i) => (
              <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: 12, padding: '4px 0', borderBottom: '1px solid rgba(48,54,61,0.4)' }}>
                <span className={`badge ${ev.severity || 'INFO'}`} style={{ flexShrink: 0 }}>{ev.type}</span>
                <span style={{ color: 'var(--text-secondary)', flex: 1 }}>
                  {ev.data?.message || ev.data?.reason || ev.data?.alert_id || ev.type}
                </span>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 10, flexShrink: 0 }}>
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
            {events.length === 0 && (
              <div className="empty-state" style={{ padding: 20 }}>
                <div className="empty-text">Waiting for live events…</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
