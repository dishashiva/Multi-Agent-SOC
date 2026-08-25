import { useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import { useSoc } from '../SocContext';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell,
} from 'recharts';
import {
  AlertTriangle,
  Zap,
  Search,
  Clock,
  Layers,
  Folder,
  Play,
  Wrench,
  TrendingUp,
  Target,
  Radio,
  CheckCircle2,
} from '../components/Icons';

const SEV_COLORS = {
  CRITICAL: '#dc2626',
  HIGH:     '#ea580c',
  MEDIUM:   '#d97706',
  LOW:      '#0284c7',
  INFO:     '#2563eb',
};

function formatUptime(s) {
  if (!s) return '—';
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return `${h ? h + 'h ' : ''}${m ? m + 'm ' : ''}${sec}s`;
}

function Kpi({ label, value, sub, accent, IconComponent }) {
  return (
    <div className={`kpi-card ${accent}`}>
      {IconComponent && (
        <div className="kpi-icon">
          <IconComponent size={26} />
        </div>
      )}
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

  const sevData = Object.entries(stats?.by_severity ?? {}).map(([k, v]) => ({ name: k, count: v, color: SEV_COLORS[k] || '#64748b' }));

  // High risk notifications needing fix
  const highRiskNotifs = notifications
    .map(n => n.data || n)
    .filter(n => n.incident_id && !fixedIds.has(n.incident_id));

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Security Operations Dashboard</h2>
          <p>{running ? `Active monitoring in progress · Engine Uptime: ${uptime}` : 'Engine is stopped — Start the monitoring engine to process log streams'}</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {!running && (
            <button className="btn btn-primary" onClick={handleStart} disabled={starting}>
              {starting ? (
                <>
                  <span className="spinner" style={{ borderTopColor: '#ffffff' }} />
                  Starting…
                </>
              ) : (
                <>
                  <Play size={14} />
                  Start Engine
                </>
              )}
            </button>
          )}
          <span className={`status-dot ${running ? 'running' : 'idle'}`} />
          <span style={{ fontSize: 13, fontWeight: 600, color: running ? 'var(--ok)' : 'var(--text-muted)' }}>
            {running ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>
      </div>

      {/* High-Risk Action Required Banner */}
      {highRiskNotifs.length > 0 && (
        <div style={{
          background: 'var(--critical-dim)',
          border: '1px solid var(--critical-border)',
          borderRadius: 'var(--radius-lg)',
          padding: '16px 20px',
          marginBottom: 20,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 16,
          boxShadow: 'var(--shadow-xs)',
        }}>
          <div>
            <div style={{ color: 'var(--critical)', fontWeight: 700, fontSize: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={18} />
              <span>HIGH RISK THREAT DETECTED</span>
              <span className="badge CRITICAL" style={{ fontSize: 10 }}>User Fix Required</span>
            </div>
            <div style={{ fontSize: 13, color: 'var(--text-primary)', marginTop: 4 }}>
              Incident <strong>{highRiskNotifs[0].incident_id}</strong>: {highRiskNotifs[0].reason || highRiskNotifs[0].message || 'Privilege escalation or high risk action detected.'}
            </div>
          </div>
          <button
            className="btn btn-danger"
            style={{ padding: '8px 16px', fontSize: 13, flexShrink: 0 }}
            onClick={() => handleFix(highRiskNotifs[0].incident_id)}
            disabled={fixingId === highRiskNotifs[0].incident_id}
          >
            {fixingId === highRiskNotifs[0].incident_id ? (
              <>
                <span className="spinner" style={{ borderTopColor: '#ffffff' }} />
                Applying Fix…
              </>
            ) : (
              <>
                <Wrench size={14} />
                Apply Fix Now
              </>
            )}
          </button>
        </div>
      )}

      {/* KPI Row */}
      <div className="kpi-grid">
        <Kpi label="Live Alerts" value={liveAlerts} sub="since session start" accent="crit" IconComponent={AlertTriangle} />
        <Kpi label="Total Alerts" value={totalAlerts} sub="historical total" accent="warn" IconComponent={Zap} />
        <Kpi label="Incidents" value={totalIncidents} sub="analyzed reports" accent="purple" IconComponent={Search} />
        <Kpi label="Uptime" value={running ? uptime : 'Offline'} sub="engine status" accent={running ? 'ok' : 'cyan'} IconComponent={Clock} />
        <Kpi label="Queue Depth" value={status ? (status.alert_queue + status.report_queue) : 0} sub="pending queue tasks" accent="cyan" IconComponent={Layers} />
        <Kpi label="Watch Path" value={status?.watch_path ? 'Active' : 'Not set'} sub={status?.watch_path || '—'} accent={status?.watch_path ? 'ok' : 'cyan'} IconComponent={Folder} />
      </div>

      {/* Activity Chart */}
      <div className="chart-card">
        <div className="card-title">
          <TrendingUp size={16} />
          Live Activity — Events per Minute
        </div>
        {chartData.length === 0 ? (
          <div className="empty-state" style={{ padding: 36 }}>
            <div className="empty-icon">
              <TrendingUp size={22} />
            </div>
            <div className="empty-text">Activity metrics populate automatically when the engine is actively monitoring log files</div>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={chartData} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#dc2626" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#dc2626" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="gN" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#2563eb" stopOpacity={0.15} />
                  <stop offset="95%" stopColor="#2563eb" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#cbd5e1' }} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#cbd5e1' }} />
              <Tooltip
                contentStyle={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: 8, color: '#0f172a', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.08)' }}
                labelStyle={{ color: '#64748b', fontWeight: 600 }}
              />
              <Area type="monotone" dataKey="alerts" stroke="#dc2626" fill="url(#gA)" strokeWidth={2} name="Threat Alerts" />
              <Area type="monotone" dataKey="normal" stroke="#2563eb" fill="url(#gN)" strokeWidth={1.5} name="Normal Events" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Two-col row: severity breakdown + recent events */}
      <div className="section-grid two-col">
        <div className="card">
          <div className="card-title">
            <Target size={16} />
            Threats by Severity
          </div>
          {sevData.length === 0 ? (
            <div className="empty-state" style={{ padding: 28 }}>
              <div className="empty-icon">
                <Target size={22} />
              </div>
              <div className="empty-text">No threat classifications recorded yet</div>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={190}>
              <BarChart data={sevData} margin={{ top: 8, right: 12, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#cbd5e1' }} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={{ stroke: '#cbd5e1' }} />
                <Tooltip
                  contentStyle={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: 8, color: '#0f172a', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.08)' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {sevData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="card-title">
            <Radio size={16} />
            Recent Live Events
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 220, overflowY: 'auto' }}>
            {events.slice(0, 12).map((ev, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  gap: 10,
                  alignItems: 'center',
                  fontSize: 12.5,
                  padding: '6px 4px',
                  borderBottom: '1px solid var(--border)',
                }}
              >
                <span className={`badge ${ev.severity || 'INFO'}`} style={{ flexShrink: 0 }}>
                  {ev.type}
                </span>
                <span style={{ color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {ev.data?.message || ev.data?.reason || ev.data?.alert_id || ev.type}
                </span>
                <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0 }}>
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
            {events.length === 0 && (
              <div className="empty-state" style={{ padding: 24 }}>
                <div className="empty-text">Awaiting real-time pipeline events…</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
