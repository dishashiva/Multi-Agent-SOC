import { useEffect, useState, useCallback } from 'react';
import { api } from '../api';

function HealthItem({ icon, label, value, cls }) {
  return (
    <div className="health-item">
      <span className="health-icon">{icon}</span>
      <div>
        <div className="health-label">{label}</div>
        <div className={`health-value ${cls || ''}`}>{value ?? '—'}</div>
      </div>
    </div>
  );
}

export default function AiHealth() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState(null);

  const check = useCallback(async () => {
    setLoading(true);
    try {
      const h = await api.health();
      setHealth(h);
      setLastChecked(new Date().toLocaleTimeString());
    } catch {
      setHealth(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { check(); const t = setInterval(check, 30000); return () => clearInterval(t); }, [check]);

  const nim   = health?.nim_reachable;
  const lat   = health?.nim_latency_ms;
  const email = health?.email_configured;
  const eng   = health?.engine_running;

  function uptime(s) {
    if (!s) return '—';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return `${h}h ${m}m`;
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>AI Health</h2>
          <p>NVIDIA NIM connectivity, model status, and system health</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {lastChecked && <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Last checked {lastChecked}</span>}
          <button className="btn btn-secondary" onClick={check} disabled={loading}>
            {loading ? <span className="spinner" /> : '↻ Check Now'}
          </button>
        </div>
      </div>

      {/* Overall health banner */}
      <div style={{
        background: nim ? 'var(--ok-dim)' : 'var(--critical-dim)',
        border: `1px solid ${nim ? 'rgba(63,185,80,0.3)' : 'rgba(255,59,59,0.3)'}`,
        borderRadius: 'var(--radius-lg)',
        padding: '16px 24px',
        marginBottom: 24,
        display: 'flex',
        alignItems: 'center',
        gap: 14,
      }}>
        <span style={{ fontSize: 32 }}>{nim ? '✅' : '❌'}</span>
        <div>
          <div style={{ fontWeight: 700, color: nim ? 'var(--ok)' : 'var(--critical)', fontSize: 16 }}>
            {nim ? 'AI System Operational' : 'AI System Unreachable'}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
            {nim
              ? `NVIDIA NIM is reachable (${lat}ms). Model: ${health?.model}`
              : 'Cannot connect to NVIDIA NIM API. Agents will use rule-based fallback.'}
          </div>
        </div>
      </div>

      <div className="health-grid">
        <HealthItem icon="🌐" label="NIM API Status"   value={nim ? `Online (${lat}ms)` : 'Offline'}    cls={nim ? 'ok' : 'err'} />
        <HealthItem icon="🤖" label="Model"            value={health?.model || '—'}                      cls="" />
        <HealthItem icon="⚡" label="Engine"           value={eng ? 'Running' : 'Stopped'}               cls={eng ? 'ok' : 'warn'} />
        <HealthItem icon="⏱️" label="Uptime"           value={uptime(health?.uptime_s)}                  cls="" />
        <HealthItem icon="📧" label="Email Alerts"     value={email ? 'Configured' : 'Not configured'}   cls={email ? 'ok' : 'warn'} />
        <HealthItem icon="🕐" label="Last Checked"     value={lastChecked || '—'}                        cls="" />
      </div>

      {!email && (
        <div style={{ marginTop: 24, background: 'var(--high-dim)', border: '1px solid rgba(255,140,0,0.3)', borderRadius: 'var(--radius-lg)', padding: '16px 24px' }}>
          <strong style={{ color: 'var(--high)' }}>⚠ Email Not Configured</strong>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 6 }}>
            Add <code>SMTP_HOST</code>, <code>SMTP_USER</code>, <code>SMTP_PASS</code>, and <code>NOTIFY_EMAIL</code> to your <code>.env</code> file to enable email alerts for critical incidents.
          </p>
        </div>
      )}

      <div style={{ marginTop: 24 }}>
        <div className="card-title" style={{ marginBottom: 12 }}>LLM Model Configuration</div>
        <div className="card">
          <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '10px 0', fontSize: 13 }}>
            {[
              ['Provider',    'NVIDIA NIM (hosted)'],
              ['Base URL',    'https://integrate.api.nvidia.com/v1'],
              ['Model',       health?.model || '—'],
              ['Auth',        'Bearer Token (NVIDIA_API_KEY)'],
              ['Mode',        'Simulation (no real commands)'],
              ['Fallback',    'Rule-based regex engine'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>{k}</span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
