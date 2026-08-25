import { useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import {
  Globe,
  Cpu,
  Zap,
  Clock,
  Mail,
  Calendar,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Sparkles,
  Bot,
} from '../components/Icons';

function HealthItem({ IconComponent, label, value, cls }) {
  return (
    <div className="health-item">
      <div className="health-icon-wrap">
        <IconComponent size={18} />
      </div>
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

  useEffect(() => {
    check();
    const t = setInterval(check, 30000);
    return () => clearInterval(t);
  }, [check]);

  const nim     = health?.nim_reachable;
  const hasKey  = health?.has_api_key;
  const lat     = health?.nim_latency_ms;
  const email   = health?.email_configured;
  const eng     = health?.engine_running;

  function uptime(s) {
    if (!s) return '—';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return `${h}h ${m}m`;
  }

  // Determine banner state
  let bannerBg = 'var(--primary-dim)';
  let bannerBorder = 'var(--primary-border)';
  let bannerColor = 'var(--primary)';
  let bannerIcon = <Bot size={28} />;
  let bannerTitle = 'Autonomous Local Heuristic Engine Active';
  let bannerDesc = 'Running offline in local rule-based detection mode. All threat triage, investigations, and response actions are fully functional locally.';

  if (nim) {
    bannerBg = 'var(--ok-dim)';
    bannerBorder = 'var(--ok-border)';
    bannerColor = 'var(--ok)';
    bannerIcon = <CheckCircle2 size={28} />;
    bannerTitle = 'NVIDIA NIM Inference Operational';
    bannerDesc = `Connected to NVIDIA NIM (${lat}ms). Active primary model: ${health?.model}`;
  } else if (hasKey) {
    bannerBg = 'var(--critical-dim)';
    bannerBorder = 'var(--critical-border)';
    bannerColor = 'var(--critical)';
    bannerIcon = <XCircle size={28} />;
    bannerTitle = 'NVIDIA NIM Authentication / Connection Issue';
    bannerDesc = 'Provided NVIDIA API key was unauthorized or endpoint was unreachable. Pipeline is operating safely in offline rule-based fallback mode.';
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>AI Engine & API Health</h2>
          <p>NVIDIA NIM connectivity, LLM inference latency, and system dependencies</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {lastChecked && <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Last checked {lastChecked}</span>}
          <button className="btn btn-secondary" onClick={check} disabled={loading}>
            {loading ? <span className="spinner" /> : <RefreshCw size={14} />}
            Check Now
          </button>
        </div>
      </div>

      {/* Overall health banner */}
      <div
        style={{
          background: bannerBg,
          border: `1px solid ${bannerBorder}`,
          borderRadius: 'var(--radius-lg)',
          padding: '16px 20px',
          marginBottom: 24,
          display: 'flex',
          alignItems: 'center',
          gap: 14,
          boxShadow: 'var(--shadow-xs)',
        }}
      >
        <div style={{ color: bannerColor, display: 'flex', alignItems: 'center' }}>
          {bannerIcon}
        </div>
        <div>
          <div style={{ fontWeight: 700, color: bannerColor, fontSize: 15 }}>
            {bannerTitle}
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2 }}>
            {bannerDesc}
          </div>
        </div>
      </div>

      <div className="health-grid">
        <HealthItem
          IconComponent={Globe}
          label="NIM API Status"
          value={nim ? `Online (${lat}ms)` : hasKey ? 'Auth Failed' : 'Offline (Local)'}
          cls={nim ? 'ok' : hasKey ? 'err' : 'ok'}
        />
        <HealthItem IconComponent={Cpu} label="Inference Model" value={health?.model || '—'} cls="" />
        <HealthItem IconComponent={Zap} label="Engine State" value={eng ? 'Running' : 'Stopped'} cls={eng ? 'ok' : 'warn'} />
        <HealthItem IconComponent={Clock} label="Engine Uptime" value={uptime(health?.uptime_s)} cls="" />
        <HealthItem IconComponent={Mail} label="Email Alerts" value={email ? 'Configured' : 'Not Configured'} cls={email ? 'ok' : 'warn'} />
        <HealthItem IconComponent={Calendar} label="Last Verified" value={lastChecked || '—'} cls="" />
      </div>

      {!hasKey && (
        <div
          style={{
            marginTop: 24,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)',
            padding: '16px 20px',
            boxShadow: 'var(--shadow-xs)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 16,
          }}
        >
          <div>
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 13.5, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Sparkles size={15} style={{ color: 'var(--primary)' }} />
              Optional: Enable Cloud NVIDIA NIM Reasoning
            </div>
            <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 4 }}>
              To connect cloud LLM models (such as <code>meta/llama-3.3-70b-instruct</code> or <code>deepseek-ai/deepseek-r1</code>), obtain a free API key at <a href="https://build.nvidia.com/" target="_blank" rel="noreferrer" style={{ color: 'var(--primary)', textDecoration: 'underline' }}>build.nvidia.com</a> and paste it into the <strong>Settings</strong> page.
            </div>
          </div>
        </div>
      )}

      <div style={{ marginTop: 24 }}>
        <div className="card-title" style={{ marginBottom: 12 }}>
          <Cpu size={16} />
          LLM Model Specification
        </div>
        <div className="card">
          <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: '12px 0', fontSize: 13 }}>
            {[
              ['Provider',        'NVIDIA NIM (Hosted Inference)'],
              ['Endpoint URL',    'https://integrate.api.nvidia.com/v1'],
              ['Active Model',    health?.model || 'meta/llama-3.3-70b-instruct'],
              ['Authentication',  hasKey ? 'Bearer Token Configured' : 'Local Fallback (No Key)'],
              ['Execution Mode',  'Autonomous Detection, Triage & Mitigation'],
              ['Safety Engine',   'Forensic Heuristic & Pattern Engine'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>{k}</span>
                <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 12.5 }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
