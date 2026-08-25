import { useState } from 'react';
import { api } from '../api';
import {
  Play,
  Square,
  CheckCircle2,
  AlertCircle,
  Settings as SettingsIcon,
  Cpu,
  Terminal,
  Trash2,
  RotateCcw,
} from '../components/Icons';

const DEFAULT_CONFIG = {
  watch_path:  './victim_app/logs',
  api_key:     '',
  model:       'meta/llama-3.1-8b-instruct',
  nim_url:     'https://integrate.api.nvidia.com/v1',
  simulate:    true,
  reports_dir: './reports',
  cooldown:    3.0,
};

const MODELS = [
  'meta/llama-3.1-8b-instruct',
  'meta/llama-3.1-70b-instruct',
  'meta/llama-3.2-3b-instruct',
  'meta/llama-3.2-11b-vision-instruct',
  'meta/llama-3.2-1b-instruct',
];

export default function Settings({ status, onStatusChange }) {
  const [cfg, setCfg] = useState(DEFAULT_CONFIG);
  const [busy, setBusy]         = useState(false);
  const [resetting, setResetting] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [msg, setMsg]           = useState(null);

  const running = status?.running;

  function update(key, val) { setCfg(prev => ({ ...prev, [key]: val })); }

  async function startEngine() {
    setBusy(true); setMsg(null);
    try {
      await api.start(cfg);
      setMsg({ ok: true, text: `Engine started successfully. Monitoring: ${cfg.watch_path}` });
      onStatusChange();
    } catch (err) {
      setMsg({ ok: false, text: `Failed to start engine: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  async function stopEngine() {
    setBusy(true); setMsg(null);
    try {
      await api.stop();
      setMsg({ ok: true, text: 'Engine stopped successfully.' });
      onStatusChange();
    } catch (err) {
      setMsg({ ok: false, text: `Failed to stop engine: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  async function handleResetAll() {
    setResetting(true);
    setShowConfirm(false);
    setMsg(null);
    try {
      const res = await api.reset();
      setMsg({ ok: true, text: res.message || 'System environment, reports, and logs have been reset to a fresh state.' });
      if (onStatusChange) onStatusChange();
    } catch (err) {
      setMsg({ ok: false, text: `Failed to reset system: ${err.message}` });
    } finally {
      setResetting(false);
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>System Configuration</h2>
          <p>Configure log monitoring directories, AI model parameters, and operational triggers</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            className="btn btn-secondary"
            onClick={() => setShowConfirm(true)}
            disabled={resetting}
            style={{ fontSize: 13, padding: '8px 14px', borderColor: 'var(--critical-border)', color: 'var(--critical)' }}
          >
            {resetting ? <span className="spinner" style={{ borderTopColor: 'var(--critical)' }} /> : <Trash2 size={14} />}
            Reset All Data
          </button>
          <span className={`badge ${running ? 'running' : 'idle'}`} style={{ fontSize: 12 }}>
            {running ? 'Running' : 'Stopped'}
          </span>
        </div>
      </div>

      {showConfirm && (
        <div
          style={{
            marginBottom: 20,
            padding: 16,
            background: 'var(--critical-dim)',
            border: '1px solid var(--critical-border)',
            borderRadius: 'var(--radius-lg)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 16,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <AlertCircle size={20} style={{ color: 'var(--critical)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 600, color: 'var(--critical)', fontSize: 14 }}>
                Are you sure you want to reset everything?
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 2 }}>
                This permanently deletes all generated incident reports (<code>./reports/</code>), monitored logs, SQLite audit history, and resets agent queues to fresh.
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button
              className="btn btn-secondary"
              onClick={() => setShowConfirm(false)}
              style={{ fontSize: 12.5, padding: '6px 12px' }}
            >
              Cancel
            </button>
            <button
              className="btn btn-danger"
              onClick={handleResetAll}
              disabled={resetting}
              style={{ fontSize: 12.5, padding: '6px 14px' }}
            >
              {resetting ? 'Resetting...' : 'Yes, Delete Everything'}
            </button>
          </div>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>

        {/* Engine Config */}
        <div>
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">
              <SettingsIcon size={16} />
              Engine & Watch Path
            </div>

            <div className="input-group">
              <label className="input-label">Watch Directory Path *</label>
              <input
                className="input"
                placeholder="./victim_app/logs  or  C:/MyApp/logs"
                value={cfg.watch_path}
                onChange={e => update('watch_path', e.target.value)}
              />
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>Path to the directory containing application log files to monitor</div>
            </div>

            <div className="input-group">
              <label className="input-label">Reports Output Directory</label>
              <input
                className="input"
                placeholder="./reports"
                value={cfg.reports_dir}
                onChange={e => update('reports_dir', e.target.value)}
              />
            </div>

            <div className="toggle-row">
              <div>
                <div className="toggle-label">Simulation Safety Mode</div>
                <div className="toggle-desc">No live destructive shell commands executed (recommended for evaluation)</div>
              </div>
              <label className="toggle">
                <input type="checkbox" checked={cfg.simulate} onChange={e => update('simulate', e.target.checked)} />
                <span className="toggle-slider" />
              </label>
            </div>

            <div className="input-group" style={{ marginTop: 14 }}>
              <label className="input-label">API Rate Cooldown: {cfg.cooldown}s</label>
              <input
                type="range"
                min="1"
                max="15"
                step="0.5"
                value={cfg.cooldown}
                onChange={e => update('cooldown', parseFloat(e.target.value))}
                style={{ width: '100%', accentColor: 'var(--primary)' }}
              />
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>Minimum interval between AI API queries to respect rate quotas</div>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 12 }}>
            {!running ? (
              <button
                className="btn btn-primary"
                style={{ flex: 1, padding: '10px 16px' }}
                onClick={startEngine}
                disabled={busy || !cfg.watch_path}
              >
                {busy ? <span className="spinner" style={{ borderTopColor: '#ffffff' }} /> : <Play size={14} />}
                Start Monitoring Engine
              </button>
            ) : (
              <button
                className="btn btn-danger"
                style={{ flex: 1, padding: '10px 16px' }}
                onClick={stopEngine}
                disabled={busy}
              >
                {busy ? <span className="spinner" style={{ borderTopColor: '#ffffff' }} /> : <Square size={14} />}
                Stop Engine
              </button>
            )}
          </div>

          {msg && (
            <div
              style={{
                marginTop: 14,
                padding: '12px 16px',
                background: msg.ok ? 'var(--ok-dim)' : 'var(--critical-dim)',
                border: `1px solid ${msg.ok ? 'var(--ok-border)' : 'var(--critical-border)'}`,
                borderRadius: 'var(--radius-md)',
                fontSize: 13,
                color: msg.ok ? 'var(--ok)' : 'var(--critical)',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
              }}
            >
              {msg.ok ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
              <span>{msg.text}</span>
            </div>
          )}
        </div>

        {/* AI Config */}
        <div>
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">
              <Cpu size={16} />
              NVIDIA NIM Inference Settings
            </div>

            <div className="input-group">
              <label className="input-label">API Key</label>
              <input
                className="input"
                type="password"
                placeholder="Loaded automatically from .env"
                value={cfg.api_key}
                onChange={e => update('api_key', e.target.value)}
              />
              <div style={{ fontSize: 11.5, color: 'var(--ok)', display: 'flex', alignItems: 'center', gap: 4 }}>
                <CheckCircle2 size={13} />
                Automatically loaded from .env (NVIDIA_NIM_KEY)
              </div>
            </div>

            <div className="input-group">
              <label className="input-label">NIM Base URL</label>
              <input
                className="input"
                value={cfg.nim_url}
                onChange={e => update('nim_url', e.target.value)}
              />
            </div>

            <div className="input-group">
              <label className="input-label">Primary Inference Model (with Auto-Failover)</label>
              <select
                className="select"
                value={cfg.model}
                onChange={e => update('model', e.target.value)}
              >
                {MODELS.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                Automatic multi-model fallback is active. If the selected model experiences latency or rate limits, alternate NIM models are engaged automatically.
              </div>
            </div>
          </div>

          {/* Maintenance & Purge Card */}
          <div className="card">
            <div className="card-title">
              <RotateCcw size={16} />
              Data Purge & Factory Reset
            </div>
            <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 12 }}>
              Clear all incident files, log streams, notifications, and SQLite audit records to restart with a clean slate:
            </p>
            <button
              className="btn btn-secondary"
              onClick={() => setShowConfirm(true)}
              disabled={resetting}
              style={{ width: '100%', borderColor: 'var(--critical-border)', color: 'var(--critical)' }}
            >
              <Trash2 size={14} />
              Clear Everything & Reset Environment
            </button>
          </div>
        </div>
      </div>

      {/* Victim app instructions */}
      <div className="card" style={{ marginTop: 24 }}>
        <div className="card-title">
          <Terminal size={16} />
          Synthetic Log Generator (Victim Application)
        </div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>
          Run the realistic log generator to produce natural application traffic and occasional security events:
        </p>
        <pre style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 14, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', overflow: 'auto' }}>{
`# Terminal 1 — Start the SOC FastAPI backend
.\\venv\\Scripts\\python -m uvicorn backend.api_server:app --port 8080 --reload

# Terminal 2 — Start the realistic victim application simulator
.\\venv\\Scripts\\python victim_app\\victim_app.py --min-delay 4.0 --max-delay 8.5 --attack-rate 0.02

# In Dashboard: Set Watch Directory Path to ./victim_app/logs and click Start Monitoring Engine`
        }</pre>
      </div>
    </div>
  );
}
