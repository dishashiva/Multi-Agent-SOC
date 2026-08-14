import { useState } from 'react';
import { api } from '../api';

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
  'meta/llama-3.3-70b-instruct',
  'mistralai/mistral-7b-instruct-v0.3',
  'microsoft/phi-3-mini-128k-instruct',
];

export default function Settings({ status, onStatusChange }) {
  const [cfg, setCfg] = useState(DEFAULT_CONFIG);
  const [busy, setBusy]     = useState(false);
  const [msg, setMsg]       = useState(null);

  const running = status?.running;

  function update(key, val) { setCfg(prev => ({ ...prev, [key]: val })); }

  async function startEngine() {
    setBusy(true); setMsg(null);
    try {
      await api.start(cfg);
      setMsg({ ok: true, text: `✓ Engine started. Watching: ${cfg.watch_path}` });
      onStatusChange();
    } catch (err) {
      setMsg({ ok: false, text: `✗ Failed to start: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  async function stopEngine() {
    setBusy(true); setMsg(null);
    try {
      await api.stop();
      setMsg({ ok: true, text: '✓ Engine stopped.' });
      onStatusChange();
    } catch (err) {
      setMsg({ ok: false, text: `✗ Failed to stop: ${err.message}` });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Settings</h2>
          <p>Configure the SOC engine, watch path, and AI model</p>
        </div>
        <span className={`badge ${running ? 'running' : 'idle'}`} style={{ fontSize: 12 }}>
          {running ? '● Running' : '○ Stopped'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>

        {/* Engine Config */}
        <div>
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">Engine Configuration</div>

            <div className="input-group">
              <label className="input-label">Watch Path *</label>
              <input className="input" placeholder="./victim_app/logs  or  C:/MyApp/logs" value={cfg.watch_path} onChange={e => update('watch_path', e.target.value)} />
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Path to the directory containing log files to monitor</div>
            </div>

            <div className="input-group">
              <label className="input-label">Reports Directory</label>
              <input className="input" placeholder="./reports" value={cfg.reports_dir} onChange={e => update('reports_dir', e.target.value)} />
            </div>

            <div className="toggle-row">
              <div>
                <div className="toggle-label">Simulate-Only Mode</div>
                <div className="toggle-desc">No real shell commands will be executed (recommended)</div>
              </div>
              <label className="toggle">
                <input type="checkbox" checked={cfg.simulate} onChange={e => update('simulate', e.target.checked)} />
                <span className="toggle-slider" />
              </label>
            </div>

            <div className="input-group">
              <label className="input-label">API Cooldown: {cfg.cooldown}s</label>
              <input
                type="range"
                min="1"
                max="15"
                step="0.5"
                value={cfg.cooldown}
                onChange={e => update('cooldown', parseFloat(e.target.value))}
                style={{ width: '100%' }}
              />
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Minimum seconds between AI API calls to avoid rate limits</div>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 12 }}>
            {!running
              ? <button className="btn btn-primary" style={{ flex: 1 }} onClick={startEngine} disabled={busy || !cfg.watch_path}>
                  {busy ? <span className="spinner" /> : '▶ Start Engine'}
                </button>
              : <button className="btn btn-danger" style={{ flex: 1 }} onClick={stopEngine} disabled={busy}>
                  {busy ? <span className="spinner" /> : '■ Stop Engine'}
                </button>
            }
          </div>

          {msg && (
            <div style={{
              marginTop: 12,
              padding: '10px 14px',
              background: msg.ok ? 'var(--ok-dim)' : 'var(--critical-dim)',
              border: `1px solid ${msg.ok ? 'rgba(63,185,80,0.3)' : 'rgba(255,59,59,0.3)'}`,
              borderRadius: 'var(--radius-md)',
              fontSize: 13,
              color: msg.ok ? 'var(--ok)' : 'var(--critical)',
            }}>
              {msg.text}
            </div>
          )}
        </div>

        {/* AI Config */}
        <div>
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title">NVIDIA NIM Configuration</div>

            <div className="input-group">
              <label className="input-label">API Key (loaded from .env if empty)</label>
              <input className="input" type="password" placeholder="Loaded automatically from .env" value={cfg.api_key} onChange={e => update('api_key', e.target.value)} />
              <div style={{ fontSize: 11, color: 'var(--ok)' }}>✓ Takes key automatically from .env (NVIDIA_NIM_KEY)</div>
            </div>

            <div className="input-group">
              <label className="input-label">NIM URL</label>
              <input className="input" value={cfg.nim_url} onChange={e => update('nim_url', e.target.value)} />
            </div>

            <div className="input-group">
              <label className="input-label">Model</label>
              <select className="select" value={cfg.model} onChange={e => update('model', e.target.value)}>
                {MODELS.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
          </div>

          {/* Email hint */}
          <div className="card">
            <div className="card-title">Email Notifications (optional)</div>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
              Add the following to your <code style={{ color: 'var(--cyan)' }}>.env</code> file to receive email alerts for critical incidents:
            </p>
            <pre style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 14, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto' }}>{
`SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=your-app-password
NOTIFY_EMAIL=alerts@you.com`
            }</pre>
          </div>
        </div>
      </div>

      {/* Victim app instructions */}
      <div className="card" style={{ marginTop: 20 }}>
        <div className="card-title">Testing with the Victim App</div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12 }}>
          Use the included <strong>victim app</strong> to generate realistic log traffic for the SOC to analyze:
        </p>
        <pre style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 14, fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', overflow: 'auto' }}>{
`# Terminal 1 — Start this SOC dashboard backend
.\\venv\\Scripts\\python -m uvicorn backend.api_server:app --port 8080 --reload

# Terminal 2 — Start the victim app (writes logs to ./victim_app/logs)
.\\venv\\Scripts\\python victim_app\\victim_app.py --rate 1 --attack-rate 0.3

# Then: set Watch Path to ./victim_app/logs in Settings above and click Start`
        }</pre>
      </div>
    </div>
  );
}
