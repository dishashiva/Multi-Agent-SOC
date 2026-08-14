// API client — all calls to the FastAPI backend

const CANDIDATE_BASES = [
  import.meta.env.VITE_API_URL,
  'http://localhost:8080',
  'http://localhost:8000',
  'http://127.0.0.1:8080',
  'http://127.0.0.1:8000',
].filter(Boolean);

let activeBase = CANDIDATE_BASES[0] || 'http://localhost:8080';

export function getWsUrl() {
  const base = activeBase || 'http://localhost:8080';
  return `${base.replace(/^http/, 'ws')}/ws/events`;
}

async function request(path, options = {}) {
  const bases = [activeBase, ...CANDIDATE_BASES.filter(b => b !== activeBase)];
  let lastErr = null;

  for (const base of bases) {
    try {
      const res = await fetch(`${base}${path}`, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`${res.status}: ${text}`);
      }
      activeBase = base;
      return await res.json();
    } catch (err) {
      lastErr = err;
      if (err.message && err.message.match(/^\d{3}:/)) {
        throw err;
      }
    }
  }

  throw new Error(`Cannot connect to backend (tried ${bases.join(', ')}). Please ensure python backend is running.`);
}

export const api = {
  start:          (body)   => request('/api/start',  { method: 'POST', body: JSON.stringify(body || {}) }),
  stop:           ()       => request('/api/stop',   { method: 'POST' }),
  status:         ()       => request('/api/status'),
  logs:           (params) => request(`/api/logs?${new URLSearchParams(params)}`),
  incidents:      ()       => request('/api/incidents'),
  incident:       (id)     => request(`/api/incidents/${id}`),
  audit:          (params) => request(`/api/audit?${new URLSearchParams(params)}`),
  auditStats:     ()       => request('/api/audit/stats'),
  health:         ()       => request('/api/health'),
  notifications:  ()       => request('/api/notifications'),
  fixIncident:    (id)     => request(`/api/incidents/${id}/fix`, { method: 'POST' }),
};

export const WS_URL = `${activeBase.replace(/^http/, 'ws')}/ws/events`;
