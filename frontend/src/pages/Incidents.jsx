import { useEffect, useState } from 'react';
import { api } from '../api';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

function SeverityBadge({ v }) {
  return <span className={`badge ${v}`}>{v}</span>;
}

function IncidentModal({ id, onClose }) {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.incident(id)
      .then(r => setContent(r.content))
      .catch(() => setContent('# Error\nCould not load incident report.'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <span className="modal-title">📄 {id}</span>
          <span className="modal-close" onClick={onClose}>✕</span>
        </div>
        <div className="modal-body">
          {loading
            ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><span className="spinner" /></div>
            : <div className="markdown-body"><ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown></div>
          }
        </div>
      </div>
    </div>
  );
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected]  = useState(null);
  const [loading, setLoading]    = useState(true);
  const [search, setSearch]      = useState('');

  async function load() {
    setLoading(true);
    try {
      const res = await api.incidents();
      setIncidents(res.incidents || []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);

  function parseSeverity(id) {
    if (id.includes('CRIT')) return 'CRITICAL';
    return 'INFO';
  }

  const filtered = incidents.filter(inc => !search || inc.id.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="page">
      {selected && <IncidentModal id={selected} onClose={() => setSelected(null)} />}

      <div className="page-header">
        <div>
          <h2>Incident Reports</h2>
          <p>{incidents.length} incidents on record</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <input className="search-input" placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} />
          <button className="btn btn-secondary" onClick={load}>↻ Refresh</button>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading
          ? <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><span className="spinner" /></div>
          : filtered.length === 0
          ? <div className="empty-state"><div className="empty-icon">🔍</div><div className="empty-text">No incidents yet. The system will generate reports as threats are detected.</div></div>
          : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Created</th>
                  <th>Size</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(inc => (
                  <tr key={inc.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(inc.id)}>
                    <td className="mono" style={{ color: 'var(--cyan)' }}>{inc.id}</td>
                    <td>{new Date(inc.created).toLocaleString()}</td>
                    <td>{(inc.size / 1024).toFixed(1)} KB</td>
                    <td>
                      <button className="btn btn-secondary" style={{ padding: '4px 12px', fontSize: 12 }}>View →</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        }
      </div>
    </div>
  );
}
