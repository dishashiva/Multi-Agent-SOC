import { useEffect, useState } from 'react';
import { api } from '../api';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  FileText,
  Search,
  RefreshCw,
  X,
  ArrowRight,
  ShieldCheck,
} from '../components/Icons';

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
          <span className="modal-title">
            <FileText size={18} />
            {id}
          </span>
          <button className="modal-close" onClick={onClose} aria-label="Close modal">
            <X size={18} />
          </button>
        </div>
        <div className="modal-body">
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
              <span className="spinner" />
            </div>
          ) : (
            <div className="markdown-body">
              <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
            </div>
          )}
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

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, []);

  const filtered = incidents.filter(inc => !search || inc.id.toLowerCase().includes(search.toLowerCase()));

  return (
    <div className="page">
      {selected && <IncidentModal id={selected} onClose={() => setSelected(null)} />}

      <div className="page-header">
        <div>
          <h2>Incident Reports</h2>
          <p>{incidents.length} forensic investigation reports on record</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <div className="search-input-wrapper" style={{ width: 220 }}>
            <Search size={14} className="search-icon" />
            <input
              className="search-input"
              placeholder="Search reports…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>
          <button className="btn btn-secondary" onClick={load}>
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
            <span className="spinner" />
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">
              <ShieldCheck size={22} />
            </div>
            <div className="empty-text">No incident records found. As security threats are identified, forensic reports will appear here.</div>
          </div>
        ) : (
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Incident ID</th>
                  <th>Timestamp</th>
                  <th>Report Size</th>
                  <th style={{ textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(inc => (
                  <tr key={inc.id} style={{ cursor: 'pointer' }} onClick={() => setSelected(inc.id)}>
                    <td className="mono" style={{ color: 'var(--primary)', fontWeight: 600 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <FileText size={15} style={{ color: 'var(--text-muted)' }} />
                        {inc.id}
                      </div>
                    </td>
                    <td>{new Date(inc.created).toLocaleString()}</td>
                    <td>{(inc.size / 1024).toFixed(1)} KB</td>
                    <td style={{ textAlign: 'right' }}>
                      <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: 12 }}>
                        View Report
                        <ArrowRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
