import { useEffect, useState } from 'react';
import { api } from '../api';
import {
  RefreshCw,
  History,
  ChevronLeft,
  ChevronRight,
} from '../components/Icons';

const AGENTS     = ['', 'SENTRY', 'INVESTIGATOR', 'RESPONDER', 'SYSTEM'];
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const PAGE_SIZE  = 50;

export default function AuditLog() {
  const [events, setEvents]     = useState([]);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(0);
  const [agent, setAgent]       = useState('');
  const [severity, setSeverity] = useState('');
  const [loading, setLoading]   = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await api.audit({ limit: PAGE_SIZE, offset: page * PAGE_SIZE, agent, severity });
      setEvents(res.events || []);
      setTotal(res.total || 0);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [page, agent, severity]);

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>System Audit Trail</h2>
          <p>{total} total structured security events recorded</p>
        </div>
        <button className="btn btn-secondary" onClick={load}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
        <select
          className="select"
          style={{ width: 180 }}
          value={agent}
          onChange={e => { setAgent(e.target.value); setPage(0); }}
        >
          {AGENTS.map(a => (
            <option key={a} value={a}>
              {a ? `Agent: ${a}` : 'All Agents'}
            </option>
          ))}
        </select>
        <select
          className="select"
          style={{ width: 180 }}
          value={severity}
          onChange={e => { setSeverity(e.target.value); setPage(0); }}
        >
          {SEVERITIES.map(s => (
            <option key={s} value={s}>
              {s ? `Severity: ${s}` : 'All Severities'}
            </option>
          ))}
        </select>
      </div>

      <div className="card" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
            <span className="spinner" />
          </div>
        ) : events.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">
              <History size={22} />
            </div>
            <div className="empty-text">No audit events match the selected filters.</div>
          </div>
        ) : (
          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Timestamp</th>
                  <th>Agent</th>
                  <th>Event Type</th>
                  <th>Severity</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {events.map(ev => (
                  <tr key={ev.id}>
                    <td className="mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>{ev.id}</td>
                    <td className="mono" style={{ fontSize: 11.5 }}>{new Date(ev.timestamp).toLocaleString()}</td>
                    <td>
                      <span className="badge INFO">{ev.agent}</span>
                    </td>
                    <td style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--primary)', fontWeight: 600 }}>
                      {ev.event_type}
                    </td>
                    <td>
                      <span className={`badge ${ev.severity}`}>{ev.severity}</span>
                    </td>
                    <td style={{ maxWidth: 420 }} className="truncate">{ev.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="pagination">
          <button
            className="btn btn-secondary"
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
          >
            <ChevronLeft size={14} />
            Previous
          </button>
          <span className="page-info">Page {page + 1} of {totalPages} ({total} events)</span>
          <button
            className="btn btn-secondary"
            onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
          >
            Next
            <ChevronRight size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
