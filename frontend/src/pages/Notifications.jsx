import { useEffect } from 'react';
import { useSoc } from '../SocContext';
import { api } from '../api';
import { useState } from 'react';

export default function Notifications() {
  const { notifications: liveNotifs } = useSoc();
  const [historical, setHistorical] = useState([]);
  const [fixedIds, setFixedIds]     = useState(new Set());
  const [fixingId, setFixingId]     = useState(null);

  useEffect(() => {
    api.notifications().then(r => setHistorical(r.notifications || [])).catch(() => {});
  }, []);

  async function handleFix(id) {
    if (!id) return;
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

  const all = [
    ...liveNotifs.map(n => ({ ...n.data, _live: true, timestamp: n.timestamp })),
    ...historical,
  ];

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Notifications</h2>
          <p>Human escalation alerts — high-risk incidents that require manual user intervention</p>
        </div>
        <span className={`badge CRITICAL`} style={{ fontSize: 12 }}>{all.length} Total</span>
      </div>

      {all.length === 0 && (
        <div className="empty-state" style={{ marginTop: 60 }}>
          <div className="empty-icon">🔕</div>
          <div className="empty-text">No escalation notifications yet.<br />High/Critical incidents that can't be auto-resolved will appear here.</div>
        </div>
      )}

      {all.map((n, i) => {
        const incId = n.incident_id;
        const isFixed = incId && fixedIds.has(incId);
        return (
          <div key={i} className="notif-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ flex: 1 }}>
              <div className="notif-header">
                <span className="notif-id">
                  {n._live && <span style={{ color: 'var(--critical)', marginRight: 6 }}>●</span>}
                  {incId || 'N/A'}
                </span>
                <span className="notif-time">{n.timestamp ? new Date(n.timestamp).toLocaleString() : '—'}</span>
              </div>
              <div className="notif-reason">{n.reason || n.message || 'Human intervention required.'}</div>
              {n.report_path && (
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  📄 {n.report_path}
                </div>
              )}
            </div>

            {incId && (
              <div style={{ marginLeft: 16 }}>
                {isFixed ? (
                  <span className="badge ok" style={{ fontSize: 12 }}>✓ Fixed by User</span>
                ) : (
                  <button
                    className="btn btn-danger"
                    style={{ fontSize: 12, padding: '6px 12px' }}
                    onClick={() => handleFix(incId)}
                    disabled={fixingId === incId}
                  >
                    {fixingId === incId ? 'Fixing…' : '🔧 Apply Fix Now'}
                  </button>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
