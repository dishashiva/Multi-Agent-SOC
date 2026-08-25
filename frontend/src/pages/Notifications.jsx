import { useEffect, useState } from 'react';
import { useSoc } from '../SocContext';
import { api } from '../api';
import {
  BellOff,
  FileText,
  Wrench,
  CheckCircle2,
  AlertOctagon,
} from '../components/Icons';

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
          <h2>Human Escalation Alerts</h2>
          <p>High-risk incidents and elevated security threats requiring human authorization or intervention</p>
        </div>
        <span className="badge CRITICAL" style={{ fontSize: 12 }}>
          {all.length} Total Alerts
        </span>
      </div>

      {all.length === 0 && (
        <div className="empty-state" style={{ marginTop: 40 }}>
          <div className="empty-icon">
            <BellOff size={24} />
          </div>
          <div className="empty-text">
            No escalation notifications pending.<br />
            Critical alerts that cannot be automatically remediated will appear here.
          </div>
        </div>
      )}

      {all.map((n, i) => {
        const incId = n.incident_id;
        const isFixed = incId && fixedIds.has(incId);
        return (
          <div
            key={i}
            className="notif-item"
            style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}
          >
            <div style={{ flex: 1 }}>
              <div className="notif-header">
                <span className="notif-id">
                  <AlertOctagon size={16} style={{ color: 'var(--critical)' }} />
                  {n._live && <span style={{ color: 'var(--critical)', marginRight: 4 }}>●</span>}
                  {incId || 'Unassigned Incident'}
                </span>
                <span className="notif-time">
                  {n.timestamp ? new Date(n.timestamp).toLocaleString() : '—'}
                </span>
              </div>
              <div className="notif-reason">{n.reason || n.message || 'Human intervention required to mitigate threat.'}</div>
              {n.report_path && (
                <div
                  style={{
                    marginTop: 8,
                    fontSize: 11.5,
                    color: 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                  }}
                >
                  <FileText size={13} />
                  <span>{n.report_path}</span>
                </div>
              )}
            </div>

            {incId && (
              <div style={{ marginLeft: 16, flexShrink: 0 }}>
                {isFixed ? (
                  <span className="badge ok" style={{ fontSize: 12, padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <CheckCircle2 size={14} />
                    Fixed by User
                  </span>
                ) : (
                  <button
                    className="btn btn-danger"
                    style={{ fontSize: 12.5, padding: '6px 14px' }}
                    onClick={() => handleFix(incId)}
                    disabled={fixingId === incId}
                  >
                    {fixingId === incId ? (
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
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
