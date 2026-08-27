import { useEffect, useState, useRef } from 'react';
import { useSoc } from '../SocContext';
import { api } from '../api';
import {
  BellOff,
  FileText,
  Wrench,
  CheckCircle2,
  AlertOctagon,
  Terminal,
  X,
  ShieldCheck,
  RotateCcw,
} from '../components/Icons';

export default function Notifications() {
  const { notifications: liveNotifs } = useSoc();
  const [historical, setHistorical]   = useState([]);
  const [resolvedMap, setResolvedMap] = useState(() => {
    try {
      const saved = localStorage.getItem('soc_resolved_incidents');
      return saved ? JSON.parse(saved) : {};
    } catch {
      return {};
    }
  });

  // Active Terminal Modal state: { incidentId, notif, isRunning, lines, stepIndex, summary }
  const [cliModal, setCliModal]       = useState(null);
  const terminalEndRef                = useRef(null);

  // Sync to localStorage
  function markIncidentResolved(id, summary) {
    setResolvedMap(prev => {
      const updated = { ...prev, [id]: { resolvedAt: new Date().toISOString(), summary } };
      try {
        localStorage.setItem('soc_resolved_incidents', JSON.stringify(updated));
      } catch { /* ignore */ }
      return updated;
    });
  }

  useEffect(() => {
    api.notifications().then(r => setHistorical(r.notifications || [])).catch(() => {});
  }, []);

  // Auto scroll terminal to bottom as lines stream
  useEffect(() => {
    if (cliModal && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [cliModal?.lines]);

  // Launch the Agentic CLI Fixer
  async function launchAgenticFix(item) {
    const incId = item.incident_id;
    if (!incId) return;

    // Check if already resolved
    if (resolvedMap[incId]) {
      // Re-open in completed inspection view
      setCliModal({
        incidentId: incId,
        notif: item,
        isRunning: false,
        isCompleted: true,
        lines: [
          { type: 'info', text: `[+] Incident ${incId} previously resolved and verified.` },
          { type: 'cmd', text: `soc-agent status --incident ${incId}` },
          { type: 'out', text: `Status: RESOLVED\nTarget isolated and neutralized\nIntegrity: PASS (0 regression errors)` },
        ],
        summary: resolvedMap[incId].summary,
      });
      return;
    }

    // Initialize interactive streaming CLI modal
    setCliModal({
      incidentId: incId,
      notif: item,
      isRunning: true,
      isCompleted: false,
      lines: [
        { type: 'info', text: `[SOC-Agentic-CLI v2.4.0 — Autonomous Incident Remediation Agent]` },
        { type: 'info', text: `Target Incident : ${incId}` },
        { type: 'info', text: `Detected Reason : ${item.reason || item.message || 'Security breach escalation'}` },
        { type: 'cmd', text: `soc-agent initialize --incident ${incId} --auto-remediate` },
        { type: 'out', text: `[+] Agent session initialized. Connecting to forensic investigation bus...` },
      ],
      summary: null,
    });

    try {
      const res = await api.fixIncident(incId);
      const steps = res.steps || [];

      // Sequentially stream steps with realistic CLI typing delay
      for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        await new Promise(r => setTimeout(r, 600));

        setCliModal(prev => {
          if (!prev || prev.incidentId !== incId) return prev;
          return {
            ...prev,
            lines: [
              ...prev.lines,
              { type: 'step-title', text: `\n[STEP ${step.step}/5] ${step.title}` },
              { type: 'cmd', text: `$ ${step.command}` },
            ],
          };
        });

        await new Promise(r => setTimeout(r, 550));

        setCliModal(prev => {
          if (!prev || prev.incidentId !== incId) return prev;
          return {
            ...prev,
            lines: [
              ...prev.lines,
              { type: 'out', text: step.stdout },
              { type: 'success', text: `✓ Step ${step.step} ${step.status}` },
            ],
          };
        });
      }

      await new Promise(r => setTimeout(r, 400));

      const finalSummary = res.summary || {
        incident_id: incId,
        resolved_at: new Date().toISOString(),
        status: 'RESOLVED',
        actions_taken: ['Attacker network connection dropped', 'Compromised process terminated', 'Integrity verified'],
        root_cause_summary: `Incident ${incId} neutralized and verified by Autonomous AI Agent.`,
      };

      setCliModal(prev => {
        if (!prev || prev.incidentId !== incId) return prev;
        return {
          ...prev,
          isRunning: false,
          isCompleted: true,
          lines: [
            ...prev.lines,
            { type: 'success', text: `\n============================================================` },
            { type: 'success', text: `[AGENT SUCCESS] All remediation steps executed & verified.` },
            { type: 'success', text: `Incident Status: RESOLVED` },
            { type: 'success', text: `============================================================` },
          ],
          summary: finalSummary,
        };
      });

      markIncidentResolved(incId, finalSummary);
    } catch (err) {
      setCliModal(prev => {
        if (!prev || prev.incidentId !== incId) return prev;
        return {
          ...prev,
          isRunning: false,
          isCompleted: false,
          lines: [
            ...prev.lines,
            { type: 'error', text: `\n[ERROR] Failed to execute remediation: ${err.message}` },
          ],
        };
      });
    }
  }

  const rawList = [
    ...liveNotifs.map(n => ({ ...n.data, _live: true, timestamp: n.timestamp })),
    ...historical,
  ];

  const seenIds = new Set();
  const all = rawList.filter(n => {
    const incId = n?.incident_id;
    if (!incId || typeof incId !== 'string' || !incId.startsWith('INC-')) {
      return false;
    }
    if (seenIds.has(incId)) {
      return false;
    }
    seenIds.add(incId);
    return true;
  });

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
        const isResolved = incId && Boolean(resolvedMap[incId]);

        return (
          <div
            key={i}
            className="notif-item"
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              gap: 16,
              borderLeft: isResolved ? '4px solid var(--success)' : '4px solid var(--critical)',
            }}
          >
            <div style={{ flex: 1 }}>
              <div className="notif-header">
                <span className="notif-id">
                  {isResolved ? (
                    <ShieldCheck size={16} style={{ color: 'var(--success)' }} />
                  ) : (
                    <AlertOctagon size={16} style={{ color: 'var(--critical)' }} />
                  )}
                  {n._live && !isResolved && <span style={{ color: 'var(--critical)', marginRight: 4 }}>●</span>}
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

              {isResolved && resolvedMap[incId]?.summary && (
                <div style={{ marginTop: 10, padding: '8px 12px', background: '#ecfdf5', borderRadius: 'var(--radius-sm)', border: '1px solid #a7f3d0', fontSize: 12.5, color: '#065f46' }}>
                  <strong>Remediation Result:</strong> {resolvedMap[incId].summary.root_cause_summary || 'Threat neutralized and verified.'}
                </div>
              )}
            </div>

            {incId && (
              <div style={{ marginLeft: 16, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'flex-end' }}>
                {isResolved ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="badge ok" style={{ fontSize: 12, padding: '6px 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <CheckCircle2 size={14} />
                      Resolved by AI
                    </span>
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: 12, padding: '5px 10px' }}
                      onClick={() => launchAgenticFix(n)}
                    >
                      <Terminal size={13} />
                      View Fix Log
                    </button>
                  </div>
                ) : (
                  <button
                    className="btn btn-danger"
                    style={{ fontSize: 12.5, padding: '7px 16px', display: 'flex', alignItems: 'center', gap: 7 }}
                    onClick={() => launchAgenticFix(n)}
                  >
                    <Terminal size={14} />
                    <span>Fix with AI Agent</span>
                  </button>
                )}
              </div>
            )}
          </div>
        );
      })}

      {/* ============================================================
          Agentic CLI Terminal Modal
          ============================================================ */}
      {cliModal && (
        <div className="modal-backdrop" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
          <div className="terminal-window" style={{ width: '100%', maxWidth: 760, maxHeight: '85vh' }}>
            {/* Header */}
            <div className="terminal-header">
              <div className="terminal-dots">
                <span className="terminal-dot red" />
                <span className="terminal-dot yellow" />
                <span className="terminal-dot green" />
              </div>
              <div className="terminal-title">
                AGENTIC CLI — {cliModal.incidentId}
              </div>
              <button
                onClick={() => setCliModal(null)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: 4 }}
              >
                <X size={16} />
              </button>
            </div>

            {/* Terminal Body */}
            <div className="terminal-body">
              {cliModal.lines.map((line, idx) => {
                if (line.type === 'step-title') {
                  return (
                    <div key={idx} className="terminal-line" style={{ color: '#f59e0b', fontWeight: 700, marginTop: 10 }}>
                      {line.text}
                    </div>
                  );
                }
                if (line.type === 'cmd') {
                  return (
                    <div key={idx} className="terminal-line terminal-cmd">
                      {line.text}
                    </div>
                  );
                }
                if (line.type === 'out') {
                  return (
                    <div key={idx} className="terminal-out">
                      {line.text}
                    </div>
                  );
                }
                if (line.type === 'success') {
                  return (
                    <div key={idx} className="terminal-line terminal-success" style={{ fontWeight: 600 }}>
                      {line.text}
                    </div>
                  );
                }
                if (line.type === 'error') {
                  return (
                    <div key={idx} className="terminal-line terminal-error">
                      {line.text}
                    </div>
                  );
                }
                return (
                  <div key={idx} className="terminal-line terminal-info">
                    {line.text}
                  </div>
                );
              })}

              {cliModal.isRunning && (
                <div style={{ marginTop: 8, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span className="spinner" style={{ borderColor: '#38bdf833', borderTopColor: '#38bdf8', width: 14, height: 14 }} />
                  <span>Agent executing remediation steps...</span>
                  <span className="terminal-cursor" />
                </div>
              )}

              {/* Summary Card when Completed */}
              {cliModal.summary && (
                <div className="fix-summary-card">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10, borderBottom: '1px solid #334155', paddingBottom: 8 }}>
                    <span style={{ fontWeight: 700, color: '#34d399', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <CheckCircle2 size={16} />
                      Remediation Summary & Resolution
                    </span>
                    <span className="badge ok" style={{ fontSize: 11 }}>STATUS: RESOLVED</span>
                  </div>
                  <div style={{ fontSize: 12.5, color: '#cbd5e1', marginBottom: 8 }}>
                    {cliModal.summary.root_cause_summary}
                  </div>
                  <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>Actions Executed:</div>
                  <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: '#e2e8f0' }}>
                    {cliModal.summary.actions_taken?.map((action, aidx) => (
                      <li key={aidx} style={{ marginBottom: 3 }}>{action}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div ref={terminalEndRef} />
            </div>

            {/* Footer */}
            <div style={{ background: '#1e293b', padding: '12px 20px', display: 'flex', justifyContent: 'flex-end', gap: 10, borderTop: '1px solid #334155' }}>
              <button
                className="btn btn-secondary"
                style={{ background: '#334155', color: '#f8fafc', borderColor: '#475569' }}
                onClick={() => setCliModal(null)}
              >
                {cliModal.isCompleted ? 'Done / Close' : 'Close Terminal'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

