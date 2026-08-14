import { useEffect, useState } from 'react';
import { api } from '../api';
import { useSoc } from '../SocContext';

const AGENTS = [
  {
    key: 'sentry',
    name: 'Sentry',
    role: 'File System Watchdog',
    icon: '👁️',
    cls: 'sentry',
    desc: 'Monitors the watched directory for log file changes. Analyses every modification with AI to detect threats.',
    statKeys: [['alerts_sent', 'Alerts Generated'], ['last_action', 'Last Action']],
  },
  {
    key: 'investigator',
    name: 'Investigator',
    role: 'Forensic Analyst',
    icon: '🔍',
    cls: 'investigator',
    desc: 'Receives Sentry alerts and performs deep forensic analysis: IP extraction, log correlation, LLM investigation.',
    statKeys: [['reports_sent', 'Reports Sent'], ['last_action', 'Last Action']],
  },
  {
    key: 'responder',
    name: 'Responder',
    role: 'Autonomous Incident Response',
    icon: '⚡',
    cls: 'responder',
    desc: 'Reads investigation reports and executes responses: block IPs, lock users, quarantine files, escalate to humans.',
    statKeys: [['incidents', 'Incidents Handled'], ['last_action', 'Last Action']],
  },
];

function fmtTime(iso) {
  if (!iso) return 'Never';
  try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
}

export default function AgentStatus({ status }) {
  const { events } = useSoc();
  const agents = status?.agents || {};
  const running = status?.running;

  // Pipeline flow indicator from live events
  const lastAlert  = events.find(e => e.type === 'ALERT');
  const lastInv    = events.find(e => e.type === 'INVESTIGATION');
  const lastResp   = events.find(e => e.type === 'RESPONSE');

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Agent Status</h2>
          <p>Real-time status of the three autonomous SOC agents</p>
        </div>
        <span className={`badge ${running ? 'running' : 'idle'}`} style={{ fontSize: 12 }}>
          {running ? '● Pipeline Running' : '○ Pipeline Idle'}
        </span>
      </div>

      {/* Pipeline diagram */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 28, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '14px 20px', overflowX: 'auto' }}>
        {['Sentry → detects threats', 'alert_queue', 'Investigator → forensic analysis', 'report_queue', 'Responder → applies fixes'].map((step, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 0, flexShrink: 0 }}>
            {i % 2 === 0 ? (
              <div style={{ padding: '6px 14px', background: 'var(--bg-elevated)', borderRadius: 8, fontSize: 12, color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                {step}
              </div>
            ) : (
              <div style={{ padding: '0 8px', fontSize: 11, color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>──{step}──▶</div>
            )}
          </div>
        ))}
      </div>

      {/* Agent cards */}
      <div className="agent-grid">
        {AGENTS.map(agent => {
          const st = agents[agent.key] || {};
          const statusVal = st.status || (running ? 'running' : 'idle');

          return (
            <div key={agent.key} className={`agent-card ${agent.cls}`}>
              <div className="agent-header">
                <div>
                  <div className="agent-icon">{agent.icon}</div>
                  <div className="agent-name">{agent.name}</div>
                  <div className="agent-role">{agent.role}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span className={`pulse-ring ${running ? 'running' : ''}`} />
                  <span className={`badge ${statusVal}`}>{statusVal}</span>
                </div>
              </div>

              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>{agent.desc}</p>

              <div className="agent-stats">
                {agent.statKeys.map(([k, label]) => (
                  <div className="agent-stat" key={k}>
                    <span className="agent-stat-label">{label}</span>
                    <span className="agent-stat-value">
                      {k === 'last_action' ? fmtTime(st[k]) : (st[k] ?? 0)}
                    </span>
                  </div>
                ))}
                <div className="agent-stat">
                  <span className="agent-stat-label">Queue Depth</span>
                  <span className="agent-stat-value">
                    {agent.key === 'sentry'       ? (status?.alert_queue  ?? '—') :
                     agent.key === 'investigator' ? (status?.report_queue ?? '—') : '—'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live pipeline feed */}
      <div className="card" style={{ marginTop: 4 }}>
        <div className="card-title">Live Pipeline Events</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0, maxHeight: 320, overflowY: 'auto' }}>
          {events.filter(e => ['ALERT','INVESTIGATION','RESPONSE'].includes(e.type)).slice(0, 30).map((ev, i) => (
            <div key={i} className="log-line" style={{ fontFamily: 'var(--font-mono)', fontSize: 12, borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
              <span style={{ color: 'var(--text-muted)', minWidth: 80 }}>{new Date(ev.timestamp).toLocaleTimeString()}</span>
              <span className={`badge ${ev.severity || 'INFO'}`} style={{ minWidth: 70, justifyContent: 'center' }}>{ev.type}</span>
              <span style={{ color: 'var(--text-secondary)' }}>
                [{ev.agent}] {JSON.stringify(ev.data).slice(0, 120)}
              </span>
            </div>
          ))}
          {events.filter(e => ['ALERT','INVESTIGATION','RESPONSE'].includes(e.type)).length === 0 && (
            <div className="empty-state"><div className="empty-icon">🔄</div><div className="empty-text">Pipeline events will appear here</div></div>
          )}
        </div>
      </div>
    </div>
  );
}
