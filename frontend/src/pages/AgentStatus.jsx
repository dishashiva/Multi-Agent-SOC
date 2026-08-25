import { useEffect, useState } from 'react';
import { api } from '../api';
import { useSoc } from '../SocContext';
import {
  Eye,
  Search,
  Zap,
  ArrowRight,
  RefreshCw,
  Cpu,
  Layers,
} from '../components/Icons';

const AGENTS = [
  {
    key: 'sentry',
    name: 'Sentry',
    role: 'Log Watchdog & Threat Detector',
    IconComponent: Eye,
    cls: 'sentry',
    desc: 'Monitors the target directory for log file changes in real time. Analyzes modifications with AI and rule-based heuristics.',
    statKeys: [['alerts_sent', 'Alerts Generated'], ['last_action', 'Last Action']],
  },
  {
    key: 'investigator',
    name: 'Investigator',
    role: 'Forensic Analyst & Correlator',
    IconComponent: Search,
    cls: 'investigator',
    desc: 'Receives Sentry alerts and performs forensic correlation: IP threat extraction, contextual log analysis, and LLM triage.',
    statKeys: [['reports_sent', 'Reports Generated'], ['last_action', 'Last Action']],
  },
  {
    key: 'responder',
    name: 'Responder',
    role: 'Autonomous Mitigation Engine',
    IconComponent: Zap,
    cls: 'responder',
    desc: 'Processes forensic reports and applies automated actions: IP blocklisting, user account locking, quarantine, or human escalation.',
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

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h2>Agent Status & Multi-Agent Pipeline</h2>
          <p>Real-time lifecycle and performance metrics for the autonomous SOC agent triad</p>
        </div>
        <span className={`badge ${running ? 'running' : 'idle'}`} style={{ fontSize: 12 }}>
          {running ? 'Pipeline Active' : 'Pipeline Idle'}
        </span>
      </div>

      {/* Pipeline diagram */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 24,
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)',
          padding: '16px 20px',
          overflowX: 'auto',
          boxShadow: 'var(--shadow-xs)',
        }}
      >
        <div style={{ padding: '8px 14px', background: 'var(--cyan-dim)', border: '1px solid var(--cyan-border)', borderRadius: 'var(--radius-md)', fontSize: 12.5, fontWeight: 600, color: 'var(--cyan)', display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <Eye size={14} />
          Sentry (Detects Threats)
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
          <ArrowRight size={14} />
          <span>alert_queue</span>
          <ArrowRight size={14} />
        </div>

        <div style={{ padding: '8px 14px', background: 'var(--purple-dim)', border: '1px solid var(--purple-border)', borderRadius: 'var(--radius-md)', fontSize: 12.5, fontWeight: 600, color: 'var(--purple)', display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <Search size={14} />
          Investigator (Forensic Triage)
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)', flexShrink: 0 }}>
          <ArrowRight size={14} />
          <span>report_queue</span>
          <ArrowRight size={14} />
        </div>

        <div style={{ padding: '8px 14px', background: 'var(--high-dim)', border: '1px solid var(--high-border)', borderRadius: 'var(--radius-md)', fontSize: 12.5, fontWeight: 600, color: 'var(--high)', display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <Zap size={14} />
          Responder (Applies Mitigation)
        </div>
      </div>

      {/* Agent cards */}
      <div className="agent-grid">
        {AGENTS.map(agent => {
          const st = agents[agent.key] || {};
          const statusVal = st.status || (running ? 'running' : 'idle');
          const IconComp = agent.IconComponent;

          return (
            <div key={agent.key} className={`agent-card ${agent.cls}`}>
              <div className="agent-header">
                <div>
                  <div className="agent-icon-wrap">
                    <IconComp size={20} />
                  </div>
                  <div className="agent-name">{agent.name}</div>
                  <div className="agent-role">{agent.role}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span className={`pulse-ring ${running ? 'running' : ''}`} />
                  <span className={`badge ${statusVal}`}>{statusVal}</span>
                </div>
              </div>

              <p style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>{agent.desc}</p>

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
                    {agent.key === 'sentry'       ? (status?.alert_queue  ?? '0') :
                     agent.key === 'investigator' ? (status?.report_queue ?? '0') : '—'}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live pipeline feed */}
      <div className="card" style={{ marginTop: 4 }}>
        <div className="card-title">
          <Layers size={16} />
          Live Pipeline Stream
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0, maxHeight: 320, overflowY: 'auto' }}>
          {events.filter(e => ['ALERT','INVESTIGATION','RESPONSE'].includes(e.type)).slice(0, 30).map((ev, i) => (
            <div
              key={i}
              className="log-line"
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 12,
                borderBottom: '1px solid var(--border)',
                padding: '8px 12px',
              }}
            >
              <span style={{ color: 'var(--text-muted)', minWidth: 80 }}>{new Date(ev.timestamp).toLocaleTimeString()}</span>
              <span className={`badge ${ev.severity || 'INFO'}`} style={{ minWidth: 70, justifyContent: 'center' }}>{ev.type}</span>
              <span style={{ color: 'var(--text-primary)', marginLeft: 8 }}>
                <strong>[{ev.agent}]</strong> {JSON.stringify(ev.data).slice(0, 130)}
              </span>
            </div>
          ))}
          {events.filter(e => ['ALERT','INVESTIGATION','RESPONSE'].includes(e.type)).length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">
                <RefreshCw size={22} />
              </div>
              <div className="empty-text">Pipeline dispatch events will stream in this window when active</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
