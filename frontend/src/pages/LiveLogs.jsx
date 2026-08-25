import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { useSoc } from '../SocContext';
import {
  RefreshCw,
  Search,
  FileText,
  Radio,
} from '../components/Icons';

const LEVELS = ['ALL', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];

export default function LiveLogs() {
  const { events } = useSoc();
  const [level, setLevel]           = useState('ALL');
  const [search, setSearch]         = useState('');
  const [logs, setLogs]             = useState([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const logContainerRef             = useRef(null);
  const topRef                      = useRef(null);

  // Fetch historical logs on mount + refresh
  async function fetchLogs() {
    try {
      const res = await api.logs({ limit: 300, level: level === 'ALL' ? '' : level, search });
      setLogs(res.entries || []);
    } catch { /* ignore */ }
  }

  useEffect(() => { fetchLogs(); }, [level, search]);

  // Merge live log events from WebSocket (newest first)
  const liveLines = events
    .filter(e => e.type === 'LOG' || (e.data?.message && typeof e.data.message === 'string'))
    .map(e => ({
      raw: `${new Date(e.timestamp).toLocaleTimeString()}  [${e.agent}]  ${e.data?.message || JSON.stringify(e.data)}`,
      level: e.severity || 'INFO',
    }))
    .filter(l => level === 'ALL' || l.level === level)
    .filter(l => !search || l.raw.toLowerCase().includes(search.toLowerCase()));

  // All lines combined (newest on top)
  const allLines = [...liveLines.slice(0, 100), ...logs].slice(0, 400);

  // Auto-scroll stays pinned to top where newest live logs appear
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, [allLines.length, autoScroll]);

  return (
    <div className="page" style={{ display: 'flex', flexDirection: 'column', height: '100%', paddingBottom: 0 }}>
      <div className="page-header" style={{ marginBottom: 16 }}>
        <div>
          <h2>Live Agent Logs</h2>
          <p>Real-time log stream · {allLines.length} events buffered · Newest logs appear at top</p>
        </div>
        <button className="btn btn-secondary" onClick={fetchLogs}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>

      <div className="log-stream" style={{ flex: 1, height: 'auto' }}>
        {/* Toolbar */}
        <div className="log-toolbar">
          <div className="chip-group">
            {LEVELS.map(l => (
              <button
                key={l}
                className={`chip ${level === l ? 'active ' + l : ''}`}
                onClick={() => setLevel(l)}
              >
                {l}
              </button>
            ))}
          </div>

          <div className="search-input-wrapper" style={{ marginLeft: 'auto', width: 220 }}>
            <Search size={14} className="search-icon" />
            <input
              className="search-input"
              placeholder="Search logs…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>

          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5, color: 'var(--text-secondary)', cursor: 'pointer', flexShrink: 0 }}>
            <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
            <span>Pin to newest</span>
          </label>
        </div>

        {/* Lines Container (scrolls to top for newest logs) */}
        <div className="log-lines" ref={logContainerRef}>
          <div ref={topRef} />
          {allLines.length === 0 && (
            <div className="empty-state">
              <div className="empty-icon">
                <FileText size={22} />
              </div>
              <div className="empty-text">No matching log entries found. Start the engine in Settings to begin stream.</div>
            </div>
          )}
          {allLines.map((entry, i) => {
            const lvl = entry.level || 'INFO';
            const isLive = i < liveLines.length;
            return (
              <div key={i} className={`log-line${isLive ? ' event-flash' : ''}`}>
                {isLive && <span style={{ color: 'var(--primary)', fontSize: 10, minWidth: 6 }}>●</span>}
                <span className={`log-level ${lvl}`}>{lvl.slice(0, 4)}</span>
                <span className="log-text">{entry.raw}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
