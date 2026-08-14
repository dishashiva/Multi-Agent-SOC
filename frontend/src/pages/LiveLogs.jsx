import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { useSoc } from '../SocContext';

const LEVELS = ['ALL', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];

export default function LiveLogs() {
  const { events } = useSoc();
  const [level, setLevel]   = useState('ALL');
  const [search, setSearch] = useState('');
  const [logs, setLogs]     = useState([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const bottomRef = useRef(null);

  // Fetch historical logs on mount + refresh
  async function fetchLogs() {
    try {
      const res = await api.logs({ limit: 300, level: level === 'ALL' ? '' : level, search });
      setLogs(res.entries || []);
    } catch { /* ignore */ }
  }

  useEffect(() => { fetchLogs(); }, [level, search]);

  // Merge live log events from WebSocket
  const liveLines = events
    .filter(e => e.type === 'LOG' || (e.data?.message && typeof e.data.message === 'string'))
    .map(e => ({
      raw: `${new Date(e.timestamp).toLocaleTimeString()}  [${e.agent}]  ${e.data?.message || JSON.stringify(e.data)}`,
      level: e.severity || 'INFO',
    }))
    .filter(l => level === 'ALL' || l.level === level)
    .filter(l => !search || l.raw.toLowerCase().includes(search.toLowerCase()));

  // All lines combined
  const allLines = [...liveLines.slice(0, 100), ...logs].slice(0, 400);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [allLines.length, autoScroll]);

  function lvlColor(l) {
    if (l === 'CRITICAL') return '#ff3b3b';
    if (l === 'ERROR')    return '#ff3b3b';
    if (l === 'WARNING')  return '#ffd700';
    if (l === 'INFO')     return '#58a6ff';
    return '#484f58';
  }

  return (
    <div className="page" style={{ display: 'flex', flexDirection: 'column', height: '100%', paddingBottom: 0 }}>
      <div className="page-header" style={{ marginBottom: 16 }}>
        <div>
          <h2>Live Logs</h2>
          <p>Real-time agent log stream · {allLines.length} entries</p>
        </div>
        <button className="btn btn-secondary" onClick={fetchLogs}>↻ Refresh</button>
      </div>

      <div className="log-stream" style={{ flex: 1, height: 'auto' }}>
        {/* Toolbar */}
        <div className="log-toolbar">
          <div className="chip-group">
            {LEVELS.map(l => (
              <button key={l} className={`chip ${level === l ? 'active ' + l : ''}`} onClick={() => setLevel(l)}>{l}</button>
            ))}
          </div>
          <input
            className="search-input"
            placeholder="Search logs…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ marginLeft: 'auto', width: 200 }}
          />
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--text-muted)', cursor: 'pointer', flexShrink: 0 }}>
            <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} />
            Auto-scroll
          </label>
        </div>

        {/* Lines */}
        <div className="log-lines">
          {allLines.length === 0 && (
            <div className="empty-state"><div className="empty-icon">📋</div><div className="empty-text">No log entries. Start the engine in Settings.</div></div>
          )}
          {allLines.map((entry, i) => {
            const lvl = entry.level || 'INFO';
            const isLive = i < liveLines.length;
            return (
              <div key={i} className={`log-line${isLive ? ' event-flash' : ''}`}>
                {isLive && <span style={{ color: 'var(--cyan)', fontSize: 10, minWidth: 6 }}>●</span>}
                <span className={`log-level ${lvl}`}>{lvl.slice(0,4)}</span>
                <span className="log-text">{entry.raw}</span>
              </div>
            );
          })}
          <div ref={bottomRef} />
        </div>
      </div>
    </div>
  );
}
