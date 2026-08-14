import { createContext, useContext, useEffect, useRef, useState } from 'react';
import { getWsUrl } from './api';

// ── Context ──────────────────────────────────────────────────────────────────
const SocContext = createContext(null);

export function useSoc() {
  return useContext(SocContext);
}

// ── Provider ─────────────────────────────────────────────────────────────────
export function SocProvider({ children }) {
  const [wsConnected, setWsConnected]   = useState(false);
  const [events, setEvents]             = useState([]);        // last 500 events
  const [liveAlerts, setLiveAlerts]     = useState(0);
  const [notifications, setNotifications] = useState([]);
  const wsRef = useRef(null);

  function connect() {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(getWsUrl());
    wsRef.current = ws;

    ws.onopen  = () => setWsConnected(true);
    ws.onclose = () => {
      setWsConnected(false);
      // Reconnect after 3 s
      setTimeout(connect, 3000);
    };
    ws.onerror = () => ws.close();

    ws.onmessage = (msg) => {
      try {
        const ev = JSON.parse(msg.data);
        setEvents(prev => [ev, ...prev].slice(0, 500));

        if (ev.type === 'ALERT') {
          setLiveAlerts(n => n + 1);
        }
        if (ev.type === 'NOTIFICATION') {
          setNotifications(prev => [ev, ...prev].slice(0, 50));
        }
      } catch { /* ignore */ }
    };
  }

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, []);

  return (
    <SocContext.Provider value={{ wsConnected, events, liveAlerts, notifications, setLiveAlerts }}>
      {children}
    </SocContext.Provider>
  );
}
