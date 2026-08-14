"""
audit_db.py - SQLite Audit Log
----------------------------------------------------------------------------
Persists every agent action, alert, and system event to a local SQLite DB.
Thread-safe: uses a single serialized connection protected by a threading.Lock.

Schema
------
    audit_events (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    TEXT    NOT NULL,
        agent        TEXT    NOT NULL,   -- SENTRY | INVESTIGATOR | RESPONDER | SYSTEM
        event_type   TEXT    NOT NULL,   -- e.g. ALERT, INVESTIGATION, ACTION, INFO
        severity     TEXT    NOT NULL,   -- LOW | MEDIUM | HIGH | CRITICAL | INFO
        message      TEXT    NOT NULL,
        details_json TEXT                -- optional JSON blob
    )
----------------------------------------------------------------------------
"""

import json
import sqlite3
import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).parent / "audit.db"
_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _create_schema(_conn)
        logger.info(f"[AuditDB] Connected to {_DB_PATH}")
    return _conn


def _create_schema(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp    TEXT    NOT NULL,
            agent        TEXT    NOT NULL,
            event_type   TEXT    NOT NULL,
            severity     TEXT    NOT NULL,
            message      TEXT    NOT NULL,
            details_json TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events (timestamp DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_agent ON audit_events (agent)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON audit_events (severity)")
    conn.commit()


def log_event(
    agent: str,
    event_type: str,
    severity: str,
    message: str,
    details: Optional[dict] = None,
) -> int:
    """
    Insert one audit event. Returns the new row id.
    Safe to call from any thread.
    """
    ts = datetime.now().isoformat()
    details_json = json.dumps(details) if details else None

    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            """INSERT INTO audit_events
               (timestamp, agent, event_type, severity, message, details_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (ts, agent, event_type, severity, message, details_json),
        )
        conn.commit()
        return cur.lastrowid


def get_events(
    limit: int = 200,
    offset: int = 0,
    agent: Optional[str] = None,
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
) -> list[dict]:
    """Return audit events as a list of dicts, newest first."""
    clauses = []
    params: list = []

    if agent:
        clauses.append("agent = ?")
        params.append(agent.upper())
    if severity:
        clauses.append("severity = ?")
        params.append(severity.upper())
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type.upper())

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params += [limit, offset]

    with _lock:
        conn = _get_conn()
        rows = conn.execute(
            f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()

    return [dict(r) for r in rows]


def get_event_count() -> int:
    with _lock:
        conn = _get_conn()
        return conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]


def get_stats() -> dict:
    """Return per-severity and per-agent counts for dashboard KPIs."""
    with _lock:
        conn = _get_conn()
        by_severity = {
            r["severity"]: r["cnt"]
            for r in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM audit_events GROUP BY severity"
            ).fetchall()
        }
        by_agent = {
            r["agent"]: r["cnt"]
            for r in conn.execute(
                "SELECT agent, COUNT(*) as cnt FROM audit_events GROUP BY agent"
            ).fetchall()
        }
        recent_alerts = conn.execute(
            """SELECT COUNT(*) FROM audit_events
               WHERE event_type='ALERT'
               AND timestamp >= datetime('now', '-1 hour')"""
        ).fetchone()[0]

    return {
        "by_severity": by_severity,
        "by_agent": by_agent,
        "recent_alerts_1h": recent_alerts,
        "total": sum(by_agent.values()),
    }
