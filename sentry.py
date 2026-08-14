"""
sentry.py - Agent 1: The Sentry
----------------------------------------------------------------------------
Watches a folder for log file events (create / modify / delete).
Every change is read and sent to the local LLM for threat analysis.
Suspicious findings are put on the shared alert_queue for the Investigator.

No external APIs. No cloud. Runs 100 % locally.
----------------------------------------------------------------------------
"""

import os
import re
import json
import time
import queue
import logging
from datetime import datetime
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from nvidia_nim_client import NvidiaNimClient

logger = logging.getLogger(__name__)

# -- System prompt that tells the LLM what role it plays ----------------------
SENTRY_SYSTEM_PROMPT = """You are a cybersecurity anomaly-detection engine embedded in a SOC.
Analyze the log content provided and decide whether it contains suspicious or malicious activity.

You MUST respond with ONLY a valid JSON object - no preamble, no explanation outside the JSON:
{
    "is_suspicious": true | false,
    "severity":      "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "event_type":    "BRUTE_FORCE" | "DATA_EXFILTRATION" | "UNAUTHORIZED_ACCESS" |
                     "PRIVILEGE_ESCALATION" | "MALWARE" | "LOG_TAMPERING" | "NORMAL",
    "reason":        "<one-sentence explanation>",
    "indicators":    ["<pattern1>", "<pattern2>"]
}"""

# -- Fallback rules used when LLM is offline -----------------------------------
FALLBACK_RULES = [
    # (regex_pattern, event_type, severity)
    (r"Failed password",              "BRUTE_FORCE",          "MEDIUM"),
    (r"authentication failure",       "BRUTE_FORCE",          "MEDIUM"),
    (r"Invalid user",                 "BRUTE_FORCE",          "HIGH"),
    (r"POSSIBLE BREAK-IN ATTEMPT",    "BRUTE_FORCE",          "CRITICAL"),
    (r"sudo.*FAILED",                 "PRIVILEGE_ESCALATION", "HIGH"),
    (r"/etc/shadow",                  "UNAUTHORIZED_ACCESS",  "CRITICAL"),
    (r"/etc/passwd",                  "UNAUTHORIZED_ACCESS",  "HIGH"),
    (r"rm\s+-rf",                     "MALWARE",              "HIGH"),
    (r"wget\s+http",                  "MALWARE",              "MEDIUM"),
    (r"curl\s+http",                  "MALWARE",              "MEDIUM"),
    (r"base64\s+-d",                  "MALWARE",              "HIGH"),
    (r"chmod\s+777",                  "PRIVILEGE_ESCALATION", "MEDIUM"),
    (r"\bnmap\b",                     "UNAUTHORIZED_ACCESS",  "MEDIUM"),
    (r"nc\s+-e",                      "MALWARE",              "CRITICAL"),   # netcat reverse shell
    (r"Accepted publickey.*root",     "UNAUTHORIZED_ACCESS",  "HIGH"),
]

SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# -----------------------------------------------------------------------------
class _LogEventHandler(FileSystemEventHandler):
    """
    Internal watchdog handler.  Not meant to be used directly -
    the SentryAgent creates and owns this.
    """

    def __init__(self, alert_queue: queue.Queue, nim: NvidiaNimClient, cooldown: float = 3.0):
        super().__init__()
        self.alert_queue = alert_queue
        self.nim = nim
        self._in_flight: set[str] = set()   # debounce: track files being processed
        self._cooldown = cooldown            # min seconds between API calls
        self._last_api_call: float = 0.0

    # -- watchdog callbacks ----------------------------------------------------
    def on_created(self, event):
        if not event.is_directory:
            self._analyze_change("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._analyze_change("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            # Can't read a deleted file - the deletion itself is suspicious
            self._emit_deletion_alert(event.src_path)

    # -- core analysis pipeline ------------------------------------------------
    def _analyze_change(self, trigger: str, file_path: str):
        """Read the file and run AI + fallback analysis on its last N lines."""
        if file_path in self._in_flight:
            return                          # already being processed
        self._in_flight.add(file_path)

        try:
            time.sleep(0.15)               # let the write fully flush to disk
            content = self._tail(file_path, n=60)
            if not content.strip():
                return

            # --- Rate limit: enforce cooldown between API calls ---
            now = time.time()
            elapsed = now - self._last_api_call
            if elapsed < self._cooldown:
                wait = self._cooldown - elapsed
                logger.info(f"[SENTRY] Throttling — waiting {wait:.1f}s before next analysis")
                time.sleep(wait)

            logger.info(f"[SENTRY] Analysing ({trigger}): {file_path}")

            # --- ask the LLM ---
            prompt = (
                f"Log file : {file_path}\n"
                f"Event    : {trigger}\n"
                f"Time     : {datetime.now().isoformat()}\n\n"
                f"--- BEGIN LOG CONTENT ---\n{content}\n--- END LOG CONTENT ---\n\n"
                f"Respond with JSON only."
            )
            self._last_api_call = time.time()
            analysis = self.nim.query_json(prompt, system=SENTRY_SYSTEM_PROMPT)

            # --- fall back to rule-based if LLM failed ---
            if "error" in analysis:
                logger.warning("[SENTRY] NVIDIA NIM unavailable - using rule-based fallback.")
                analysis = self._rule_based(content)

            if analysis.get("is_suspicious"):
                alert = {
                    "alert_id":   f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}",
                    "timestamp":  datetime.now().isoformat(),
                    "trigger":    trigger,
                    "file_path":  file_path,
                    "raw_log":    content,
                    **analysis,
                }
                self._log_alert(alert)
                self.alert_queue.put(alert)
            else:
                logger.info(f"[SENTRY] OK  Clean: {file_path}")

        except Exception as exc:
            logger.error(f"[SENTRY] Error processing {file_path}: {exc}")
        finally:
            self._in_flight.discard(file_path)

    def _emit_deletion_alert(self, file_path: str):
        """A deleted log file is always suspicious (potential evidence tampering)."""
        alert = {
            "alert_id":   f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}",
            "timestamp":  datetime.now().isoformat(),
            "trigger":    "DELETED",
            "file_path":  file_path,
            "raw_log":    "",
            "is_suspicious": True,
            "severity":   "HIGH",
            "event_type": "LOG_TAMPERING",
            "reason":     "Log file was deleted - possible evidence tampering.",
            "indicators": ["file_deletion"],
        }
        self._log_alert(alert)
        self.alert_queue.put(alert)

    # -- helpers ---------------------------------------------------------------
    def _tail(self, file_path: str, n: int = 60) -> str:
        """Return the last N lines of a file as a single string."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            return "".join(lines[-n:])
        except PermissionError:
            return f"[PERMISSION DENIED: cannot read {file_path}]"
        except Exception as exc:
            return f"[READ ERROR: {exc}]"

    def _rule_based(self, content: str) -> dict:
        """
        Simple regex rule engine - runs offline with no LLM.
        Iterates through FALLBACK_RULES and escalates severity as needed.
        """
        matched_indicators = []
        severity = "LOW"
        event_type = "NORMAL"

        for pattern, evt_type, sev in FALLBACK_RULES:
            if re.search(pattern, content, re.IGNORECASE):
                matched_indicators.append(pattern)
                event_type = evt_type
                if SEV_ORDER.index(sev) > SEV_ORDER.index(severity):
                    severity = sev

        suspicious = bool(matched_indicators)
        return {
            "is_suspicious": suspicious,
            "severity":      severity,
            "event_type":    event_type,
            "reason":        (
                f"Rule-based match: {', '.join(matched_indicators)}"
                if suspicious else "No suspicious patterns found."
            ),
            "indicators":    matched_indicators,
        }

    def _log_alert(self, alert: dict):
        logger.warning(
            f"[SENTRY] !!  THREAT DETECTED | "
            f"ID={alert['alert_id']} | "
            f"Severity={alert['severity']} | "
            f"Type={alert['event_type']} | "
            f"File={alert['file_path']}"
        )


# -----------------------------------------------------------------------------
class SentryAgent:
    """
    Agent 1 - The Sentry

    Usage
    -----
    sentry = SentryAgent(watch_path="./logs", alert_queue=q, ollama=client)
    sentry.start()          # non-blocking; runs watchdog in a background thread
    ...
    sentry.stop()
    """

    def __init__(
        self,
        watch_path: str,
        alert_queue: queue.Queue,
        nim_client: NvidiaNimClient,
        cooldown: float = 3.0,
    ):
        self.watch_path = watch_path
        self.alert_queue = alert_queue
        self.nim = nim_client
        self.cooldown = cooldown
        self._observer: Observer | None = None

        # Make sure the watched directory exists
        Path(watch_path).mkdir(parents=True, exist_ok=True)
        logger.info(f"[SENTRY] Initialised. Watching: '{watch_path}' (cooldown: {cooldown}s)")

    def start(self):
        """Start the file-system observer in its own background thread."""
        handler = _LogEventHandler(self.alert_queue, self.nim, cooldown=self.cooldown)
        self._observer = Observer()
        self._observer.schedule(handler, self.watch_path, recursive=True)
        self._observer.start()
        logger.info(f"[SENTRY] !!   Started - monitoring '{self.watch_path}' for threats...")

    def stop(self):
        """Cleanly stop the observer thread."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
            self._observer = None
        logger.info("[SENTRY] Stopped.")

    @property
    def is_running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()
