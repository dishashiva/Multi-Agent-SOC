"""
responder.py - Agent 3: The Responder
----------------------------------------------------------------------------
Receives investigation_report dicts from the Investigator via report_queue.

Responsibilities
----------------
1. classify_threat()     - ask the LLM to decide the action and severity
2. Execute one of the tool functions based on the decision:
       block_ip()          -> simulates iptables rule
       lock_user()         -> simulates usermod -L
       quarantine_file()   -> moves a suspicious file to ./quarantine/
       create_file()       -> create a new file (used for reports)
       write_file()        -> append/overwrite a file
       update_file()       -> find-and-replace inside a file
       delete_file()       -> delete (scoped to ./reports/ only for safety)
       run_command()       -> whitelisted shell commands only
3. generate_incident_report() - write a Markdown report to ./reports/
4. notify_human()         - if the threat cannot be auto-resolved, alert
                            the operator prominently in the terminal and in
                            a notifications log.

SAFETY
------
* simulate_only=True  (default) - no real command is ever executed.
  All actions print what they WOULD do. Perfect for a prototype/demo.
* run_command() enforces a strict whitelist regardless of simulate_only.
* delete_file() is restricted to the ./reports/ directory.
----------------------------------------------------------------------------
"""

import os
import re
import uuid
import json
import queue
import shlex
import shutil
import logging
import subprocess
from datetime import datetime
from pathlib import Path

from nvidia_nim_client import NvidiaNimClient

logger = logging.getLogger(__name__)

# -- LLM role for the Responder ------------------------------------------------
RESPONDER_SYSTEM_PROMPT = """You are an autonomous SOC incident-responder.
Given a security investigation report, decide the best response action.

Available actions  (choose exactly one):
    NO_ACTION        - benign, nothing to do
    MONITOR          - low risk; keep watching, log only
    BLOCK_IP         - block a source IP at the firewall
    LOCK_USER        - disable a compromised user account
    QUARANTINE_FILE  - isolate a malicious or suspicious file
    DELETE_FILE      - permanently remove a confirmed-malicious file (use with care)
    ESCALATE_HUMAN   - threat is too complex for automation; human must step in

You MUST respond with ONLY valid JSON (nothing outside the braces):
{
    "action":             "<one of the actions above>",
    "target":             "<IP address | username | file path | null>",
    "simulated_command":  "<exact shell command that would be run, or null>",
    "can_auto_resolve":   true | false,
    "escalation_reason":  "<why a human is needed, or null>",
    "incident_title":     "<short descriptive title>",
    "incident_report_md": "<complete Markdown incident report - see format below>"
}

Auxiliary Commands:
In the "simulated_command" field, you can provide a shell command for additional diagnostics or remediation.
Whitelisted commands include:
- Network: iptables, ufw, firewall-cmd, ipconfig, netstat, ss, ping, nslookup
- Identity: usermod, passwd, whoami, id, last, lastlog, quser
- Processes: pkill, kill, ps, tasklist, taskkill, lsof
- Services/Logs: systemctl, service, journalctl, sc, net, wevtutil
- Filesystem: ls, dir, find, stat, df, du, cat, grep, chmod, chown, cp, mv, mkdir
- Misc: echo, date, hostname, logger, sleep

Incident report format:
# Incident Report: {incident_id}
**Timestamp:** ...
**Severity:** ...
**Type:** ...
## Summary
...
## Evidence
...
## Root Cause Analysis
| | |
|-|-|
| Why | ... |
| Where | ... |
| How | ... |
| Impact | ... |
## Actions Taken
...
## Recommendations
...
"""

# -- Shell commands the Responder is permitted to run (whitelist) ---------------
ALLOWED_COMMANDS: set[str] = {
    # -- Network Diagnostics & Firewall --
    "iptables", "ufw", "firewall-cmd", "nft", "ipconfig", "ifconfig", "netstat", "ss", "ping", "nslookup", "dig",

    # -- Identity & Access Management --
    "usermod", "passwd", "chage", "last", "lastlog", "whoami", "id", "who", "w", "quser",

    # -- Process Analysis & Control --
    "pkill", "kill", "ps", "pgrep", "top", "tasklist", "taskkill", "lsof",

    # -- Service & Log Management --
    "systemctl", "service", "journalctl", "sc", "net", "wevtutil",

    # -- Filesystem & System Information --
    "ls", "dir", "find", "stat", "df", "du", "free", "uptime", "hostname", "date",

    # -- File Investigation & Text Processing --
    "cat", "head", "tail", "grep", "awk", "sed", "type", "findstr",

    # -- File System Remediation --
    "chmod", "chown", "icacls", "cp", "mv", "mkdir", "cd",

    # -- Miscellaneous --
    "echo", "logger", "sleep", "true", "false"
}


class ResponderAgent:
    """
    Agent 3 - The Responder

    Usage
    -----
    responder = ResponderAgent(
        report_queue  = report_q,
        ollama_client = client,
        simulate_only = True,      # <--- keep True for demo/prototype
        reports_dir   = "reports",
    )
    responder.run()    # blocking; run in a Thread
    """

    def __init__(
        self,
        report_queue: queue.Queue,
        nim_client: NvidiaNimClient,
        simulate_only: bool = True,
        reports_dir: str = "reports",
        quarantine_dir: str = "quarantine",
    ):
        self.report_queue   = report_queue
        self.nim            = nim_client
        self.simulate_only  = simulate_only
        self.reports_dir    = os.path.abspath(reports_dir)
        self.quarantine_dir = os.path.abspath(quarantine_dir)
        self._running       = False

        Path(reports_dir).mkdir(parents=True, exist_ok=True)
        Path(quarantine_dir).mkdir(parents=True, exist_ok=True)

        mode_label = "SIMULATE ONLY" if simulate_only else "LIVE (real commands)"
        logger.info(f"[RESPONDER] Initialised. Mode={mode_label}. Reports -> '{reports_dir}/'")

    # ==========================================================================
    #  TOOL FUNCTIONS
    # ==========================================================================

    def create_file(self, file_path: str, content: str = "") -> dict:
        """Create a new file (and any missing parent directories) with content."""
        try:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            logger.info(f"[RESPONDER] create_file OK  '{file_path}'")
            return {"success": True, "action": "created", "file": file_path}
        except Exception as exc:
            logger.error(f"[RESPONDER] create_file failed: {exc}")
            return {"success": False, "error": str(exc)}

    # --------------------------------------------------------------------------
    def write_file(self, file_path: str, content: str, mode: str = "a") -> dict:
        """
        Append (mode='a') or overwrite (mode='w') a file.
        Creates the file if it does not exist.
        """
        try:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, mode, encoding="utf-8") as fh:
                fh.write(content)
            action = "appended" if mode == "a" else "overwritten"
            logger.info(f"[RESPONDER] write_file OK  '{file_path}' ({action})")
            return {"success": True, "action": action, "file": file_path}
        except Exception as exc:
            logger.error(f"[RESPONDER] write_file failed: {exc}")
            return {"success": False, "error": str(exc)}

    # --------------------------------------------------------------------------
    def update_file(self, file_path: str, old_text: str, new_text: str) -> dict:
        """Replace every occurrence of old_text with new_text inside file_path."""
        try:
            with open(file_path, "r", encoding="utf-8") as fh:
                content = fh.read()

            if old_text not in content:
                return {"success": False, "error": f"'{old_text}' not found in file."}

            replacements = content.count(old_text)
            updated = content.replace(old_text, new_text)

            with open(file_path, "w", encoding="utf-8") as fh:
                fh.write(updated)

            logger.info(f"[RESPONDER] update_file OK  '{file_path}' ({replacements} replacements)")
            return {"success": True, "replacements": replacements, "file": file_path}
        except Exception as exc:
            logger.error(f"[RESPONDER] update_file failed: {exc}")
            return {"success": False, "error": str(exc)}

    # --------------------------------------------------------------------------
    def delete_file(self, file_path: str) -> dict:
        """
        Delete a file.
        SAFETY: Only files inside reports_dir can be deleted.
        (Prevents the agent from accidentally deleting system files.)
        """
        abs_target = os.path.abspath(file_path)

        if not abs_target.startswith(self.reports_dir):
            logger.warning(f"[RESPONDER] delete_file BLOCKED (outside reports dir): {file_path}")
            return {
                "success": False,
                "blocked": True,
                "reason":  "Deletion is only allowed inside the reports/ directory.",
            }
        try:
            os.remove(abs_target)
            logger.info(f"[RESPONDER] delete_file OK  '{file_path}'")
            return {"success": True, "action": "deleted", "file": file_path}
        except FileNotFoundError:
            return {"success": False, "error": "File not found."}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # --------------------------------------------------------------------------
    def quarantine_file(self, file_path: str) -> dict:
        """
        Move a suspicious file to the quarantine directory.
        In simulate_only mode, logs the intended action without moving.
        """
        if not file_path or not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        filename = os.path.basename(file_path)
        dest = os.path.join(
            self.quarantine_dir,
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}",
        )

        if self.simulate_only:
            logger.info(f"[RESPONDER] [SIMULATED] quarantine_file: '{file_path}' -> '{dest}'")
            return {"success": True, "simulated": True, "source": file_path, "destination": dest}

        try:
            shutil.move(file_path, dest)
            logger.info(f"[RESPONDER] quarantine_file OK  '{file_path}' -> '{dest}'")
            return {"success": True, "simulated": False, "source": file_path, "destination": dest}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # --------------------------------------------------------------------------
    def run_command(self, command: str) -> dict:
        """
        Execute a shell command with a strict whitelist and optional simulation.

        Security model
        --------------
        1. Parse command with shlex.split (handles quoting correctly).
        2. Check the base binary against ALLOWED_COMMANDS.
        3. If simulate_only=True  -> print the command, return fake success.
        4. If simulate_only=False -> run with subprocess, 10-second timeout.
        """
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            return {"success": False, "error": f"Command parse error: {exc}"}

        if not parts:
            return {"success": False, "error": "Empty command."}

        base_cmd = parts[0]

        # -- whitelist check ------------------------------------------------
        if base_cmd not in ALLOWED_COMMANDS:
            logger.warning(f"[RESPONDER] run_command BLOCKED (not in whitelist): '{command}'")
            return {
                "success": False,
                "blocked": True,
                "command": command,
                "reason":  f"'{base_cmd}' is not in the allowed command list.",
                "allowed": sorted(ALLOWED_COMMANDS),
            }

        # -- simulation mode ------------------------------------------------
        if self.simulate_only:
            logger.info(f"[RESPONDER] [SIMULATED] $ {command}")
            return {
                "success":   True,
                "simulated": True,
                "command":   command,
                "stdout":    f"[SIMULATION] Would have run: {command}",
                "returncode": 0,
            }

        # -- real execution -------------------------------------------------
        try:
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=10,
            )
            ok = result.returncode == 0
            logger.info(f"[RESPONDER] $ {command}  ->  RC={result.returncode}")
            return {
                "success":    ok,
                "simulated":  False,
                "command":    command,
                "stdout":     result.stdout,
                "stderr":     result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out (>10 s)."}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # --------------------------------------------------------------------------
    #  High-level convenience wrappers (call run_command internally)
    # --------------------------------------------------------------------------

    def block_ip(self, ip: str) -> dict:
        """Simulate/execute iptables DROP rule for an IP."""
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return {"success": False, "error": f"Invalid IP: {ip}"}
        logger.warning(f"[RESPONDER] [ACTION] Blocking IP: {ip}")
        return self.run_command(f"iptables -A INPUT -s {ip} -j DROP")

    def lock_user(self, username: str) -> dict:
        """Simulate/execute usermod -L to lock an account."""
        if not re.match(r'^\w[\w.-]{0,31}$', username):
            return {"success": False, "error": f"Invalid username: {username}"}
        logger.warning(f"[RESPONDER] [ACTION] Locking user account: {username}")
        return self.run_command(f"usermod -L {username}")

    # --------------------------------------------------------------------------
    def notify_human(self, incident_id: str, reason: str, report_path: str):
        """
        Alert a human operator when the system cannot auto-resolve a threat.

        Prototype behaviour  - prints a banner to the terminal + writes to
                               reports/HUMAN_NOTIFICATIONS.log
        Production extension - add email / Slack / PagerDuty here.
        """
        border = "=" * 64
        banner = (
            f"\n{border}\n"
            f"!!  HUMAN INTERVENTION REQUIRED  !!\n"
            f"{border}\n"
            f"Incident ID : {incident_id}\n"
            f"Time        : {datetime.now().isoformat()}\n"
            f"Reason      : {reason}\n"
            f"Report File : {report_path}\n"
            f"\nThe autonomous responder could NOT resolve this incident.\n"
            f"Please open the report and take manual action.\n"
            f"{border}\n"
        )
        logger.critical(banner)

        notif_log = os.path.join(self.reports_dir, "HUMAN_NOTIFICATIONS.log")
        self.write_file(notif_log, banner + "\n", mode="a")

    # ==========================================================================
    #  MAIN RESPONSE FUNCTION
    # ==========================================================================

    def classify_and_respond(self, investigation_report: dict) -> dict:
        """
        Main entry point for a single investigation report.

        Flow
        ----
        1. Ask LLM to classify + decide action.
        2. Execute the decided action using the appropriate tool.
        3. Write the incident report Markdown to ./reports/.
        4. Notify human if escalation is required.
        5. Return a summary dict.
        """
        incident_id = (
            f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            f"-{str(uuid.uuid4())[:4].upper()}"
        )

        alert       = investigation_report.get("original_alert", {})
        ai_analysis = investigation_report.get("ai_analysis", {})
        evidence    = investigation_report.get("evidence", {})
        severity    = alert.get("severity", "LOW")
        event_type  = alert.get("event_type", "UNKNOWN")

        logger.info(
            f"\n[RESPONDER] [ACTION] Responding | "
            f"Incident={incident_id} | Severity={severity} | Type={event_type}"
        )

        # -- Step 1: Ask LLM to decide action ------------------------------
        prompt = (
            f"=== INVESTIGATION REPORT ===\n"
            f"Incident ID   : {incident_id}\n"
            f"Severity      : {severity}\n"
            f"Event Type    : {event_type}\n"
            f"File          : {alert.get('file_path')}\n"
            f"IPs           : {evidence.get('extracted_ips', [])}\n"
            f"Users         : {evidence.get('extracted_users', [])}\n\n"
            f"=== AI INVESTIGATOR FINDINGS ===\n"
            f"WHY    : {ai_analysis.get('why')}\n"
            f"WHERE  : {ai_analysis.get('where')}\n"
            f"HOW    : {ai_analysis.get('how')}\n"
            f"IMPACT : {ai_analysis.get('impact')}\n"
            f"Recommendation: {ai_analysis.get('recommended_action')}\n"
            f"MITRE Tactic  : {ai_analysis.get('mitre_tactic')}\n\n"
            f"=== SENTRY DETAILS ===\n"
            f"Reason     : {alert.get('reason')}\n"
            f"Indicators : {alert.get('indicators', [])}\n\n"
            f"Now produce your response JSON for incident {incident_id}."
        )

        decision = self.nim.query_json(prompt, system=RESPONDER_SYSTEM_PROMPT)

        # Fallback if LLM fails
        if "error" in decision:
            logger.warning("[RESPONDER] LLM decision failed - defaulting to ESCALATE_HUMAN.")
            decision = {
                "action":             "ESCALATE_HUMAN",
                "target":             None,
                "simulated_command":  None,
                "can_auto_resolve":   False,
                "escalation_reason":  "AI responder could not parse the LLM response.",
                "incident_title":     f"Unresolved {event_type}",
                "incident_report_md": self._fallback_report(
                    incident_id, alert, ai_analysis, evidence
                ),
            }

        action  = decision.get("action", "MONITOR")
        target  = decision.get("target") or ""
        action_log: list[dict] = []

        # -- Step 2: Execute action -----------------------------------------
        if action == "BLOCK_IP" and target:
            result = self.block_ip(target)
            action_log.append({"action": "BLOCK_IP", "target": target, "result": result})

        elif action == "LOCK_USER" and target:
            result = self.lock_user(target)
            action_log.append({"action": "LOCK_USER", "target": target, "result": result})

        elif action == "QUARANTINE_FILE" and target:
            result = self.quarantine_file(target)
            action_log.append({"action": "QUARANTINE_FILE", "target": target, "result": result})

        elif action == "DELETE_FILE" and target:
            result = self.delete_file(target)
            action_log.append({"action": "DELETE_FILE", "target": target, "result": result})

        elif action in ("MONITOR", "NO_ACTION"):
            logger.info(f"[RESPONDER] [INFO] {action} - logging event, no hard action taken.")
            action_log.append({"action": action, "target": target or "N/A", "result": {"logged": True}})

        elif action == "ESCALATE_HUMAN":
            logger.warning("[RESPONDER] Escalating to human - will notify after report is written.")
            action_log.append({"action": "ESCALATE_HUMAN", "result": {"pending_notification": True}})

        # Also run the custom simulated command if one was provided
        cmd = decision.get("simulated_command")
        if cmd and action not in ("ESCALATE_HUMAN", "NO_ACTION"):
            cmd_result = self.run_command(cmd)
            action_log.append({"action": "RUN_COMMAND", "command": cmd, "result": cmd_result})

        # -- Step 3: Write incident report ----------------------------------
        report_md = decision.get("incident_report_md") or self._fallback_report(
            incident_id, alert, ai_analysis, evidence
        )

        # Append live action results to the report
        actions_section = (
            "\n\n---\n## Actions Taken by Responder\n\n"
            f"```json\n{json.dumps(action_log, indent=2)}\n```\n"
            f"\n*Simulate-only mode: {self.simulate_only}*\n"
            f"\n*Report generated: {datetime.now().isoformat()}*\n"
        )
        report_md += actions_section

        report_filename = f"{incident_id}.md"
        report_path     = os.path.join(self.reports_dir, report_filename)
        self.create_file(report_path, report_md)

        logger.info(f"[RESPONDER] [INFO] Report saved: {report_path}")

        # -- Step 4: Escalate to human if needed ---------------------------
        if action == "ESCALATE_HUMAN" or not decision.get("can_auto_resolve", True):
            self.notify_human(
                incident_id,
                decision.get("escalation_reason") or "Threat requires manual review.",
                report_path,
            )

        # -- Step 5: Return summary -----------------------------------------
        summary = {
            "incident_id":        incident_id,
            "timestamp":          datetime.now().isoformat(),
            "severity":           severity,
            "event_type":         event_type,
            "action_taken":       action,
            "action_log":         action_log,
            "report_path":        report_path,
            "escalated_to_human": action == "ESCALATE_HUMAN",
            "investigation_id":   investigation_report.get("investigation_id"),
        }

        logger.info(
            f"[RESPONDER] OK Complete | "
            f"Incident={incident_id} | Action={action} | Report={report_path}"
        )
        return summary

    # ==========================================================================
    #  HELPERS
    # ==========================================================================

    def _fallback_report(
        self,
        incident_id: str,
        alert: dict,
        ai_analysis: dict,
        evidence: dict,
    ) -> str:
        """Minimal Markdown report used when the LLM cannot produce one."""
        return (
            f"# Incident Report: {incident_id}\n\n"
            f"**Timestamp:** {datetime.now().isoformat()}  \n"
            f"**Severity:** {alert.get('severity', 'UNKNOWN')}  \n"
            f"**Type:** {alert.get('event_type', 'UNKNOWN')}  \n\n"
            f"## Summary\n"
            f"A {alert.get('event_type', 'security')} event was detected in "
            f"`{alert.get('file_path', 'unknown file')}`.\n\n"
            f"## Evidence\n"
            f"- **IPs Found:** {evidence.get('extracted_ips', [])}\n"
            f"- **Users Found:** {evidence.get('extracted_users', [])}\n"
            f"- **Related Log Hits:** {len(evidence.get('related_events', []))}\n\n"
            f"## Root Cause Analysis\n"
            f"| | |\n|-|-|\n"
            f"| **Why** | {ai_analysis.get('why', 'N/A')} |\n"
            f"| **Where** | {ai_analysis.get('where', 'N/A')} |\n"
            f"| **How** | {ai_analysis.get('how', 'N/A')} |\n"
            f"| **Impact** | {ai_analysis.get('impact', 'N/A')} |\n\n"
            f"## Recommendations\n"
            f"{ai_analysis.get('recommended_action', 'Manual review required.')}\n\n"
            f"---\n*Generated by SOC-in-a-Box Responder (Fallback Mode)*\n"
        )

    # ==========================================================================
    #  MAIN LOOP
    # ==========================================================================

    def run(self):
        """
        Blocking loop.
        Reads investigation_report dicts from report_queue and processes them.
        Run in a threading.Thread.
        """
        self._running = True
        logger.info("[RESPONDER] [ACTION] Ready - waiting for investigation reports...")

        while self._running:
            try:
                report = self.report_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self.classify_and_respond(report)
            except Exception as exc:
                logger.error(f"[RESPONDER] Unhandled error: {exc}", exc_info=True)
            finally:
                self.report_queue.task_done()

    def stop(self):
        self._running = False
        logger.info("[RESPONDER] Stopped.")
