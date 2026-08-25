"""
responder.py - Agent 3: The Responder
----------------------------------------------------------------------------
Receives investigation_report dicts from the Investigator via report_queue.

Responsibilities
----------------
1. classify_threat()     - determine appropriate response action and remediation.
2. Execute tool functions: block_ip, lock_user, quarantine_file, run_command.
3. generate_incident_report() - write a Markdown report to ./reports/.
4. notify_human()         - alert human operator for critical/high threats.
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

RESPONDER_SYSTEM_PROMPT = """You are an autonomous SOC incident-responder.
Given a security investigation report, decide the best response action.

Available actions  (choose exactly one):
    NO_ACTION        - benign, nothing to do
    MONITOR          - low risk; keep watching, log only
    BLOCK_IP         - block a source IP at the firewall
    LOCK_USER        - disable a compromised user account
    QUARANTINE_FILE  - isolate a malicious or suspicious file
    DELETE_FILE      - permanently remove a confirmed-malicious file
    ESCALATE_HUMAN   - threat is too complex for automation; human must step in

You MUST respond with ONLY valid JSON:
{
    "action":             "<one of the actions above>",
    "target":             "<IP address | username | file path | null>",
    "simulated_command":  "<exact shell command that would be run, or null>",
    "can_auto_resolve":   true | false,
    "escalation_reason":  "<clear explanation of why this incident occurred and what action is required>",
    "incident_title":     "<short descriptive title>",
    "incident_report_md": "<complete Markdown incident report>"
}
"""

ALLOWED_COMMANDS: set[str] = {
    "iptables", "ufw", "firewall-cmd", "nft", "ipconfig", "ifconfig", "netstat", "ss", "ping", "nslookup", "dig",
    "usermod", "passwd", "chage", "last", "lastlog", "whoami", "id", "who", "w", "quser",
    "pkill", "kill", "ps", "pgrep", "top", "tasklist", "taskkill", "lsof",
    "systemctl", "service", "journalctl", "sc", "net", "wevtutil",
    "ls", "dir", "find", "stat", "df", "du", "free", "uptime", "hostname", "date",
    "cat", "head", "tail", "grep", "awk", "sed", "type", "findstr",
    "chmod", "chown", "icacls", "cp", "mv", "mkdir", "cd",
    "echo", "logger", "sleep", "true", "false"
}


class ResponderAgent:
    """Agent 3 - The Responder"""

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

    def create_file(self, file_path: str, content: str = "") -> dict:
        try:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            return {"success": True, "action": "created", "file": file_path}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def write_file(self, file_path: str, content: str, mode: str = "a") -> dict:
        try:
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, mode, encoding="utf-8") as fh:
                fh.write(content)
            return {"success": True, "action": "written", "file": file_path}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def quarantine_file(self, file_path: str) -> dict:
        if not file_path or not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        filename = os.path.basename(file_path)
        dest = os.path.join(
            self.quarantine_dir,
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}",
        )

        if self.simulate_only:
            return {"success": True, "simulated": True, "source": file_path, "destination": dest}

        try:
            shutil.move(file_path, dest)
            return {"success": True, "simulated": False, "source": file_path, "destination": dest}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def run_command(self, command: str) -> dict:
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            return {"success": False, "error": f"Command parse error: {exc}"}

        if not parts:
            return {"success": False, "error": "Empty command."}

        base_cmd = parts[0]
        if base_cmd not in ALLOWED_COMMANDS:
            return {
                "success": False,
                "blocked": True,
                "command": command,
                "reason":  f"'{base_cmd}' is not in the allowed command list.",
            }

        if self.simulate_only:
            return {
                "success":   True,
                "simulated": True,
                "command":   command,
                "stdout":    f"[SIMULATION] Would have run: {command}",
                "returncode": 0,
            }

        try:
            result = subprocess.run(parts, capture_output=True, text=True, timeout=10)
            return {
                "success":    result.returncode == 0,
                "simulated":  False,
                "command":    command,
                "stdout":     result.stdout,
                "stderr":     result.stderr,
                "returncode": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timed out."}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def block_ip(self, ip: str) -> dict:
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return {"success": False, "error": f"Invalid IP: {ip}"}
        return self.run_command(f"iptables -A INPUT -s {ip} -j DROP")

    def lock_user(self, username: str) -> dict:
        if not re.match(r'^\w[\w.-]{0,31}$', username):
            return {"success": False, "error": f"Invalid username: {username}"}
        return self.run_command(f"usermod -L {username}")

    def notify_human(self, incident_id: str, reason: str, report_path: str):
        border = "=" * 64
        banner = (
            f"\n{border}\n"
            f"!!  HUMAN INTERVENTION REQUIRED  !!\n"
            f"{border}\n"
            f"Incident ID : {incident_id}\n"
            f"Time        : {datetime.now().isoformat()}\n"
            f"Reason      : {reason}\n"
            f"Report File : {report_path}\n"
            f"{border}\n"
        )
        notif_log = os.path.join(self.reports_dir, "HUMAN_NOTIFICATIONS.log")
        self.write_file(notif_log, banner + "\n", mode="a")

    def classify_and_respond(self, investigation_report: dict) -> dict:
        incident_id = (
            f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            f"-{str(uuid.uuid4())[:4].upper()}"
        )

        alert       = investigation_report.get("original_alert", {})
        ai_analysis = investigation_report.get("ai_analysis", {})
        evidence    = investigation_report.get("evidence", {})
        severity    = alert.get("severity", "LOW")
        event_type  = alert.get("event_type", "UNKNOWN")

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

        # Clear, informative domain-specific heuristic fallback
        if "error" in decision:
            primary_ips = evidence.get("extracted_ips", [])
            primary_users = evidence.get("extracted_users", [])
            primary_ip = primary_ips[0] if primary_ips else None
            primary_user = primary_users[0] if primary_users else None
            sentry_reason = alert.get("reason", "Anomalous telemetry indicator detected.")

            if "MALWARE" in event_type or "SUSPICIOUS_PROCESS" in event_type:
                action = "BLOCK_IP" if primary_ip else "ESCALATE_HUMAN"
                target = primary_ip
                cmd = f"iptables -A INPUT -s {primary_ip} -j DROP" if primary_ip else None
                escalation_reason = (
                    f"Intrusion detected: Rogue reverse shell process spawned. "
                    f"Source IP: {primary_ip or 'unknown'}. Offending file: {Path(alert.get('file_path', '')).name}."
                )
            elif "PRIVILEGE" in event_type or "ROOT" in event_type:
                action = "LOCK_USER" if primary_user else "ESCALATE_HUMAN"
                target = primary_user
                cmd = f"usermod -L {primary_user}" if primary_user else None
                escalation_reason = (
                    f"Privilege escalation breach attempt: Unauthorized root/sudo access by user '{primary_user or 'unknown'}'. "
                    f"{sentry_reason}"
                )
            elif "SQL" in event_type:
                action = "BLOCK_IP" if primary_ip else "ESCALATE_HUMAN"
                target = primary_ip
                cmd = f"iptables -A INPUT -s {primary_ip} -j DROP" if primary_ip else None
                escalation_reason = (
                    f"SQL injection exploit attempt targeting web application database from IP {primary_ip or 'unknown'}."
                )
            elif "BRUTE" in event_type or "AUTH" in event_type:
                action = "BLOCK_IP" if primary_ip else "ESCALATE_HUMAN"
                target = primary_ip
                cmd = f"iptables -A INPUT -s {primary_ip} -j DROP" if primary_ip else None
                escalation_reason = (
                    f"Credential brute-force attack: Repeated authentication failures from IP {primary_ip or 'unknown'}."
                )
            else:
                action = "BLOCK_IP" if primary_ip else "MONITOR"
                target = primary_ip
                cmd = f"iptables -A INPUT -s {primary_ip} -j DROP" if primary_ip else None
                escalation_reason = f"Security anomaly detected: {event_type} - {sentry_reason}"

            decision = {
                "action":             action,
                "target":             target,
                "simulated_command":  cmd,
                "can_auto_resolve":   bool(action != "ESCALATE_HUMAN"),
                "escalation_reason":  escalation_reason,
                "incident_title":     f"{severity} {event_type} - {target or 'System'}",
                "incident_report_md": self._fallback_report(
                    incident_id, alert, ai_analysis, evidence
                ),
            }

        action  = decision.get("action", "MONITOR")
        target  = decision.get("target") or ""
        escalation_reason = decision.get("escalation_reason") or f"{event_type} detected: {alert.get('reason', '')}"
        action_log: list[dict] = []

        # Execute action
        if action == "BLOCK_IP" and target:
            result = self.block_ip(target)
            action_log.append({"action": "BLOCK_IP", "target": target, "result": result})
        elif action == "LOCK_USER" and target:
            result = self.lock_user(target)
            action_log.append({"action": "LOCK_USER", "target": target, "result": result})
        elif action == "QUARANTINE_FILE" and target:
            result = self.quarantine_file(target)
            action_log.append({"action": "QUARANTINE_FILE", "target": target, "result": result})
        elif action in ("MONITOR", "NO_ACTION"):
            action_log.append({"action": action, "target": target or "N/A", "result": {"logged": True}})
        elif action == "ESCALATE_HUMAN":
            action_log.append({"action": "ESCALATE_HUMAN", "result": {"pending_notification": True}})

        cmd = decision.get("simulated_command")
        if cmd and action not in ("ESCALATE_HUMAN", "NO_ACTION"):
            cmd_result = self.run_command(cmd)
            action_log.append({"action": "RUN_COMMAND", "command": cmd, "result": cmd_result})

        report_md = decision.get("incident_report_md") or self._fallback_report(
            incident_id, alert, ai_analysis, evidence
        )

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

        # Notify human if needed
        if action == "ESCALATE_HUMAN" or not decision.get("can_auto_resolve", True):
            self.notify_human(incident_id, escalation_reason, report_path)

        summary = {
            "incident_id":        incident_id,
            "timestamp":          datetime.now().isoformat(),
            "severity":           severity,
            "event_type":         event_type,
            "action_taken":       action,
            "target":             target,
            "escalation_reason":  escalation_reason,
            "action_log":         action_log,
            "report_path":        report_path,
            "escalated_to_human": action == "ESCALATE_HUMAN",
            "investigation_id":   investigation_report.get("investigation_id"),
            "ai_analysis":        ai_analysis,
        }

        return summary

    def _fallback_report(
        self,
        incident_id: str,
        alert: dict,
        ai_analysis: dict,
        evidence: dict,
    ) -> str:
        return (
            f"# Incident Report: {incident_id}\n\n"
            f"**Timestamp:** {datetime.now().isoformat()}  \n"
            f"**Severity:** {alert.get('severity', 'UNKNOWN')}  \n"
            f"**Type:** {alert.get('event_type', 'UNKNOWN')}  \n\n"
            f"## Summary\n"
            f"A **{alert.get('severity', '')}** severity **{alert.get('event_type', 'security')}** event was detected in "
            f"`{alert.get('file_path', 'unknown file')}`.\n\n"
            f"## Evidence\n"
            f"- **Source IPs Identified:** {evidence.get('extracted_ips', [])}\n"
            f"- **Target Users:** {evidence.get('extracted_users', [])}\n"
            f"- **Correlated Log Hits:** {len(evidence.get('related_events', []))}\n\n"
            f"## Root Cause Analysis\n"
            f"| Dimension | Details |\n|---|---|\n"
            f"| **Why (Root Cause)** | {ai_analysis.get('why', 'N/A')} |\n"
            f"| **Where (Origin)** | {ai_analysis.get('where', 'N/A')} |\n"
            f"| **How (Attack Vector)** | {ai_analysis.get('how', 'N/A')} |\n"
            f"| **Impact Analysis** | {ai_analysis.get('impact', 'N/A')} |\n\n"
            f"## Recommendations\n"
            f"{ai_analysis.get('recommended_action', 'Review incident report in dashboard.')}\n\n"
            f"---\n*Generated by Autonomous SOC Engine*\n"
        )

    def run(self):
        self._running = True
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
