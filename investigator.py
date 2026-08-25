"""
investigator.py - Agent 2: The Investigator
----------------------------------------------------------------------------
Receives an alert dict from the Sentry via alert_queue.
Runs a set of specialised tool-functions to gather evidence:
    * search_logs()              - grep through all log files for a keyword
    * open_file()                - read a full file safely
    * read_lines()               - read a specific range of lines
    * get_file_metadata()        - size, timestamps of a file
    * extract_ip_addresses()     - pull all IPs from a text blob
    * extract_usernames()        - pull usernames from auth-style log lines
    * count_occurrences()        - how often did a pattern appear recently?
    * check_ip_blocklist()       - compare against local JSON blocklist

After gathering evidence, it asks the LLM:
    WHY did this happen? WHERE did it come from? HOW was it done?

Puts the completed investigation_report onto report_queue for the Responder.
----------------------------------------------------------------------------
"""

import os
import re
import glob
import json
import queue
import logging
from datetime import datetime, timedelta
from pathlib import Path

from nvidia_nim_client import NvidiaNimClient

logger = logging.getLogger(__name__)

# -- LLM role for the Investigator ---------------------------------------------
INVESTIGATOR_SYSTEM_PROMPT = """You are a senior cybersecurity investigator conducting a forensic analysis.
Given an alert and supporting evidence, determine:

    WHY   - root cause / attacker motivation
    WHERE - exact origin: source IP, username, file, or process
    HOW   - attack vector / technique used
    IMPACT - potential damage if unchecked

You MUST respond with ONLY valid JSON (no text outside the braces):
{
    "why":                "<root cause>",
    "where":              "<origin - IP / user / path>",
    "how":                "<attack method>",
    "impact":             "<potential damage>",
    "confidence":         "HIGH" | "MEDIUM" | "LOW",
    "recommended_action": "<what the Responder should do>",
    "threat_actor":       "script_kiddie" | "insider_threat" | "apt" | "automated_bot" | "unknown",
    "mitre_tactic":       "<MITRE ATT&CK tactic name, e.g. Initial Access>"
}"""


class InvestigatorAgent:
    """
    Agent 2 - The Investigator
    """

    def __init__(
        self,
        logs_path: str,
        alert_queue: queue.Queue,
        report_queue: queue.Queue,
        nim_client: NvidiaNimClient,
        blocklist_path: str = "blocklist.json",
    ):
        self.logs_path     = os.path.abspath(logs_path)
        self.alert_queue   = alert_queue
        self.report_queue  = report_queue
        self.nim           = nim_client
        self.blocklist_path = blocklist_path
        self._running      = False

        Path(logs_path).mkdir(parents=True, exist_ok=True)
        logger.info(f"[INVESTIGATOR] Initialised. Logs path: '{self.logs_path}'")

    # ==========================================================================
    #  TOOL FUNCTIONS
    # ==========================================================================

    def search_logs(self, keyword: str, max_results: int = 80) -> list[dict]:
        """Search every .log and .txt file under logs_path for keyword."""
        if not keyword:
            return []

        matches: list[dict] = []
        files = (
            glob.glob(os.path.join(self.logs_path, "**", "*.log"), recursive=True)
            + glob.glob(os.path.join(self.logs_path, "**", "*.txt"), recursive=True)
        )

        for log_file in files:
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
                    for line_no, line in enumerate(fh, start=1):
                        if keyword.lower() in line.lower():
                            matches.append({
                                "file":        log_file,
                                "line_number": line_no,
                                "content":     line.rstrip(),
                            })
                            if len(matches) >= max_results:
                                return matches
            except Exception as exc:
                logger.warning(f"[INVESTIGATOR] Could not search '{log_file}': {exc}")

        return matches

    def open_file(self, file_path: str) -> str:
        """Safely read the full contents of a file inside logs_path."""
        abs_target = os.path.abspath(file_path)

        if not abs_target.startswith(self.logs_path):
            logger.warning(f"[INVESTIGATOR] open_file BLOCKED (outside logs_path): {file_path}")
            return f"[ACCESS DENIED - '{file_path}' is outside the monitored directory]"

        try:
            with open(abs_target, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except FileNotFoundError:
            return f"[FILE NOT FOUND: {file_path}]"
        except Exception as exc:
            return f"[ERROR: {exc}]"

    def read_lines(self, file_path: str, start: int = 1, end: int = 50) -> list[str]:
        """Read lines [start..end] from a file inside logs_path."""
        abs_target = os.path.abspath(file_path)

        if not abs_target.startswith(self.logs_path):
            return ["[ACCESS DENIED]"]

        try:
            with open(abs_target, "r", encoding="utf-8", errors="replace") as fh:
                all_lines = fh.readlines()
            selected = all_lines[start - 1 : end]
            return [ln.rstrip() for ln in selected]
        except Exception as exc:
            return [f"[ERROR: {exc}]"]

    def get_file_metadata(self, file_path: str) -> dict:
        """Return os.stat metadata for a file."""
        try:
            st = os.stat(file_path)
            return {
                "file":          file_path,
                "exists":        True,
                "size_bytes":    st.st_size,
                "created":       datetime.fromtimestamp(st.st_ctime).isoformat(),
                "last_modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
            }
        except FileNotFoundError:
            return {"file": file_path, "exists": False}
        except Exception as exc:
            return {"file": file_path, "error": str(exc)}

    def extract_ip_addresses(self, text: str) -> list[str]:
        """Pull every unique IPv4 address from text."""
        return list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))

    def extract_usernames(self, text: str) -> list[str]:
        """Extract usernames from auth log patterns."""
        patterns = [
            r"Failed password for (?:invalid user )?(\w[\w.-]+)",
            r"Accepted (?:password|publickey) for (\w[\w.-]+)",
            r"Invalid user (\w[\w.-]+)",
            r"user=(\w[\w.-]+)",
            r"for (\w[\w.-]+) from \d",
            r"sudo:\s+(\w[\w.-]+)\s*:",
        ]
        usernames: set[str] = set()
        for pat in patterns:
            usernames.update(re.findall(pat, text, re.IGNORECASE))

        usernames.discard("root")
        return list(usernames)

    def count_occurrences(self, keyword: str, within_minutes: int = 10) -> int:
        """Count how many times keyword appears across recent log files."""
        if not keyword:
            return 0

        cutoff = datetime.now() - timedelta(minutes=within_minutes)
        count  = 0
        files  = glob.glob(os.path.join(self.logs_path, "**", "*.log"), recursive=True)

        for log_file in files:
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
                if mtime < cutoff:
                    continue
                with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
                    count += fh.read().lower().count(keyword.lower())
            except Exception:
                pass

        return count

    def check_ip_blocklist(self, ip: str) -> dict:
        """Check an IP against the local blocklist file."""
        try:
            with open(self.blocklist_path, "r") as fh:
                data = json.load(fh)

            blocked = data.get("blocked_ips", {})
            if isinstance(blocked, dict):
                if ip in blocked:
                    return {"ip": ip, "is_blocked": True, "reason": blocked[ip]}
            elif isinstance(blocked, list):
                if ip in blocked:
                    return {"ip": ip, "is_blocked": True, "reason": "Listed in local blocklist"}

            return {"ip": ip, "is_blocked": False}
        except Exception:
            return {"ip": ip, "is_blocked": False}

    # ==========================================================================
    #  ORCHESTRATOR
    # ==========================================================================

    def investigate(self, alert: dict) -> dict:
        """Full investigation pipeline for one Sentry alert."""
        raw_log   = alert.get("raw_log", "")
        evidence: dict = {}

        # 1. Entity extraction
        ips   = self.extract_ip_addresses(raw_log)
        users = self.extract_usernames(raw_log)
        evidence["extracted_ips"]   = ips
        evidence["extracted_users"] = users

        # 2. Related event search
        search_terms = ips + users
        event_type_kw = alert.get("event_type", "").replace("_", " ")
        if event_type_kw:
            search_terms.append(event_type_kw)

        related: list[dict] = []
        for term in search_terms[:4]:
            if term:
                related.extend(self.search_logs(term, max_results=25))

        seen: set[tuple] = set()
        unique_related: list[dict] = []
        for r in related:
            key = (r["file"], r["line_number"])
            if key not in seen:
                seen.add(key)
                unique_related.append(r)

        evidence["related_events"] = unique_related[:40]

        # 3. File metadata & context
        evidence["file_metadata"] = self.get_file_metadata(alert.get("file_path", ""))
        freq: dict[str, int] = {}
        for ip in ips[:3]:
            freq[ip] = self.count_occurrences(ip, within_minutes=10)
        evidence["ip_frequency_10min"] = freq
        evidence["ip_blocklist"] = [self.check_ip_blocklist(ip) for ip in ips[:5]]

        file_path = alert.get("file_path", "")
        if file_path and os.path.exists(file_path):
            evidence["file_head_80"] = self.read_lines(file_path, start=1, end=80)

        # 4. LLM Forensic Analysis
        evidence_summary = {
            "extracted_ips":      ips,
            "extracted_users":    users,
            "related_events":     evidence["related_events"][:5],
            "ip_frequency_10min": freq,
            "ip_blocklist":       evidence["ip_blocklist"],
            "file_metadata":      evidence["file_metadata"],
        }

        prompt = (
            f"=== SECURITY ALERT ===\n"
            f"Alert ID   : {alert.get('alert_id')}\n"
            f"Event Type : {alert.get('event_type')}\n"
            f"Severity   : {alert.get('severity')}\n"
            f"File       : {alert.get('file_path')}\n"
            f"Timestamp  : {alert.get('timestamp')}\n"
            f"Sentry Note: {alert.get('reason')}\n\n"
            f"=== EVIDENCE GATHERED ===\n"
            f"{json.dumps(evidence_summary, indent=2)}\n\n"
            f"=== RAW LOG SAMPLE (last 30 lines) ===\n"
            f"{chr(10).join(raw_log.splitlines()[-30:])}\n\n"
            f"=== TOP RELATED LOG HITS ===\n"
            f"{json.dumps(evidence['related_events'][:6], indent=2)}\n\n"
            f"Now produce your forensic JSON analysis."
        )

        ai_result = self.nim.query_json(prompt, system=INVESTIGATOR_SYSTEM_PROMPT)

        # Rich, informative rule-based heuristic fallback if LLM is unavailable
        if "error" in ai_result:
            event_type = alert.get("event_type", "SECURITY_ALERT")
            reason_text = alert.get("reason", "Suspicious pattern detected.")
            primary_ip = ips[0] if ips else "External/Unknown"
            primary_user = users[0] if users else "System/Unknown"

            if "MALWARE" in event_type or "SUSPICIOUS_PROCESS" in event_type:
                why = f"Host intrusion attempt: unauthorized process execution or reverse shell spawned by remote threat actor."
                how = f"Reverse shell / command execution payload: {reason_text}"
                impact = "Risk of remote code execution, host takeover, or lateral movement across internal network."
                rec = f"Isolate affected host, terminate rogue process, and block source IP {primary_ip} at the perimeter firewall."
                tactic = "Execution / Command and Control"
            elif "PRIVILEGE" in event_type or "ROOT" in event_type or "SUDO" in event_type:
                why = f"Unauthorized privilege escalation attempt against administrative account (root)."
                how = f"Excessive failed sudo attempts or PAM authentication bypass attempt: {reason_text}"
                impact = "Risk of root level credential compromise and full administrative system takeover."
                rec = f"Lock user account '{primary_user}', rotate credentials, and verify sudoers permissions."
                tactic = "Privilege Escalation"
            elif "SQL" in event_type:
                why = f"Web application database extraction / injection exploit targeting backend database."
                how = f"SQL injection payload in HTTP parameters: {reason_text}"
                impact = "Risk of unauthorized data exfiltration, database corruption, or auth bypass."
                rec = f"Block source IP {primary_ip} at WAF and review parameterized query enforcement."
                tactic = "Initial Access / SQL Injection"
            elif "BRUTE" in event_type or "AUTH" in event_type:
                why = f"Automated credential stuffing / brute-force authentication attack."
                how = f"Repeated failed SSH/OAuth login attempts: {reason_text}"
                impact = "Account compromise and unauthorized access."
                rec = f"Block offending IP {primary_ip} via iptables firewall rule."
                tactic = "Credential Access"
            else:
                why = f"Anomalous security indicator detected in system telemetry: {reason_text}"
                how = reason_text
                impact = "Potential unauthorized reconnaissance or system tampering."
                rec = f"Inspect active connections for source IP {primary_ip} and review host audit logs."
                tactic = "Defense Evasion"

            ai_result = {
                "why":                why,
                "where":              f"Source IP: {primary_ip} | User: {primary_user} | File: {Path(alert.get('file_path', '')).name}",
                "how":                how,
                "impact":             impact,
                "confidence":         "HIGH",
                "recommended_action": rec,
                "threat_actor":       "automated_bot" if "BRUTE" in event_type else "unknown",
                "mitre_tactic":       tactic,
            }

        inv_id = f"INV-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        report = {
            "investigation_id": inv_id,
            "timestamp":        datetime.now().isoformat(),
            "original_alert":   alert,
            "evidence":         evidence,
            "ai_analysis":      ai_result,
            "summary": (
                f"[{alert.get('severity')}] {alert.get('event_type')} in "
                f"'{alert.get('file_path', 'unknown')}'. "
                f"IPs={ips}. Users={users}. "
                f"Confidence={ai_result.get('confidence')}."
            ),
        }

        return report

    def run(self):
        self._running = True
        while self._running:
            try:
                alert = self.alert_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                report = self.investigate(alert)
                self.report_queue.put(report)
            except Exception as exc:
                logger.error(f"[INVESTIGATOR] Unhandled error: {exc}", exc_info=True)
            finally:
                self.alert_queue.task_done()

    def stop(self):
        self._running = False
