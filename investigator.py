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

    Usage
    -----
    inv = InvestigatorAgent(
        logs_path    = "./logs",
        alert_queue  = alert_q,
        report_queue = report_q,
        ollama_client= client,
    )
    inv.run()          # blocking loop - run in a Thread
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
    #  TOOL FUNCTIONS - each does exactly ONE thing
    # ==========================================================================

    def search_logs(self, keyword: str, max_results: int = 80) -> list[dict]:
        """
        Search every .log and .txt file under logs_path for keyword.
        Returns a list of {file, line_number, content} dicts.
        """
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
                                logger.info(f"[INVESTIGATOR] search_logs('{keyword}') -> {len(matches)} hits (capped)")
                                return matches
            except Exception as exc:
                logger.warning(f"[INVESTIGATOR] Could not search '{log_file}': {exc}")

        logger.info(f"[INVESTIGATOR] search_logs('{keyword}') -> {len(matches)} hits")
        return matches

    # --------------------------------------------------------------------------
    def open_file(self, file_path: str) -> str:
        """
        Safely read the full contents of a file.
        Access is restricted to files inside logs_path to prevent
        the agent accidentally reading sensitive system files.
        """
        abs_target = os.path.abspath(file_path)

        if not abs_target.startswith(self.logs_path):
            logger.warning(f"[INVESTIGATOR] open_file BLOCKED (outside logs_path): {file_path}")
            return f"[ACCESS DENIED - '{file_path}' is outside the monitored directory]"

        try:
            with open(abs_target, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            logger.info(f"[INVESTIGATOR] open_file('{file_path}') -> {len(content):,} chars")
            return content
        except FileNotFoundError:
            return f"[FILE NOT FOUND: {file_path}]"
        except PermissionError:
            return f"[PERMISSION DENIED: {file_path}]"
        except Exception as exc:
            return f"[ERROR: {exc}]"

    # --------------------------------------------------------------------------
    def read_lines(self, file_path: str, start: int = 1, end: int = 50) -> list[str]:
        """
        Read lines [start..end] (1-indexed, inclusive) from a file.
        Also safety-restricted to logs_path.
        """
        abs_target = os.path.abspath(file_path)

        if not abs_target.startswith(self.logs_path):
            logger.warning(f"[INVESTIGATOR] read_lines BLOCKED: {file_path}")
            return ["[ACCESS DENIED]"]

        try:
            with open(abs_target, "r", encoding="utf-8", errors="replace") as fh:
                all_lines = fh.readlines()
            selected = all_lines[start - 1 : end]
            logger.info(f"[INVESTIGATOR] read_lines('{file_path}', {start}-{end}) -> {len(selected)} lines")
            return [ln.rstrip() for ln in selected]
        except Exception as exc:
            return [f"[ERROR: {exc}]"]

    # --------------------------------------------------------------------------
    def get_file_metadata(self, file_path: str) -> dict:
        """Return os.stat metadata for a file as a readable dict."""
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

    # --------------------------------------------------------------------------
    def extract_ip_addresses(self, text: str) -> list[str]:
        """Pull every unique IPv4 address from a text string."""
        ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        logger.info(f"[INVESTIGATOR] extract_ip_addresses() -> {ips}")
        return ips

    # --------------------------------------------------------------------------
    def extract_usernames(self, text: str) -> list[str]:
        """
        Heuristically pull usernames from typical auth/syslog lines.
        Covers sshd, sudo, and PAM log formats.
        """
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

        # Remove common false positives
        usernames.discard("root")          # handle root separately
        result = list(usernames)
        logger.info(f"[INVESTIGATOR] extract_usernames() -> {result}")
        return result

    # --------------------------------------------------------------------------
    def count_occurrences(self, keyword: str, within_minutes: int = 10) -> int:
        """
        Count how many times keyword appears across recently modified log files
        (files touched within the last `within_minutes` minutes).
        """
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

        logger.info(f"[INVESTIGATOR] count_occurrences('{keyword}', {within_minutes}min) -> {count}")
        return count

    # --------------------------------------------------------------------------
    def check_ip_blocklist(self, ip: str) -> dict:
        """
        Check a single IP against the local JSON blocklist file.
        Format expected: {"blocked_ips": {"1.2.3.4": "reason", ...}}
        """
        try:
            with open(self.blocklist_path, "r") as fh:
                data = json.load(fh)

            blocked = data.get("blocked_ips", {})

            # Support both dict {"ip": "reason"} and list ["ip", ...]
            if isinstance(blocked, dict):
                if ip in blocked:
                    return {"ip": ip, "is_blocked": True, "reason": blocked[ip]}
            elif isinstance(blocked, list):
                if ip in blocked:
                    return {"ip": ip, "is_blocked": True, "reason": "Listed in local blocklist"}

            return {"ip": ip, "is_blocked": False}

        except FileNotFoundError:
            return {"ip": ip, "is_blocked": False, "note": "No blocklist file at " + self.blocklist_path}
        except Exception as exc:
            return {"ip": ip, "error": str(exc)}

    # ==========================================================================
    #  ORCHESTRATOR - calls all tools, then calls the LLM
    # ==========================================================================

    def investigate(self, alert: dict) -> dict:
        """
        Full investigation pipeline for one Sentry alert.

        Steps
        -----
        1. Extract IPs and usernames from the raw log.
        2. Search for related events across all log files.
        3. Get file metadata of the triggering log.
        4. Count how often flagged IPs appeared in the last 10 minutes.
        5. Check IPs against the local blocklist.
        6. Read the first 80 lines of the triggering file for extra context.
        7. Ask the LLM: WHY / WHERE / HOW / IMPACT.

        Returns a full investigation_report dict.
        """
        logger.info(
            f"\n[INVESTIGATOR] [INFO] Investigating alert: "
            f"{alert.get('alert_id')} | {alert.get('event_type')} | {alert.get('severity')}"
        )

        raw_log   = alert.get("raw_log", "")
        evidence: dict = {}

        # -- Step 1: Entity extraction --------------------------------------
        ips   = self.extract_ip_addresses(raw_log)
        users = self.extract_usernames(raw_log)
        evidence["extracted_ips"]   = ips
        evidence["extracted_users"] = users

        # -- Step 2: Related event search -----------------------------------
        search_terms = ips + users
        # Also add the general event_type keyword
        event_type_kw = alert.get("event_type", "").replace("_", " ")
        if event_type_kw:
            search_terms.append(event_type_kw)

        related: list[dict] = []
        for term in search_terms[:4]:   # cap to 4 terms to stay fast
            if term:
                related.extend(self.search_logs(term, max_results=25))

        # Deduplicate by (file, line_number)
        seen: set[tuple] = set()
        unique_related: list[dict] = []
        for r in related:
            key = (r["file"], r["line_number"])
            if key not in seen:
                seen.add(key)
                unique_related.append(r)

        evidence["related_events"] = unique_related[:40]   # cap final list

        # -- Step 3: File metadata ------------------------------------------
        evidence["file_metadata"] = self.get_file_metadata(alert.get("file_path", ""))

        # -- Step 4: Occurrence frequency ----------------------------------
        freq: dict[str, int] = {}
        for ip in ips[:3]:
            freq[ip] = self.count_occurrences(ip, within_minutes=10)
        evidence["ip_frequency_10min"] = freq

        # -- Step 5: Blocklist check ----------------------------------------
        evidence["ip_blocklist"] = [self.check_ip_blocklist(ip) for ip in ips[:5]]

        # -- Step 6: Context lines from triggering file ---------------------
        file_path = alert.get("file_path", "")
        if file_path and os.path.exists(file_path):
            evidence["file_head_80"] = self.read_lines(file_path, start=1, end=80)

        # -- Step 7: LLM analysis -------------------------------------------
        # Build a compact evidence summary to stay within token limits
        evidence_summary = {
            "extracted_ips":      ips,
            "extracted_users":    users,
            "related_events":     evidence["related_events"][:5],    # sample for LLM
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

        if "error" in ai_result:
            logger.warning("[INVESTIGATOR] AI analysis failed; using rule-based fallback.")
            ai_result = {
                "why":                "AI analysis unavailable - see evidence for raw indicators.",
                "where":              ", ".join(ips) if ips else "Unknown",
                "how":                alert.get("event_type", "Unknown technique"),
                "impact":             "Unknown - manual review recommended.",
                "confidence":         "LOW",
                "recommended_action": "Escalate to human analyst.",
                "threat_actor":       "unknown",
                "mitre_tactic":       "Unknown",
            }

        # -- Build final report ---------------------------------------------
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

        logger.info(f"[INVESTIGATOR] [OK] Done - {inv_id}")
        logger.info(f"[INVESTIGATOR] WHY    : {ai_result.get('why')}")
        logger.info(f"[INVESTIGATOR] WHERE  : {ai_result.get('where')}")
        logger.info(f"[INVESTIGATOR] HOW    : {ai_result.get('how')}")
        logger.info(f"[INVESTIGATOR] IMPACT : {ai_result.get('impact')}")

        return report

    # ==========================================================================
    #  MAIN LOOP
    # ==========================================================================

    def run(self):
        """
        Blocking loop.
        Reads alert dicts from alert_queue, calls investigate(),
        and puts the result on report_queue for the Responder.
        Run this inside a threading.Thread.
        """
        self._running = True
        logger.info("[INVESTIGATOR] [INFO] Ready - waiting for Sentry alerts...")

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
        logger.info("[INVESTIGATOR] Stopped.")
