# SOC-in-a-Box 🛡️

### Multi-Agent Autonomous Security Operations Centre — Prototype v1.0

> **Academic context:** 3rd Year Engineering Major Project, 2025–2026  
> **Keywords:** Multi-agent systems, autonomous cyber defence, LLM-assisted threat detection, SIEM automation, incident response

---

## Abstract

SOC-in-a-Box is a prototype Security Operations Centre (SOC) implemented as a pipeline of three autonomous AI agents. Each agent mirrors a distinct human role in a real SOC team — the Analyst, the Investigator, and the Incident Responder — and all three collaborate through shared in-memory queues without external orchestration. The system ingests raw system log files, classifies threats using a large language model (LLM) hosted on the NVIDIA NIM inference platform, enriches alerts with forensic evidence, and produces structured Markdown incident reports alongside simulated remediation actions. A rule-based fallback engine ensures continuity when the LLM is unreachable. The prototype demonstrates that a lightweight, locally deployable multi-agent architecture can automate the detect–investigate–respond loop that typically requires a full SOC team, reducing mean-time-to-respond (MTTR) for common attack patterns.

---

## Table of Contents

1. [Motivation and Problem Statement](#1-motivation-and-problem-statement)
2. [System Architecture](#2-system-architecture)
3. [Agent Design](#3-agent-design)
   - [Agent 1 — The Sentry](#31-agent-1--the-sentry-sentrypy)
   - [Agent 2 — The Investigator](#32-agent-2--the-investigator-investigatorpy)
   - [Agent 3 — The Responder](#33-agent-3--the-responder-responderpy)
4. [LLM Integration — NVIDIA NIM](#4-llm-integration--nvidia-nim)
5. [Safety and Containment Model](#5-safety-and-containment-model)
6. [Synthetic Log Simulator](#6-synthetic-log-simulator)
7. [Output — Incident Reports](#7-output--incident-reports)
8. [Tech Stack](#8-tech-stack)
9. [Installation and Usage](#9-installation-and-usage)
10. [Project Structure](#10-project-structure)
11. [Evaluation and Limitations](#11-evaluation-and-limitations)
12. [Future Work](#12-future-work)
13. [References and Related Work](#13-references-and-related-work)

---

## 1. Motivation and Problem Statement

Modern Security Operations Centres face a chronic shortage of skilled analysts. According to industry surveys, a typical SOC analyst reviews hundreds of alerts per shift, leading to alert fatigue, missed detections, and slow incident response. The median cost of a data breach in 2024 exceeded $4.8 million (IBM Cost of a Data Breach Report), with the majority of that cost attributable to the time between initial compromise and containment.

Existing SIEM (Security Information and Event Management) tools such as Splunk, Microsoft Sentinel, and IBM QRadar provide powerful correlation engines but still require significant human effort for triage and remediation. Large language models have recently demonstrated strong performance on security-related tasks — vulnerability analysis, log interpretation, and code review — but have not yet been embedded into fully autonomous, pipeline-oriented agent architectures for real-time SOC operations.

**SOC-in-a-Box** addresses this gap by:
- Replacing human tier-1 and tier-2 analyst work with three specialised agents that operate continuously.
- Using LLM reasoning to produce human-readable forensic narratives (WHY / WHERE / HOW / IMPACT) rather than just pattern-matched alerts.
- Providing a safe, simulate-only default mode that makes the system suitable for research, teaching, and demonstration without risk of accidental system modification.

---

## 2. System Architecture

### High-Level Pipeline

```
┌────────────────────────────────────────────────────────────────────┐
│                         SOC-in-a-Box                               │
│                                                                    │
│  ┌──────────┐   alert_queue   ┌───────────────┐  report_queue     │
│  │  SENTRY  │ ─────────────▶ │ INVESTIGATOR  │ ─────────────▶    │
│  │ (thread) │                │   (thread)    │                    │
│  └────┬─────┘                └───────────────┘                    │
│       │                                         ┌──────────────┐  │
│  watchdog                                       │  RESPONDER   │  │
│  observer                                       │   (thread)   │  │
│       │                                         └──────┬───────┘  │
│  ./logs/*.log                                          │           │
│                                                  ./reports/        │
│                                               INC-*.md             │
└────────────────────────────────────────────────────────────────────┘
```

### Inter-Agent Communication

The three agents run as concurrent Python threads and share two `queue.Queue` instances:

| Queue | Producer | Consumer | Payload |
|-------|----------|----------|---------|
| `alert_queue` | Sentry | Investigator | Alert dict with raw log, severity, event type, indicators |
| `report_queue` | Investigator | Responder | Investigation report with evidence bundle and AI forensic analysis |

No external message broker (Kafka, Redis, RabbitMQ) is required. The in-process queue approach keeps the system self-contained and deployable on any machine with Python ≥ 3.10.

### Threading Model

```
Main thread
  ├── SentryAgent.start()        → Watchdog Observer thread (daemon)
  ├── InvestigatorAgent.run()    → threading.Thread (daemon)
  └── ResponderAgent.run()       → threading.Thread (daemon)
```

Graceful shutdown is handled via `signal.SIGINT` / `signal.SIGTERM` hooks that set a shared `threading.Event`, after which each agent's `stop()` method is called and threads are joined with a 5-second timeout.

---

## 3. Agent Design

### 3.1 Agent 1 — The Sentry (`sentry.py`)

**Role:** Continuous file-system monitor and first-pass threat detector.

**Mechanism:**  
The Sentry wraps Python's `watchdog` library to receive OS-level inotify/FSEvents/ReadDirectoryChangesW callbacks for any file create, modify, or delete event under the watched directory (default: `./logs/`). On each event:

1. **Debounce:** A per-file in-flight set prevents re-entrant processing of the same file.
2. **Rate limiter:** A configurable `cooldown` (default: 3 seconds) enforces a minimum inter-call delay to avoid exhausting the LLM API rate limit.
3. **Tail read:** The last 60 lines of the file are extracted — sufficient to capture a burst attack without sending the full (potentially large) log file.
4. **LLM analysis:** The tail is sent to NVIDIA NIM with a strict system prompt that demands a JSON-only response.
5. **Fallback:** If the LLM is unreachable, a 14-rule regex engine (`FALLBACK_RULES`) evaluates the content.
6. **Alert emission:** If `is_suspicious=true`, an alert dict is placed on `alert_queue`.

**LLM output schema (Sentry):**
```json
{
  "is_suspicious": true,
  "severity":      "LOW | MEDIUM | HIGH | CRITICAL",
  "event_type":    "BRUTE_FORCE | DATA_EXFILTRATION | UNAUTHORIZED_ACCESS |
                    PRIVILEGE_ESCALATION | MALWARE | LOG_TAMPERING | NORMAL",
  "reason":        "<one-sentence explanation>",
  "indicators":    ["<matched pattern 1>", "..."]
}
```

**Deletion detection:**  
Log file deletion is treated as an unconditional HIGH-severity `LOG_TAMPERING` event (evidence destruction), without consulting the LLM.

**Fallback rule catalogue:**

| Regex Pattern | Event Type | Severity |
|---|---|---|
| `Failed password` | BRUTE_FORCE | MEDIUM |
| `Invalid user` | BRUTE_FORCE | HIGH |
| `POSSIBLE BREAK-IN ATTEMPT` | BRUTE_FORCE | CRITICAL |
| `sudo.*FAILED` | PRIVILEGE_ESCALATION | HIGH |
| `/etc/shadow` | UNAUTHORIZED_ACCESS | CRITICAL |
| `rm\s+-rf` | MALWARE | HIGH |
| `base64\s+-d` | MALWARE | HIGH |
| `nc\s+-e` | MALWARE | CRITICAL |
| `chmod\s+777` | PRIVILEGE_ESCALATION | MEDIUM |
| `\bnmap\b` | UNAUTHORIZED_ACCESS | MEDIUM |

---

### 3.2 Agent 2 — The Investigator (`investigator.py`)

**Role:** Forensic analyst. Receives Sentry alerts, gathers structured evidence using a tool-belt of purpose-built functions, then calls the LLM to produce a root-cause narrative.

**Tool-belt (8 functions):**

| Tool | Description |
|------|-------------|
| `search_logs(keyword)` | Full-text search across all `*.log` / `*.txt` files under `./logs/`; returns `{file, line_number, content}` hits (capped at 80) |
| `open_file(path)` | Safe whole-file read, access-controlled to `./logs/` |
| `read_lines(path, start, end)` | Read a specific line range (1-indexed) from a log file |
| `get_file_metadata(path)` | `os.stat` wrapper: size, creation time, last-modified time |
| `extract_ip_addresses(text)` | Regex-based IPv4 extraction from arbitrary text |
| `extract_usernames(text)` | Heuristic multi-pattern extraction covering `sshd`, `sudo`, PAM formats |
| `count_occurrences(keyword, minutes)` | Frequency count of a keyword across recently modified log files |
| `check_ip_blocklist(ip)` | Lookup against a local `blocklist.json` (dict or list format) |

**Investigation pipeline (per alert):**
1. Extract IPs and usernames from `raw_log`.
2. Search all log files for each IP and username (up to 4 search terms).
3. Deduplicate and cap related events at 40 hits.
4. Collect file metadata of the triggering log.
5. Count IP frequency over the last 10 minutes.
6. Check each IP against the local blocklist.
7. Read the first 80 lines of the triggering file for context.
8. Assemble a compact evidence summary and call the LLM.

**LLM output schema (Investigator):**
```json
{
  "why":                "<root cause>",
  "where":              "<origin IP / user / path>",
  "how":                "<attack method / technique>",
  "impact":             "<potential damage>",
  "confidence":         "HIGH | MEDIUM | LOW",
  "recommended_action": "<what the Responder should do>",
  "threat_actor":       "script_kiddie | insider_threat | apt | automated_bot | unknown",
  "mitre_tactic":       "<MITRE ATT&CK tactic name>"
}
```

The output is placed on `report_queue` as a full `investigation_report` dict containing the original alert, all evidence, and the AI analysis.

---

### 3.3 Agent 3 — The Responder (`responder.py`)

**Role:** Incident commander. Classifies the threat, executes a remediation action (real or simulated), writes a structured Markdown incident report, and escalates to a human operator when automation is insufficient.

**Response action taxonomy:**

| Action | Description |
|--------|-------------|
| `NO_ACTION` | Benign; nothing to do |
| `MONITOR` | Low risk; log only |
| `BLOCK_IP` | Add iptables DROP rule for source IP |
| `LOCK_USER` | Disable account via `usermod -L` |
| `QUARANTINE_FILE` | Move suspicious file to `./quarantine/` |
| `DELETE_FILE` | Remove confirmed-malicious file (scoped to `./reports/`) |
| `ESCALATE_HUMAN` | Too complex for automation; notify operator |

**LLM output schema (Responder):**
```json
{
  "action":             "<action from taxonomy>",
  "target":             "<IP | username | file path | null>",
  "simulated_command":  "<exact shell command, or null>",
  "can_auto_resolve":   true,
  "escalation_reason":  "<reason or null>",
  "incident_title":     "<short title>",
  "incident_report_md": "<complete Markdown incident report>"
}
```

**Execution flow:**
1. Call LLM to classify and produce incident report Markdown.
2. Execute the decided action (`block_ip`, `lock_user`, `quarantine_file`, etc.).
3. Optionally run the `simulated_command` through the whitelisted shell executor.
4. Append live action results (JSON log) to the incident report.
5. Write report to `./reports/INC-<timestamp>-<uuid4[:4]>.md`.
6. If `ESCALATE_HUMAN`: print terminal banner + append to `HUMAN_NOTIFICATIONS.log`.

**Shell command whitelist (`ALLOWED_COMMANDS`):**  
~40 pre-approved binaries across six categories: network diagnostics, identity/access, process control, service/log management, filesystem, and miscellaneous. Any command whose base binary is not in this set is silently blocked and logged.

**Human escalation banner:**
```
================================================================
!!  HUMAN INTERVENTION REQUIRED  !!
================================================================
Incident ID : INC-20260723-103004-1BB1
Time        : 2026-07-23T10:30:07.711154
Reason      : Threat requires manual review.
Report File : ./reports/INC-20260723-103004-1BB1.md
================================================================
```

---

## 4. LLM Integration — NVIDIA NIM

All three agents share a single `NvidiaNimClient` instance (`nvidia_nim_client.py`), which wraps the NVIDIA NIM REST API using an OpenAI-compatible `/v1/chat/completions` endpoint.

### Client features

| Feature | Implementation |
|---------|----------------|
| **Model** | Configurable; default `meta/llama-3.1-8b-instruct` |
| **Temperature** | 0.2 (low randomness for deterministic JSON output) |
| **Top-p** | 0.7 |
| **Max tokens** | 1024 |
| **Rate-limit handling** | Exponential backoff on HTTP 429: 2 s → 4 s → 8 s (cap 30 s), 3 retries |
| **JSON extraction** | Strips markdown fences (` ```json … ``` `), then finds first `{` … last `}` |
| **Timeout** | 120 seconds per request |
| **Health check** | `GET /v1/models` with 5-second timeout |
| **Connectivity modes** | Hosted NIM (`https://integrate.api.nvidia.com/v1`) or self-hosted local NIM (`http://localhost:8000/v1`) |

### Fallback strategy

If `query_json()` returns an `{"error": ...}` dict (connection failure, timeout, or JSON parse failure), each agent falls back to a deterministic rule-based equivalent:

- **Sentry:** regex-based `FALLBACK_RULES` engine
- **Investigator:** static fallback dict with `confidence: LOW` and `recommended_action: "Escalate to human analyst."`
- **Responder:** defaults to `ESCALATE_HUMAN` with reason `"AI responder could not parse the LLM response."`

This ensures the pipeline never blocks or crashes due to LLM unavailability.

---

## 5. Safety and Containment Model

The system was designed with a layered safety model to make it safe to demonstrate and research on real hardware:

| Layer | Mechanism |
|-------|-----------|
| **Simulate-only mode** (default) | `ResponderAgent(simulate_only=True)` — all actions are logged as `[SIMULATED]` with no actual system changes |
| **Command whitelist** | `run_command()` checks the base binary against `ALLOWED_COMMANDS` before any execution, regardless of `simulate_only` |
| **Filesystem scope — delete** | `delete_file()` resolves absolute paths and refuses to delete anything outside `./reports/` |
| **Filesystem scope — read** | `open_file()` and `read_lines()` are scoped to `./logs/` |
| **Input validation** | `block_ip()` validates IPv4 format via regex; `lock_user()` validates username format |
| **Process isolation** | `subprocess.run()` is called with `capture_output=True`, a 10-second timeout, and no shell interpolation (array-based) |

To enable real command execution for a live deployment, pass `--live` to `main.py`. This is explicitly flagged as dangerous in the startup banner.

---

## 6. Synthetic Log Simulator

`log_generator.py` is a standalone script that generates realistic syslog-format entries and writes them to `./logs/`, providing the Sentry with test data during development and demos.

### Attack scenarios

| Scenario | `--attack` flag | What it writes |
|----------|-----------------|----------------|
| SSH brute-force | `brute_force` | 12 `Failed password` lines from attacker IP + 1 success |
| Data exfiltration | `exfiltration` | Login + 500 MB outbound netflow + `/etc/shadow` access |
| Privilege escalation | `privilege_esc` | `sudo` failure + BREAK-IN ATTEMPT + `chmod 777 /tmp/backdoor.sh` |
| Port scan | `port_scan` | nmap detection + SYN probes on 9 common ports |
| Malware download | `malware` | `wget` to attacker domain + `base64 -d | bash` + `nc -e /bin/bash` reverse shell |

### Simulation modes

| Mode | Behaviour |
|------|-----------|
| `--mode normal` | Drip-feeds benign auth/cron/systemd log lines |
| `--mode attack` | Injects the specified attack scenario on repeat |
| `--mode mixed` | Interleaves normal logs with a random attack every 5 ticks |

The attacker IP is fixed at `185.220.101.34` (a well-known Tor exit node in publicly available threat-intel feeds) to make blocklist lookups meaningful.

---

## 7. Output — Incident Reports

Each processed alert produces one Markdown file in `./reports/` named `INC-<YYYYMMDD>-<HHMMSS>-<UUID4[:4]>.md`.

### Report structure

```markdown
# Incident Report: INC-20260723-103004-1BB1

**Timestamp:** 2026-07-23T10:30:07.711154
**Severity:** HIGH
**Type:** BRUTE_FORCE

## Summary
...

## Evidence
- IPs Found: [...]
- Users Found: [...]
- Related Log Hits: N

## Root Cause Analysis
| | |
|-|-|
| Why    | ... |
| Where  | ... |
| How    | ... |
| Impact | ... |

## Actions Taken
...

## Recommendations
...

---
## Actions Taken by Responder

```json
[{"action": "BLOCK_IP", "target": "185.220.101.34", "result": {...}}]
```

*Simulate-only mode: True*
*Report generated: ...*
```

The report is authored by the LLM (Responder's system prompt specifies the format) and then augmented with the actual JSON action log appended by the Responder's Python code.

---

## 8. Tech Stack

| Component | Technology | Version | Rationale |
|-----------|-----------|---------|-----------|
| Language | Python | ≥ 3.10 | `match`/`case`, `X \| Y` type hints, wide library support |
| File monitoring | `watchdog` | ≥ 6.0.0 | Cross-platform fs event callbacks (inotify / FSEvents / ReadDirectoryChangesW) |
| LLM inference | NVIDIA NIM API | — | Hosted or local GPU inference; OpenAI-compatible REST API |
| Default model | `meta/llama-3.1-8b-instruct` | — | Good instruction-following at modest cost; easily swapped |
| HTTP client | `requests` | ≥ 2.31.0 | Synchronous; appropriate for agent threads |
| REST API layer | FastAPI + uvicorn | ≥ 0.111.0 | Backend API server (backend/api_server.py) |
| Async file I/O | `aiofiles` | ≥ 23.2.1 | Non-blocking file operations for the API server |
| Env config | `python-dotenv` | ≥ 1.0.1 | `NVIDIA_NIM_KEY` / `NVIDIA_API_KEY` loaded from `.env` |
| Concurrency | `threading` + `queue.Queue` | stdlib | Lightweight; avoids asyncio complexity in agent loops |

---

## 9. Installation and Usage

### Prerequisites

- Python 3.10 or later
- An NVIDIA NIM API key (obtain at [build.nvidia.com](https://build.nvidia.com/)) **or** a locally running NIM instance

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/<your-repo>/soc-in-a-box.git
cd soc-in-a-box

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set your NVIDIA API key (or pass it via --api-key)
echo "NVIDIA_NIM_KEY=nvapi-..." > .env
```

### Running the SOC

```bash
# Default (simulate-only, hosted NIM, llama-3.1-8b-instruct)
python main.py

# Custom log directory and model
python main.py --logs /var/log/myapp --model mistralai/mistral-7b-instruct-v0.3

# Point to a local NIM instance
python main.py --nim-url http://localhost:8000/v1

# Enable real remediation commands (use with caution)
python main.py --live
```

### Injecting test logs

```bash
# Terminal 2 — inject a brute-force scenario
python log_generator.py --mode attack --attack brute_force

# Continuous mixed simulation (normal + random attacks every ~15s)
python log_generator.py --mode mixed --interval 3

# Available attack types
python log_generator.py --mode attack --attack exfiltration
python log_generator.py --mode attack --attack privilege_esc
python log_generator.py --mode attack --attack port_scan
python log_generator.py --mode attack --attack malware
```

### Viewing results

```bash
# List incident reports
ls reports/

# Read the latest report
cat reports/INC-*.md | head -60

# Watch the live SOC log
tail -f soc.log
```

### CLI reference

```
python main.py [OPTIONS]

Options:
  --logs     PATH   Directory to watch for log changes  [default: ./logs]
  --reports  PATH   Directory for incident reports       [default: ./reports]
  --nim-url  URL    NVIDIA NIM base URL                  [default: https://integrate.api.nvidia.com/v1]
  --model    NAME   NIM model identifier                 [default: meta/llama-3.1-8b-instruct]
  --api-key  KEY    NVIDIA API key (overrides env var)
  --cooldown FLOAT  Minimum seconds between API calls    [default: 3.0]
  --live            Execute real shell commands (default: simulate only)
```

---

## 10. Project Structure

```
soc-in-a-box/
│
├── main.py                   # Entry point; wires agents, handles signals
├── nvidia_nim_client.py      # Shared NVIDIA NIM REST client (all agents)
├── sentry.py                 # Agent 1 — file-system monitor + threat detector
├── investigator.py           # Agent 2 — forensic evidence gathering + analysis
├── responder.py              # Agent 3 — response action + incident report writer
│
├── log_generator.py          # Synthetic attack log injector (testing/demo)
├── blocklist.json            # Local IP blocklist (JSON)
├── requirements.txt          # Python dependencies
├── .env                      # API key (not committed)
│
├── backend/                  # FastAPI REST API layer
│   ├── api_server.py         # REST endpoints (agents, reports, status)
│   ├── audit_db.py           # Incident audit database
│   ├── email_notifier.py     # Email escalation integration
│   ├── event_bus.py          # Internal event publish/subscribe
│   └── __init__.py
│
├── frontend/                 # Web dashboard (React/Vite)
│   └── ...
│
├── logs/                     # Watched log directory (auto-created)
├── reports/                  # Incident report output (auto-created)
└── quarantine/               # Quarantined files (auto-created)
```

---

## 11. Evaluation and Limitations

### Detection coverage

The system detects all five attack categories injected by `log_generator.py`:

| Attack Type | Detection Method | Severity |
|-------------|-----------------|----------|
| SSH Brute Force | LLM + `Failed password` fallback rule | MEDIUM → CRITICAL |
| Data Exfiltration | LLM (netflow + `/etc/shadow` access) | HIGH |
| Privilege Escalation | LLM + `sudo.*FAILED` / `/etc/shadow` rules | HIGH |
| Port Scan | LLM + `\bnmap\b` rule | MEDIUM |
| Malware / Reverse Shell | LLM + `wget`, `base64 -d`, `nc -e` rules | HIGH → CRITICAL |

### Known limitations

1. **Log ingestion scope:** The Sentry only monitors a single local directory. Enterprise environments require log aggregation (e.g., syslog forwarding, Filebeat) before this point.
2. **No log normalisation:** Logs are processed as raw text. Structured log formats (JSON, CEF, LEEF) are not parsed into fields.
3. **Single-file tailing:** The Sentry reads the last 60 lines per event; multi-file correlation happens only in the Investigator phase.
4. **LLM hallucination:** At temperature 0.2, the LLM occasionally produces invalid JSON or incorrect forensic conclusions. The fallback engine mitigates this but cannot replicate LLM-level reasoning.
5. **No persistent state:** Agent state is in-memory only. A crash loses in-flight alerts. A production system would use a durable queue (Kafka, Redis Streams).
6. **Rate limiting:** The default 3-second cooldown limits throughput to ~20 events/minute. High-volume environments require batching or a local NIM deployment.
7. **Simulated-only actions:** In default mode, no real system changes occur. Transitioning to live mode requires careful access controls and audit logging.

---

## 12. Future Work

- **Vector-store memory:** Persist past incidents in a vector database (e.g., ChromaDB, pgvector) so the Investigator can compare new alerts against historical patterns.
- **MITRE ATT&CK integration:** Map detected techniques to ATT&CK matrix entries and visualise attack chains (Navigator layer output).
- **Streaming log ingestion:** Replace the watchdog file-tail approach with a proper log aggregation pipeline (Fluentd / Filebeat → Kafka → Sentry).
- **Multi-host monitoring:** Extend the Sentry to consume logs from multiple hosts via a centralised log topic.
- **Confidence-gated automation:** Only execute hard remediation actions (BLOCK_IP, LOCK_USER) when the Investigator's `confidence` is HIGH; otherwise default to MONITOR.
- **Feedback loop:** Allow human analysts to label incident report quality; use those labels to fine-tune the LLM prompts or a smaller local classifier.
- **Web dashboard:** The `frontend/` and `backend/` directories lay the groundwork for a real-time incident dashboard (React/Vite + FastAPI).
- **Alerting integrations:** The `notify_human()` stub in `responder.py` is designed to be extended with Slack, PagerDuty, or email via the `backend/email_notifier.py` module.

---

## 13. References and Related Work

- **NVIDIA NIM:** [https://build.nvidia.com](https://build.nvidia.com) — hosted LLM inference API.
- **Meta Llama 3.1:** Touvron et al. (2023). *Llama: Open and Efficient Foundation Language Models.* arXiv:2302.13971.
- **watchdog library:** [https://github.com/gorakhargosh/watchdog](https://github.com/gorakhargosh/watchdog)
- **MITRE ATT&CK Framework:** [https://attack.mitre.org](https://attack.mitre.org) — the taxonomy used for tactic labelling in the Investigator's output.
- **IBM Cost of a Data Breach Report 2024:** IBM Security / Ponemon Institute.
- **AutoGPT / LangChain Agents:** Related multi-agent LLM frameworks; this system favours a simpler hand-coded pipeline over a general-purpose agent loop to maximise determinism and safety.
- **Sigma Rules:** [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) — community detection rules that could replace or augment the `FALLBACK_RULES` regex bank.

---

*SOC-in-a-Box — Multi-Agent Autonomous Security Researcher*  
*3rd Year Engineering Major Project, 2025–2026*  
*Prototype v1.0 · Simulate-only by default · No external cloud required for rule-based mode*
