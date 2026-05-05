# SOC-in-a-Box 🛡️
### Multi-Agent Autonomous Security Researcher — Major Project (3rd Year Engineering)

---

## What It Does
Three Python agents that work like a real SOC team:

```
[Log Files] ──▶ SENTRY ──▶ INVESTIGATOR ──▶ RESPONDER ──▶ [Incident Report]
                  (detect)    (why/where/how)   (act + report)
```

| Agent | File | Role |
|-------|------|------|
| **Sentry** | `sentry.py` | Watches `./logs/` for file changes; flags anomalies using NVIDIA NIM AI + rule-based fallback |
| **Investigator** | `investigator.py` | Gathers evidence (IPs, users, related events, blocklist); asks AI: *Why? Where? How?* |
| **Responder** | `responder.py` | Classifies threat; blocks IP / locks user / quarantines file (simulated); writes Markdown incident report |

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Get NVIDIA API Key
1. Visit [NVIDIA API Catalog](https://build.nvidia.com/).
2. Select a model (e.g., `meta/llama-3.1-8b-instruct`).
3. Generate an API Key.

### 3. Start the SOC system
```bash
python main.py --api-key YOUR_NVIDIA_API_KEY
```

### 4. Inject test logs (simulate attacks)
```bash
# Terminal 3 — inject a brute-force attack
python simulator/log_generator.py --mode attack --attack brute_force

# Or run a continuous mixed simulation
python simulator/log_generator.py --mode mixed --interval 3
```

### 5. View incident reports
```bash
ls reports/          # Markdown files appear here after each alert
cat reports/INC-*.md
```

---

## Project Structure
```
soc-in-a-box/
├── main.py                        # Entry point — starts all 3 agents
├── requirements.txt
├── README.md
├── nvidia_nim_client.py           # Shared LLM interface (NVIDIA NIM)
├── sentry.py                      # Agent 1 — Anomaly Detection
├── investigator.py                # Agent 2 — Threat Investigation
├── responder.py                   # Agent 3 — Response & Reporting
├── log_generator.py               # Synthetic attack log injector
├── blocklist.json                 # Known bad IPs (local)
├── logs/                          # Watched directory (auto-created)
├── reports/                       # Incident reports (auto-created)
└── quarantine/                    # Quarantined files (auto-created)
```

---

## CLI Options
```
python main.py --help

  --logs     PATH   Directory to watch (default: ./logs)
  --reports  PATH   Where to save incident reports (default: ./reports)
  --nim-url  URL    NVIDIA NIM base URL (default: https://integrate.api.nvidia.com/v1)
  --model    NAME   NVIDIA NIM model (default: meta/llama-3.1-8b-instruct)
  --api-key  KEY    NVIDIA API Key
  --live            Run REAL shell commands (default is simulate-only)
```

---

## How the Agents Communicate
```
SentryAgent
  │  [watchdog thread watches ./logs/]
  │  On file event: reads last 60 lines → asks Ollama → if suspicious:
  └──▶ alert_queue.put(alert_dict)

InvestigatorAgent   [runs in Thread]
  │  alert_queue.get()
  │  Runs: search_logs, extract_ips, extract_users, count_occurrences,
  │        check_blocklist, read_lines, get_metadata → ask Ollama WHY/WHERE/HOW
  └──▶ report_queue.put(investigation_report)

ResponderAgent      [runs in Thread]
  │  report_queue.get()
  │  Asks Ollama: what action to take?
  │  Executes tool: block_ip | lock_user | quarantine_file | monitor
  │  Writes Markdown incident report to ./reports/INC-*.md
  └──▶ notify_human() if cannot auto-resolve
```

---

## Customisation

### Add a new detection rule (Sentry fallback)
Edit `agents/sentry.py` — add to the `FALLBACK_RULES` list:
```python
(r"your_regex_pattern", "EVENT_TYPE", "SEVERITY"),
```

### Add a new Investigator tool
In `agents/investigator.py`, add a method:
```python
def my_new_tool(self, param: str) -> dict:
    ...
```
Then call it inside `investigate()`.

### Add a new Responder action
In `agents/responder.py`, add a method and handle it in `classify_and_respond()`:
```python
elif action == "MY_ACTION" and target:
    result = self.my_new_action(target)
    action_log.append(...)
```

---

## Tech Stack
| Component | Technology | Why |
|-----------|-----------|-----|
| Language | Python 3.10+ | Team familiarity |
| File monitoring | `watchdog` | Mature, cross-platform fs events |
| LLM | NVIDIA NIM API | Hosted or local NIM |
| HTTP client | `requests` | NVIDIA NIM REST API |
| Multi-threading | `threading` + `queue` | Agents run concurrently |

---

## Safety Notes
- **simulate_only=True** (default): no real iptables, usermod, or file deletions run.
- The Responder's `run_command()` enforces a strict whitelist regardless of mode.
- `delete_file()` is scoped to `./reports/` only.
- `open_file()` and `read_lines()` are scoped to `./logs/` only.

---

*Major Project — 3rd Year Engineering, 2025–2026*
