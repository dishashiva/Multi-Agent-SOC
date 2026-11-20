# SOC-in-a-Box

SOC-in-a-Box is a prototype security operations workflow for synthetic and local log data. Three Python agents detect suspicious activity, gather evidence, and propose a response. A React dashboard presents logs, incidents, agent status, and audit information.

## How it works

1. **Sentry** watches a local log directory and analyzes recent file content.
2. **Investigator** searches available logs, extracts indicators, and builds an incident summary.
3. **Responder** creates a report and records a proposed action.

Agents communicate through in-process queues. NVIDIA NIM analysis is optional; deterministic rule-based paths provide limited fallback behavior. The included log generator creates synthetic normal and attack scenarios. This is a demonstration prototype, not a production SIEM or validated threat-detection product.

Response is simulation-only by default. The standalone CLI has a `--live` option that can execute guarded commands; use only in an isolated environment. Review `responder.py` and API action controls before enabling any live response.

## Stack

Python, watchdog, NVIDIA NIM-compatible API, FastAPI, SQLite audit storage, React, Vite, and Recharts.

## Run with Docker Compose

Requirements: Docker and Docker Compose. From the repository root:

```bash
docker compose up --build
```

Set `NVIDIA_NIM_KEY` in the shell or an untracked `.env` file to enable hosted model analysis. Without a key, the project uses its rule-based paths. Configure SMTP variables only if email notification is needed. Do not commit credentials.

## Run the standalone engine

Requirements: Python 3.10+.

```bash
python -m venv .venv
# Activate .venv, then:
pip install -r requirements.txt
python main.py
```

The CLI watches `./logs` by default and writes reports to `./reports`. Generate sample events in another terminal:

```bash
python log_generator.py --mode attack --attack brute_force
```

The API and dashboard are included in the Compose setup. For local development, install frontend dependencies with `cd frontend && npm install`; the FastAPI service is started by the Compose configuration.

## Key files

- `main.py`, `sentry.py`, `investigator.py`, `responder.py` — standalone agent workflow
- `backend/api_server.py`, `backend/audit_db.py` — dashboard API and audit persistence
- `frontend/src/` — dashboard interface
- `log_generator.py` — synthetic log scenarios
- `reports/` — generated incident reports (runtime output)
