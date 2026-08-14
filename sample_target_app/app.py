"""
sample_target_app/app.py - Real-world Sample Application with Vulnerabilities & Bugs
----------------------------------------------------------------------------------
Simulates a production web application (FinTech / User Portal) that writes runtime logs
to a local `logs/` directory (`logs/app.log` and `logs/security.log`).

This app includes:
1. Normal user activity (login, profile view, search, checkout)
2. Authentication failures & brute-force attack vectors
3. Unhandled application errors & 500 server crashes (DB connection errors, NullPointer)
4. Security bugs & injection attempts (SQLi, Directory Traversal, Command Injection)
5. File access anomalies
----------------------------------------------------------------------------------
"""

import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Response, Query
from pydantic import BaseModel

# Ensure logs directory exists
LOGS_DIR = Path(__file__).parent / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

APP_LOG_PATH = LOGS_DIR / "app.log"
SEC_LOG_PATH = LOGS_DIR / "security.log"

# Setup standard python logging handlers
formatter = logging.Formatter("%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

# App log handler
app_handler = RotatingFileHandler(APP_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
app_handler.setFormatter(formatter)
app_handler.setLevel(logging.INFO)

# Security log handler
sec_handler = RotatingFileHandler(SEC_LOG_PATH, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
sec_handler.setFormatter(formatter)
sec_handler.setLevel(logging.WARNING)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)

logger = logging.getLogger("TargetApp")
logger.setLevel(logging.DEBUG)
logger.addHandler(app_handler)
logger.addHandler(sec_handler)
logger.addHandler(console_handler)

app = FastAPI(title="Sample Target Application", version="1.0.0")

# --- Models ---
class LoginRequest(BaseModel):
    username: str
    password: str

class PaymentRequest(BaseModel):
    account_id: str
    amount: float
    currency: str = "USD"

# --- Middleware for Access Logging ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    
    log_msg = f"{client_ip} - \"{request.method} {request.url.path}\" {response.status_code} ({duration_ms}ms)"
    if response.status_code >= 500:
        logger.error(f"HTTP Server Error: {log_msg}")
    elif response.status_code >= 400:
        logger.warning(f"HTTP Client Error: {log_msg}")
    else:
        logger.info(f"HTTP Request: {log_msg}")
        
    return response

# --- Endpoints with Normal & Buggy Behaviors ---

@app.get("/")
def read_root():
    return {"status": "online", "system": "Target App v1.0", "logs_directory": str(LOGS_DIR)}

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "185.220.101.47"
    
    # Simulate valid users
    valid_users = {"admin": "SecretPass123!", "alice": "password123", "bob": "securepass"}
    
    if req.username in valid_users and valid_users[req.username] == req.password:
        logger.info(f"[SSHD/AUTH] Accepted password for {req.username} from {client_ip} port {request.url.port or 443}")
        return {"status": "success", "token": "jwt-token-sample-xyz"}
    
    # Bug / Security Failure: Failed login attempts
    if "admin" in req.username.lower() or "root" in req.username.lower():
        logger.warning(f"[SSHD/AUTH] Failed password for invalid user {req.username} from {client_ip}")
        logger.error(f"POSSIBLE BREAK-IN ATTEMPT from {client_ip} for user {req.username}")
    else:
        logger.warning(f"[SSHD/AUTH] Failed password for user {req.username} from {client_ip}")
        
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.get("/api/db/search")
def search_database(q: str = Query(...), request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    # SQL Injection detection simulation
    sql_keywords = ["SELECT", "UNION", "DROP", "INSERT", "--", "' OR '1'='1"]
    if any(kw in q.upper() for kw in sql_keywords):
        logger.error(f"[DB_ERROR] Query failed: You have an error in your SQL syntax near '{q}' at line 1 - possible SQL injection attempt from {client_ip}")
        raise HTTPException(status_code=400, detail="Database syntax error")
        
    logger.info(f"[DB] Executed query: SELECT * FROM items WHERE name LIKE '%{q}%'")
    return {"results": [{"id": 1, "name": f"Item matching {q}"}]}

@app.get("/api/files/download")
def download_file(path: str = Query(...), request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    # Sensitive file access / Directory Traversal simulation
    if "etc/passwd" in path or "etc/shadow" in path or "system32" in path.lower():
        logger.critical(f"[AUDITD] SYSCALL type=OPEN comm=cat name={path} user=guest src={client_ip} - UNAUTHORIZED ACCESS TO SENSITIVE SYSTEM FILE")
        raise HTTPException(status_code=403, detail="Access to sensitive system file denied")
        
    logger.info(f"[FILES] File requested: {path} by client {client_ip}")
    return {"filename": path, "content": "Sample file data"}

@app.post("/api/payments/process")
def process_payment(payment: PaymentRequest, request: Request):
    # Simulate DB Connection Failure Bug / Exception
    if payment.amount > 5000:
        logger.error(f"[DATABASE_CRASH] ConnectionRefusedError: Could not connect to PostgreSQL master pool at 10.0.0.4:5432 (Timeout 30s)")
        logger.critical(f"[SYSTEMD] Service postgresql.service: Main process exited, code=killed status=9/KILL")
        raise HTTPException(status_code=500, detail="Internal Server Error: Database Connection Failed")
        
    logger.info(f"[PAYMENTS] Processed payment of ${payment.amount} for account {payment.account_id}")
    return {"status": "processed", "transaction_id": f"tx_{int(time.time())}"}

@app.post("/api/system/exec")
def execute_command(cmd: str = Query(...), request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    dangerous_cmds = ["nc -e", "base64", "chmod 777", "rm -rf", "wget", "curl"]
    if any(d in cmd for d in dangerous_cmds):
        logger.critical(f"[PROCESS] Suspicious malicious command executed: `{cmd}` by user root from {client_ip}")
        logger.error(f"[SUDO] root : FAILED command execution ; TTY=pts/0 ; COMMAND={cmd}")
        return {"status": "blocked", "warning": "Malicious command execution flagged"}
        
    logger.info(f"[SYSTEM] Shell command executed: {cmd}")
    return {"status": "executed", "output": f"Executed {cmd}"}

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Target Application on http://127.0.0.1:8002 ...")
    uvicorn.run(app, host="127.0.0.1", port=8002)
