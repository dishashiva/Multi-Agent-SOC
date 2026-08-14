"""
main.py - SOC-in-a-Box Entry Point
----------------------------------------------------------------------------
Wires the three agents together and starts them in background threads.

    Sentry (watchdog thread)
        |  alert_queue
    Investigator (thread)
        |  report_queue
    Responder (thread)
        |  ./reports/*.md

Usage
-----
    python main.py                     # default config
    python main.py --logs ./my_logs    # custom log folder
    python main.py --live              # run REAL commands (dangerous!)
    python main.py --model mistral     # use a different Ollama model

Requirements
------------
    pip install -r requirements.txt
    ollama pull llama3.1:8b
    ollama serve                       (in a separate terminal)
----------------------------------------------------------------------------
"""

import sys
import time
import queue
import signal
import logging
import argparse
import threading
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from nvidia_nim_client   import NvidiaNimClient
from sentry              import SentryAgent
from investigator        import InvestigatorAgent
from responder           import ResponderAgent

# -- logging setup -------------------------------------------------------------
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt = "%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("soc.log", mode="a"),
    ],
)
logger = logging.getLogger(__name__)


# -- graceful shutdown ---------------------------------------------------------
_SHUTDOWN = threading.Event()

def _handle_signal(sig, frame):
    logger.info("\n[MAIN] Shutdown signal received. Stopping agents...")
    _SHUTDOWN.set()

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# -- startup banner ------------------------------------------------------------
BANNER = r"""
 ____   ___   ____      _          _        ____
/ ___| / _ \ / ___|    (_)_ __    /_\      | __ )  _____  __
\___ \| | | | |   _____| | '_ \  //_\\     |  _ \ / _ \ \/ /
 ___) | |_| | |__|_____| | | | |/  _  \    | |_) | (_) >  <
|____/ \___/ \____|    |_|_| |_/_/ \_\ \   |____/ \___/_/\_\

  Multi-Agent Autonomous Security Researcher - Prototype v1.0
  -------------------------------------------------------------
  Agents: Sentry -> Investigator -> Responder
  LLM:    NVIDIA NIM API
  Mode:   SIMULATION (no real system changes)
"""


# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="SOC-in-a-Box - Autonomous Security Researcher")
    parser.add_argument("--logs",    default="./logs",          help="Directory to watch (default: ./logs)")
    parser.add_argument("--reports", default="./reports",       help="Incident reports output dir")
    parser.add_argument("--nim-url", default="https://integrate.api.nvidia.com/v1", help="NVIDIA NIM base URL")
    parser.add_argument("--model",   default="meta/llama-3.1-8b-instruct", help="NVIDIA NIM model name")
    parser.add_argument("--api-key", default=os.getenv("NVIDIA_NIM_KEY") or os.getenv("NVIDIA_API_KEY"),  help="NVIDIA API Key")
    parser.add_argument("--live",    action="store_true",        help="Run REAL commands (NOT recommended for demo)")
    parser.add_argument("--cooldown", type=float, default=3.0,   help="Seconds between API calls (default: 3)")
    args = parser.parse_args()

    print(BANNER)

    # -- Pre-flight checks -------------------------------------------------
    logger.info("=== PRE-FLIGHT CHECKS ===")

    nim = NvidiaNimClient(base_url=args.nim_url, model=args.model, api_key=args.api_key)

    if nim.is_available():
        logger.info(f"[OK] NVIDIA NIM is reachable ({args.nim_url}) model={args.model}")
    else:
        logger.warning(
            "[!!] NVIDIA NIM is NOT reachable. "
            "Agents will use rule-based fallback.\n"
            "   -> Check your API key and internet connection.\n"
            "   -> Hosted URL: https://integrate.api.nvidia.com/v1"
        )

    simulate = not args.live
    if not simulate:
        logger.warning("[!!] LIVE MODE - real shell commands will be executed!")
    else:
        logger.info("[OK] Simulate-only mode  (no real commands will run)")

    logger.info(f"[OK] Watching logs directory: {args.logs}")
    logger.info(f"[OK] Saving reports to:       {args.reports}")
    logger.info("=========================\n")

    # -- Shared queues -----------------------------------------------------
    # alert_queue : Sentry -> Investigator
    # report_queue: Investigator -> Responder
    alert_queue  = queue.Queue()
    report_queue = queue.Queue()

    # -- Instantiate agents ------------------------------------------------
    sentry = SentryAgent(
        watch_path   = args.logs,
        alert_queue  = alert_queue,
        nim_client   = nim,
        cooldown     = args.cooldown,
    )

    investigator = InvestigatorAgent(
        logs_path    = args.logs,
        alert_queue  = alert_queue,
        report_queue = report_queue,
        nim_client   = nim,
    )

    responder = ResponderAgent(
        report_queue  = report_queue,
        nim_client    = nim,
        simulate_only = simulate,
        reports_dir   = args.reports,
    )


    # -- Start the Investigator and Responder in background threads --------
    t_investigator = threading.Thread(
        target=investigator.run, name="Investigator", daemon=True
    )
    t_responder = threading.Thread(
        target=responder.run, name="Responder", daemon=True
    )

    t_investigator.start()
    t_responder.start()
    logger.info("[MAIN] Investigator thread started.")
    logger.info("[MAIN] Responder thread started.")

    # -- Start the Sentry (watchdog observer in its own thread) ------------
    sentry.start()

    logger.info("[MAIN] [READY] All agents running. Press Ctrl+C to stop.\n")

    # -- Main loop - just wait for shutdown signal -------------------------
    try:
        while not _SHUTDOWN.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    # -- Graceful shutdown -------------------------------------------------
    logger.info("[MAIN] Shutting down...")

    sentry.stop()
    investigator.stop()
    responder.stop()

    # Give threads a moment to finish their current task
    t_investigator.join(timeout=5)
    t_responder.join(timeout=5)

    logger.info("[MAIN] All agents stopped. Goodbye.")


if __name__ == "__main__":
    main()
