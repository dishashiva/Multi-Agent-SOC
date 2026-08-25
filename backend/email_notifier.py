"""
email_notifier.py - SMTP Email Notifications with Anti-Spam & Deduplication
----------------------------------------------------------------------------
Sends email alerts for rare CRITICAL severity security incidents.

Configuration:
- Sender Name: SOC in a BOX Alert
- Sender Address: darshanxd@yahoo.com (via Yahoo Mail SMTP)
- Recipient: disha.gcp.jam.atria@gmail.com (configurable via NOTIFY_EMAIL)
- Anti-Spam: 5-minute deduplication cooldown per threat signature, 30s global throttle.
----------------------------------------------------------------------------
"""

import os
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from datetime import datetime

logger = logging.getLogger(__name__)

# Anti-spam state tracking
_LAST_GLOBAL_EMAIL_TIME: float = 0.0
_RECENT_ALERTS: dict[str, float] = {}  # signature -> timestamp
_GLOBAL_MIN_INTERVAL: float = 180.0    # Strict 3-minute minimum throttle between ANY outgoing email
_ALERT_COOLDOWN: float = 300.0         # 5 min deduplication cooldown per threat signature

DEFAULT_RECIPIENT = "disha.gcp.jam.atria@gmail.com"
SENDER_DISPLAY_NAME = "SOC in a BOX Alert"


def reset_anti_spam():
    """Reset the cooldown and throttling cache for clean fresh start."""
    global _LAST_GLOBAL_EMAIL_TIME, _RECENT_ALERTS
    _LAST_GLOBAL_EMAIL_TIME = 0.0
    _RECENT_ALERTS.clear()
    logger.info("[EmailNotifier] Anti-spam deduplication cache reset.")


def _get_config() -> dict:
    user = os.getenv("SMTP_USER", "darshanxd@yahoo.com")
    passwd = os.getenv("SMTP_PASS") or os.getenv("SMTP_PASSWORD", "dhgcrxoltibibtaf")
    host = os.getenv("SMTP_HOST", "smtp.mail.yahoo.com")
    port_str = os.getenv("SMTP_PORT", "587")
    try:
        port = int(port_str)
    except ValueError:
        port = 587
    to = os.getenv("NOTIFY_EMAIL") or DEFAULT_RECIPIENT

    return {
        "host": host,
        "port": port,
        "user": user,
        "passwd": passwd,
        "to": to,
    }


def is_configured() -> bool:
    cfg = _get_config()
    return bool(cfg["host"] and cfg["user"] and cfg["passwd"] and cfg["to"])


def send_alert(
    incident_id: str,
    severity: str,
    event_type: str,
    reason: str,
    report_path: str,
    extra_details: str = "",
) -> bool:
    """
    Send an HTML email alert with rate-limiting and deduplication.
    Only sends for CRITICAL severity incidents (never spammed).
    """
    global _LAST_GLOBAL_EMAIL_TIME, _RECENT_ALERTS

    sev_upper = severity.upper()
    if sev_upper != "CRITICAL":
        return False

    if not is_configured():
        logger.warning(
            "[EmailNotifier] SMTP not configured — skipping email. "
            "Set SMTP_HOST, SMTP_USER, SMTP_PASS, NOTIFY_EMAIL in .env to enable."
        )
        return False

    now = time.time()

    # 1. Deduplication check based on incident ID or (event_type + reason prefix)
    sig = f"{event_type}:{reason[:40].strip()}"
    if incident_id and incident_id in _RECENT_ALERTS:
        last_sent = _RECENT_ALERTS[incident_id]
        if now - last_sent < _ALERT_COOLDOWN:
            logger.info(f"[EmailNotifier] Anti-Spam: Suppressed duplicate email for incident {incident_id} (5-min cooldown active).")
            return False
    elif sig in _RECENT_ALERTS:
        last_sent = _RECENT_ALERTS[sig]
        if now - last_sent < _ALERT_COOLDOWN:
            logger.info(f"[EmailNotifier] Anti-Spam: Suppressed repeated alert '{event_type}' (5-min cooldown active).")
            return False

    # 2. Global rate throttle: enforce gap between consecutive emails
    if now - _LAST_GLOBAL_EMAIL_TIME < _GLOBAL_MIN_INTERVAL:
        wait_time = int(_GLOBAL_MIN_INTERVAL - (now - _LAST_GLOBAL_EMAIL_TIME))
        logger.info(f"[EmailNotifier] Anti-Spam: Throttling email to prevent flood ({wait_time}s remaining).")
        return False

    cfg = _get_config()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_color = "#dc2626" if sev_upper == "CRITICAL" else "#ea580c"
    subject = f"[{sev_upper}] Security Alert: {event_type} — {incident_id}"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #0f172a; margin: 0; padding: 24px; }}
        .card {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; padding: 28px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }}
        .header {{ margin-bottom: 20px; border-bottom: 1px solid #f1f5f9; padding-bottom: 16px; }}
        .title {{ margin: 0; font-size: 18px; font-weight: 700; color: #0f172a; }}
        .badge {{ background-color: {severity_color}18; color: {severity_color}; border: 1px solid {severity_color}40; padding: 6px 12px; border-radius: 999px; font-weight: 700; font-size: 12px; text-transform: uppercase; display: inline-block; }}
        .meta-table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13.5px; }}
        .meta-table td {{ padding: 8px 0; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
        .meta-label {{ color: #64748b; font-weight: 600; width: 130px; }}
        .meta-value {{ color: #0f172a; font-family: monospace; font-size: 13px; }}
        .snippet {{ margin-top: 18px; padding: 14px; background: #f1f5f9; border-radius: 8px; font-family: monospace; font-size: 12.5px; color: #334155; border: 1px solid #e2e8f0; overflow-x: auto; }}
        .footer {{ margin-top: 24px; padding-top: 16px; border-top: 1px solid #f1f5f9; font-size: 12px; color: #94a3b8; line-height: 1.5; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <h1 class="title">SOC-in-a-Box Security Alert</h1>
          <div style="font-size: 12px; color: #64748b; margin-top: 2px;">Autonomous Multi-Agent SOC Monitor</div>
        </div>

        <div style="margin-bottom: 16px;">
          <span class="badge">{sev_upper} SEVERITY</span>
        </div>

        <table class="meta-table">
          <tr>
            <td class="meta-label">Incident ID:</td>
            <td class="meta-value">{incident_id}</td>
          </tr>
          <tr>
            <td class="meta-label">Event Type:</td>
            <td class="meta-value" style="color: {severity_color}; font-weight: bold;">{event_type}</td>
          </tr>
          <tr>
            <td class="meta-label">Timestamp:</td>
            <td class="meta-value">{ts}</td>
          </tr>
          <tr>
            <td class="meta-label">Reason:</td>
            <td style="color: #0f172a; font-weight: 500;">{reason}</td>
          </tr>
          <tr>
            <td class="meta-label">Report File:</td>
            <td class="meta-value" style="color: #2563eb;">{report_path}</td>
          </tr>
        </table>

        {f'<div class="snippet">{extra_details}</div>' if extra_details else ''}

        <div class="footer">
          This alert was automatically generated by SOC-in-a-Box.<br>
          Recipient: <strong>{cfg['to']}</strong>
        </div>
      </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    # Format sender header as 'SOC in a BOX Alert <user@yahoo.com>'
    msg["From"] = formataddr((SENDER_DISPLAY_NAME, cfg["user"]))
    msg["To"] = cfg["to"]
    msg.attach(MIMEText(html, "html"))

    success = False
    error_msg = ""

    # Strategy 1: Try STARTTLS on specified port (default 587)
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=12) as server:
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception:
                pass
            server.login(cfg["user"], cfg["passwd"])
            server.sendmail(cfg["user"], [cfg["to"]], msg.as_string())
        success = True
    except Exception as exc1:
        error_msg = str(exc1)
        # Strategy 2: Try SSL on port 465 if port 587 failed
        try:
            with smtplib.SMTP_SSL(cfg["host"], 465, timeout=12) as server_ssl:
                server_ssl.login(cfg["user"], cfg["passwd"])
                server_ssl.sendmail(cfg["user"], [cfg["to"]], msg.as_string())
            success = True
        except Exception as exc2:
            error_msg += f" | SSL retry: {exc2}"

    if success:
        _LAST_GLOBAL_EMAIL_TIME = now
        if incident_id:
            _RECENT_ALERTS[incident_id] = now
        _RECENT_ALERTS[sig] = now
        logger.info(f"[EmailNotifier] Critical alert email delivered successfully to {cfg['to']} for {incident_id}")
        return True
    else:
        logger.error(f"[EmailNotifier] Failed to send email alert to {cfg['to']}: {error_msg}")
        return False
