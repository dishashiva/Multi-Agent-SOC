"""
email_notifier.py - SMTP Email Notifications
----------------------------------------------------------------------------
Sends real email alerts for CRITICAL / HIGH severity incidents that the
Responder cannot auto-resolve.

Configuration (via .env or environment variables)
-------------------------------------------------
    SMTP_HOST     = smtp.gmail.com
    SMTP_PORT     = 587
    SMTP_USER     = your@gmail.com
    SMTP_PASS     = your-app-password    (Gmail: use App Passwords)
    NOTIFY_EMAIL  = alerts@yourcompany.com

If any of the above are missing, email sending is silently skipped and
a warning is logged. No crash, no broken agents.
----------------------------------------------------------------------------
"""

import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logger = logging.getLogger(__name__)


def _get_config() -> dict:
    return {
        "host":    os.getenv("SMTP_HOST", ""),
        "port":    int(os.getenv("SMTP_PORT", "587")),
        "user":    os.getenv("SMTP_USER", ""),
        "passwd":  os.getenv("SMTP_PASS", ""),
        "to":      os.getenv("NOTIFY_EMAIL", ""),
    }


def is_configured() -> bool:
    cfg = _get_config()
    return all([cfg["host"], cfg["user"], cfg["passwd"], cfg["to"]])


def send_alert(
    incident_id: str,
    severity: str,
    event_type: str,
    reason: str,
    report_path: str,
    extra_details: str = "",
) -> bool:
    """
    Send an HTML email alert.
    Returns True on success, False on failure / not configured.
    """
    if not is_configured():
        logger.warning(
            "[EmailNotifier] SMTP not configured — skipping email. "
            "Set SMTP_HOST, SMTP_USER, SMTP_PASS, NOTIFY_EMAIL in .env to enable."
        )
        return False

    cfg = _get_config()
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    severity_color = {
        "CRITICAL": "#FF3B3B",
        "HIGH":     "#FF8C00",
        "MEDIUM":   "#FFD700",
        "LOW":      "#00CED1",
    }.get(severity.upper(), "#888888")

    subject = f"🚨 [{severity}] SOC Alert: {event_type} — {incident_id}"

    html = f"""
    <html><body style="font-family: Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 24px;">
      <div style="max-width: 640px; margin: 0 auto; background: #161b22; border-radius: 12px; padding: 32px; border: 1px solid #30363d;">
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:24px;">
          <span style="font-size:32px;">🛡️</span>
          <h1 style="margin:0; font-size:20px; color:#58a6ff;">SOC-in-a-Box Alert</h1>
        </div>
        <div style="background:{severity_color}22; border-left: 4px solid {severity_color}; padding:16px; border-radius:8px; margin-bottom:24px;">
          <span style="color:{severity_color}; font-weight:bold; font-size:18px;">⚠ {severity} SEVERITY</span>
        </div>
        <table style="width:100%; border-collapse:collapse;">
          <tr><td style="padding:8px; color:#8b949e; width:160px;">Incident ID</td>
              <td style="padding:8px; font-family:monospace; color:#f0f6fc;">{incident_id}</td></tr>
          <tr><td style="padding:8px; color:#8b949e;">Event Type</td>
              <td style="padding:8px; color:#f0f6fc;">{event_type}</td></tr>
          <tr><td style="padding:8px; color:#8b949e;">Timestamp</td>
              <td style="padding:8px; color:#f0f6fc;">{ts}</td></tr>
          <tr><td style="padding:8px; color:#8b949e;">Reason</td>
              <td style="padding:8px; color:#f0f6fc;">{reason}</td></tr>
          <tr><td style="padding:8px; color:#8b949e;">Report File</td>
              <td style="padding:8px; font-family:monospace; color:#79c0ff;">{report_path}</td></tr>
        </table>
        {f'<div style="margin-top:16px; padding:16px; background:#21262d; border-radius:8px;"><pre style="margin:0; color:#e6edf3; font-size:13px;">{extra_details}</pre></div>' if extra_details else ''}
        <p style="margin-top:24px; color:#8b949e; font-size:13px;">
          This alert was generated automatically by SOC-in-a-Box.<br>
          The autonomous responder could NOT resolve this incident — <strong style="color:#f85149;">human intervention required</strong>.
        </p>
      </div>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg["user"]
    msg["To"]      = cfg["to"]
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(cfg["user"], cfg["passwd"])
            server.sendmail(cfg["user"], cfg["to"], msg.as_string())
        logger.info(f"[EmailNotifier] Alert email sent to {cfg['to']} for {incident_id}")
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("[EmailNotifier] SMTP authentication failed — check SMTP_USER/SMTP_PASS.")
    except smtplib.SMTPConnectError:
        logger.error(f"[EmailNotifier] Cannot connect to {cfg['host']}:{cfg['port']}.")
    except Exception as exc:
        logger.error(f"[EmailNotifier] Failed to send email: {exc}")
    return False
