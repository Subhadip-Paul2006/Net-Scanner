"""Post-scan lifecycle hooks (feature F8).

Alert dispatch when an *untrusted* device joins the network (its IP is
present in the latest scan but not marked ``trusted`` in the device's
inventory). Three backends:

  * ``windows_toast`` — native toast via PowerShell + WinRT (no deps).
  * ``slack``         — POST to a webhook URL (stdlib ``urllib``).
  * ``email``         — SMTP via env vars SIGHT_SMTP_*/SIGHT_ALERT_TO.

The CLI calls :func:`run_post_scan_hooks` after each scan is persisted.
Each backend is best-effort: failures are logged, never raised.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import subprocess
from email.message import EmailMessage
from typing import TYPE_CHECKING
from urllib import request as urllib_request

if TYPE_CHECKING:
    from netsight.models import ScanResult

_LOG = logging.getLogger("netsight.hooks")


def _windows_toast(title: str, body: str) -> bool:
    """Best-effort Windows toast via PowerShell / WinRT."""
    ps = (
        "[Windows.UI.Notifications.ToastNotificationManager, "
        "Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;"
        "$t = [Windows.UI.Notifications.ToastNotificationManager]::"
        "GetTemplateContent('ToastText02');"
        "$t.SelectSingleNode('//text[@id=\"1\"]').InnerText = "
        + _ps_sq(title) + ";"
        "$t.SelectSingleNode('//text[@id=\"2\"]').InnerText = "
        + _ps_sq(body) + ";"
        "$n = New-Object Windows.UI.Notifications.ToastNotification $t;"
        "[Windows.UI.Notifications.ToastNotificationManager]::"
        "CreateToastNotifier('NetSight').Show($n)"
    )
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, timeout=10, check=False,
        )
        return True
    except (OSError, subprocess.TimeoutExpired) as exc:
        _LOG.warning("windows_toast failed: %s", exc)
        return False


def _ps_sq(text: str) -> str:
    """PowerShell single-quote escape."""
    return "'" + text.replace("'", "''") + "'"


def _slack(webhook: str, title: str, body: str) -> bool:
    """Post a JSON message to a Slack incoming webhook."""
    payload = json.dumps({
        "text": f"*{title}*\n{body}",
    }).encode("utf-8")
    try:
        req = urllib_request.Request(
            webhook,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except OSError as exc:
        _LOG.warning("slack hook failed: %s", exc)
        return False


def _email(title: str, body: str) -> bool:
    """Send an alert email using SIGHT_SMTP_* environment variables."""
    host = os.environ.get("SIGHT_SMTP_HOST")
    to_addr = os.environ.get("SIGHT_ALERT_TO")
    if not host or not to_addr:
        return False
    port = int(os.environ.get("SIGHT_SMTP_PORT", "587"))
    user = os.environ.get("SIGHT_SMTP_USER", "")
    password = os.environ.get("SIGHT_SMTP_PASS", "")
    from_addr = os.environ.get("SIGHT_ALERT_FROM", user or to_addr)

    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        _LOG.warning("email hook failed: %s", exc)
        return False


def run_post_scan_hooks(
    scan: "ScanResult",
    scan_id: int,
    *,
    unknown_ips: list[str] | None = None,
    slack_webhook: str | None = None,
    toast: bool = False,
    email: bool = False,
) -> None:
    """Dispatch alerts for untrusted devices found in ``scan``.

    Args:
        scan: The completed scan.
        scan_id: Row id in the history DB.
        unknown_ips: IPs not marked trusted. Passed every hook when falsy.
        slack_webhook: Slack incoming-webhook URL, or None to disable.
        toast: When True, attempt a native Windows toast.
        email: When True, attempt an SMTP email via SIGHT_SMTP_* env vars.
    """
    if not unknown_ips:
        return
    title = "NetSight — untrusted device(s) detected"
    body = (
        f"Scan #{scan_id} ({scan.subnet}) found "
        f"{len(unknown_ips)} untrusted device(s): "
        + ", ".join(unknown_ips[:10])
    )
    if len(unknown_ips) > 10:
        body += f", +{len(unknown_ips) - 10} more"

    if toast:
        _windows_toast(title, body)
    if slack_webhook:
        _slack(slack_webhook, title, body)
    if email:
        _email(title, body)
