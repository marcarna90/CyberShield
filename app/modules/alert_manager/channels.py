"""Alert delivery channels: structured log, SMTP e-mail and dashboard (database)."""

from __future__ import annotations

import logging
import re
import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from typing import Protocol

from app.modules.alert_manager.models import AlertEvent

alerts_logger = logging.getLogger("cybershield.alerts")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+$")
_HEADER_SAFE = re.compile(r"[\r\n]+")


class AlertChannel(Protocol):
    name: str

    def send(self, alert: AlertEvent) -> bool: ...


class LogChannel:
    """Write alerts to the ``cybershield.alerts`` logger (``logs/alerts.log`` + stdout)."""

    name = "log"

    def send(self, alert: AlertEvent) -> bool:
        level = logging.CRITICAL if alert.severity.rank >= 4 else logging.WARNING
        alerts_logger.log(
            level,
            "[%s] %s",
            alert.severity.value.upper(),
            alert.title,
            extra={
                "alert_trigger": alert.trigger.value,
                "alert_severity": alert.severity.value,
                "alert_asset": alert.asset,
                "alert_source": alert.source,
                "alert_fingerprint": alert.fingerprint,
            },
        )
        return True


class EmailChannel:
    """SMTP delivery with STARTTLS (certificate verified) and header-injection protection."""

    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        username: str | None = None,
        password: str | None = None,
        starttls: bool = True,
        timeout: float = 10.0,
        smtp_factory: Callable[..., smtplib.SMTP] = smtplib.SMTP,
    ) -> None:
        invalid = [r for r in [sender, *recipients] if not _EMAIL_RE.match(r)]
        if invalid:
            raise ValueError(f"Invalid e-mail address(es): {invalid}")
        if not recipients:
            raise ValueError("At least one recipient is required")
        self.host, self.port, self.sender, self.recipients = host, port, sender, recipients
        self.username, self.password, self.starttls, self.timeout = username, password, starttls, timeout
        self._smtp_factory = smtp_factory

    def build_message(self, alert: AlertEvent) -> EmailMessage:
        message = EmailMessage()
        subject = f"[CyberShield][{alert.severity.value.upper()}] {alert.title}"
        message["Subject"] = _HEADER_SAFE.sub(" ", subject)[:200]
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message.set_content(
            "\n".join(
                [
                    f"Severity : {alert.severity.value}",
                    f"Trigger  : {alert.trigger.value}",
                    f"Asset    : {alert.asset or '-'}",
                    f"Source   : {alert.source}",
                    f"Time     : {alert.created_at.isoformat()}",
                    "",
                    alert.message,
                    "",
                    "-- CyberShield Enterprise Security Platform (automated alert)",
                ]
            )
        )
        return message

    def send(self, alert: AlertEvent) -> bool:
        try:
            with self._smtp_factory(self.host, self.port, timeout=self.timeout) as smtp:
                if self.starttls:
                    smtp.starttls(context=ssl.create_default_context())
                if self.username and self.password:
                    smtp.login(self.username, self.password)
                smtp.send_message(self.build_message(alert))
        except (OSError, smtplib.SMTPException) as exc:
            logging.getLogger(__name__).error("E-mail alert delivery failed: %s", exc)
            return False
        return True


class DashboardChannel:
    """Persist alerts so they appear in the dashboard (callback injected by the service layer)."""

    name = "dashboard"

    def __init__(self, persist: Callable[[AlertEvent, list[str]], None]) -> None:
        self._persist = persist
        self.pending_channels: list[str] = []

    def send(self, alert: AlertEvent) -> bool:
        self._persist(alert, self.pending_channels)
        return True
