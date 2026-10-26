"""Security alerting (log, e-mail, dashboard) with de-duplication."""

from app.modules.alert_manager.channels import DashboardChannel, EmailChannel, LogChannel
from app.modules.alert_manager.manager import (
    AlertManager,
    ChannelRoute,
    alerts_from_compliance,
    alerts_from_findings,
)
from app.modules.alert_manager.models import AlertEvent, AlertTrigger

__all__ = [
    "AlertEvent",
    "AlertManager",
    "AlertTrigger",
    "ChannelRoute",
    "DashboardChannel",
    "EmailChannel",
    "LogChannel",
    "alerts_from_compliance",
    "alerts_from_findings",
]
