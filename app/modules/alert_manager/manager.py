"""Alert routing: severity thresholds per channel, de-duplication and trigger builders."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from app.core.models import Finding, Severity
from app.modules.alert_manager.channels import AlertChannel
from app.modules.alert_manager.models import AlertEvent, AlertTrigger

logger = logging.getLogger(__name__)

#: Alerts are only raised for these severities (informational is never alerted).
ALERTABLE = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


@dataclass
class ChannelRoute:
    channel: AlertChannel
    min_severity: Severity = Severity.LOW


@dataclass
class DispatchResult:
    sent: list[AlertEvent] = field(default_factory=list)
    suppressed: list[AlertEvent] = field(default_factory=list)


class AlertManager:
    """Dispatch alerts to channels with de-duplication.

    ``is_duplicate`` is a callback (fingerprint -> bool) so the cooldown can be
    backed by the database across processes; an in-memory set is used by
    default and also suppresses duplicates within a single batch.
    """

    def __init__(
        self,
        routes: Iterable[ChannelRoute],
        is_duplicate: Callable[[str], bool] | None = None,
    ) -> None:
        self.routes = list(routes)
        self._is_duplicate = is_duplicate or (lambda _fp: False)
        self._seen: set[str] = set()

    def dispatch(self, alert: AlertEvent) -> bool:
        """Send one alert. Returns ``False`` if it was suppressed."""
        if alert.severity not in ALERTABLE:
            return False
        if alert.fingerprint in self._seen or self._is_duplicate(alert.fingerprint):
            return False
        self._seen.add(alert.fingerprint)
        eligible = [r for r in self.routes if alert.severity.rank >= r.min_severity.rank]
        names = [r.channel.name for r in eligible]
        delivered: list[str] = []
        for route in eligible:
            if hasattr(route.channel, "pending_channels"):
                route.channel.pending_channels = names  # type: ignore[attr-defined]
            try:
                if route.channel.send(alert):
                    delivered.append(route.channel.name)
            except Exception:  # a broken channel must never stop the others
                logger.exception("Alert channel %s failed", route.channel.name)
        return bool(delivered)

    def dispatch_many(self, alerts: Iterable[AlertEvent]) -> DispatchResult:
        result = DispatchResult()
        for alert in alerts:
            (result.sent if self.dispatch(alert) else result.suppressed).append(alert)
        return result


# =============================================================================
# Trigger builders
# =============================================================================

_TRIGGER_BY_SOURCE = {
    "system_auditor": AlertTrigger.UNSAFE_CONFIGURATION,
    "vulnerability_analyzer": AlertTrigger.VULNERABILITY_DISCOVERED,
    "traffic_monitor": AlertTrigger.TRAFFIC_ANOMALY,
}


def alerts_from_findings(findings: Iterable[Finding], min_severity: Severity = Severity.HIGH) -> list[AlertEvent]:
    """One alert per finding at or above ``min_severity``."""
    alerts = []
    for finding in findings:
        if finding.severity.rank < min_severity.rank or finding.severity not in ALERTABLE:
            continue
        if finding.finding_id.startswith("TRF-IOC"):
            trigger = AlertTrigger.THREAT_INTEL_MATCH
        elif finding.finding_id == "TRF-SPIKE":
            trigger = AlertTrigger.TRAFFIC_SPIKE
        else:
            trigger = _TRIGGER_BY_SOURCE.get(finding.source, AlertTrigger.UNSAFE_CONFIGURATION)
        alerts.append(
            AlertEvent(
                severity=finding.severity,
                trigger=trigger,
                title=finding.title,
                message=f"{finding.description}\n\nEvidence: {finding.evidence}\n\nRecommendation: "
                f"{finding.recommendation}",
                source=finding.source,
                asset=finding.asset,
            )
        )
    return alerts


def alerts_from_compliance(framework_scores: dict[str, float], threshold: float) -> list[AlertEvent]:
    """Raise a compliance-failure alert for each framework scoring below ``threshold``."""
    alerts = []
    for framework, score in framework_scores.items():
        if score >= threshold:
            continue
        severity = Severity.HIGH if score < threshold - 20 else Severity.MEDIUM
        alerts.append(
            AlertEvent(
                severity=severity,
                trigger=AlertTrigger.COMPLIANCE_FAILURE,
                # Stable title (no score) so the cooldown de-duplicates repeated evaluations.
                title=f"{framework} compliance below the {threshold:.0f}% threshold",
                message=f"The latest technical compliance evaluation for {framework} scored {score:.1f}% "
                f"(threshold {threshold:.0f}%). Review the gap analysis in the compliance report.",
                source="compliance_checker",
            )
        )
    return alerts
