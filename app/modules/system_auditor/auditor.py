"""Host audit orchestration and scoring."""

from __future__ import annotations

import platform
import socket
from collections import Counter
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field

from app.core.models import CheckResult, CheckStatus, Finding, Severity, severity_counts, sort_findings, utcnow
from app.modules.system_auditor.checks import REGISTRY, AuditContext, parse_key_values, run_check


class HostAuditReport(BaseModel):
    """Complete result of a host audit (serialisable to JSON)."""

    hostname: str
    os_name: str
    kernel: str
    host_root: str
    started_at: datetime
    finished_at: datetime
    score: float = Field(..., ge=0, le=100, description="Hardening score (100 = fully compliant)")
    checks: list[CheckResult]
    findings: list[Finding]
    summary: dict[str, dict[str, int]]

    def check_statuses(self) -> dict[str, CheckStatus]:
        return {c.check_id: c.status for c in self.checks}


def hardening_score(checks: list[CheckResult]) -> float:
    """Weighted pass ratio over evaluated checks (WARN counts as half)."""
    earned = possible = 0.0
    for result in checks:
        weight = result.severity.weight
        if weight == 0 or result.status in (CheckStatus.UNKNOWN, CheckStatus.NOT_APPLICABLE):
            continue
        possible += weight
        if result.status is CheckStatus.PASS:
            earned += weight
        elif result.status is CheckStatus.WARN:
            earned += weight / 2
    return round(100.0 * earned / possible, 1) if possible else 100.0


class HostAuditor:
    """Run every registered check against an :class:`AuditContext`."""

    def __init__(self, context: AuditContext | None = None, only: set[str] | None = None) -> None:
        self.context = context or AuditContext()
        self.only = only

    def _system_info(self) -> tuple[str, str, str]:
        ctx = self.context
        os_release = parse_key_values(ctx.read("etc/os-release") or "", "=")
        os_name = os_release.get("pretty_name") or os_release.get("name") or platform.system()
        if ctx.is_live:
            hostname, kernel = socket.gethostname(), platform.release()
        else:
            hostname = (ctx.read("etc/hostname") or "unknown-host").strip() or "unknown-host"
            kernel = (ctx.read("proc/sys/kernel/osrelease") or "unknown").strip()
        return hostname, os_name, kernel

    def run(self) -> HostAuditReport:
        started = utcnow()
        hostname, os_name, kernel = self._system_info()
        results = [
            run_check(meta, fn, self.context)
            for meta, fn in REGISTRY
            if self.only is None or meta.check_id in self.only
        ]
        findings = sort_findings(f for r in results if (f := r.to_finding(asset=hostname)) is not None)
        status_counts = Counter(r.status.value for r in results)
        return HostAuditReport(
            hostname=hostname,
            os_name=os_name,
            kernel=kernel,
            host_root=str(Path(self.context.host_root)),
            started_at=started,
            finished_at=utcnow(),
            score=hardening_score(results),
            checks=results,
            findings=findings,
            summary={
                "status": {s.value: status_counts.get(s.value, 0) for s in CheckStatus},
                "severity": severity_counts(findings),
            },
        )


__all__ = ["HostAuditReport", "HostAuditor", "Severity", "hardening_score"]
