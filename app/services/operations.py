"""High-level security operations used by the API, CLI, sensor and demo seeder.

Each operation: runs a module, persists results (scan record, assets,
findings), raises alerts, and re-evaluates compliance where relevant.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import Settings
from app.core.models import CheckStatus, Finding, Severity, utcnow
from app.core.scope import ScopeError
from app.database import repository
from app.database.models import Alert, Asset, ReportRecord, Scan, TrafficSnapshot
from app.modules.alert_manager import (
    AlertEvent,
    AlertManager,
    ChannelRoute,
    DashboardChannel,
    EmailChannel,
    LogChannel,
    alerts_from_compliance,
    alerts_from_findings,
)
from app.modules.compliance_checker import ComplianceChecker, ComplianceReport, derive_signals
from app.modules.network_scanner import SCAN_PROFILES, NetworkScanner, ScanError
from app.modules.reporting_engine import ReportEngine, ReportFormat, ReportType, build_report
from app.modules.system_auditor import AuditContext, HostAuditor, HostAuditReport
from app.modules.traffic_monitor.analyzer import TrafficSummary
from app.modules.traffic_monitor.capture import analyze_pcap
from app.modules.vulnerability_analyzer import VulnerabilityAnalyzer
from app.services.context import get_cve_db, get_iocs, get_scope, traffic_thresholds

logger = logging.getLogger(__name__)


# =============================================================================
# Alerting
# =============================================================================


def build_alert_manager(db: Session, settings: Settings, *, is_demo: bool = False) -> AlertManager:
    def persist(alert: AlertEvent, channels: list[str]) -> None:
        db.add(
            Alert(
                created_at=alert.created_at,
                severity=alert.severity.value,
                trigger=alert.trigger.value,
                title=alert.title[:300],
                message=alert.message,
                source=alert.source,
                asset=alert.asset,
                fingerprint=alert.fingerprint,
                channels=channels,
                is_demo=is_demo,
            )
        )
        db.commit()

    routes = [ChannelRoute(LogChannel()), ChannelRoute(DashboardChannel(persist))]
    if settings.smtp_host and settings.alert_email_recipients and not is_demo:
        routes.append(
            ChannelRoute(
                EmailChannel(
                    host=settings.smtp_host,
                    port=settings.smtp_port,
                    sender=settings.smtp_from,
                    recipients=settings.alert_email_recipients,
                    username=settings.smtp_user,
                    password=settings.smtp_password_value,
                    starttls=settings.smtp_starttls,
                ),
                min_severity=Severity.parse(settings.alert_email_min_severity),
            )
        )
    return AlertManager(
        routes, is_duplicate=lambda fp: repository.alert_recently_raised(db, fp, settings.alert_cooldown_minutes)
    )


# =============================================================================
# Host audit
# =============================================================================


def run_host_audit(
    db: Session,
    settings: Settings,
    actor: str,
    *,
    host_root: Path | None = None,
    context: AuditContext | None = None,
    is_demo: bool = False,
    now: datetime | None = None,
) -> tuple[Scan, HostAuditReport]:
    root = host_root or settings.host_root
    scan = repository.create_scan(db, scan_type="host_audit", target=str(root), requested_by=actor, is_demo=is_demo)
    if now:
        scan.started_at = now
    try:
        report = HostAuditor(context or AuditContext(host_root=root)).run()
    except Exception as exc:
        repository.fail_scan(db, scan, f"{type(exc).__name__}: {exc}")
        raise
    repository.complete_scan(db, scan, report.model_dump(mode="json"), finished_at=now)
    repository.sync_findings(
        db,
        findings=report.findings,
        source="system_auditor",
        assets_in_scope=[report.hostname],
        scan=scan,
        is_demo=is_demo,
        seen_at=now,
    )
    build_alert_manager(db, settings, is_demo=is_demo).dispatch_many(alerts_from_findings(report.findings))
    run_compliance(db, settings, actor, is_demo=is_demo, now=now)
    return scan, report


# =============================================================================
# Network scan + vulnerability analysis
# =============================================================================


def queue_network_scan(db: Session, actor: str, targets: Sequence[str], profile: str) -> Scan:
    """Create a queued scan record (validated targets) for background execution."""
    if profile not in SCAN_PROFILES:
        raise ValueError(f"Unknown profile {profile!r}")
    return repository.create_scan(
        db, scan_type="network", target=",".join(targets), profile=profile, requested_by=actor, status="queued"
    )


def execute_network_scan(
    db: Session,
    settings: Settings,
    scan: Scan,
    targets: Sequence[str],
    profile: str,
    *,
    scanner_factory: Callable[[], Any] | None = None,
) -> Scan:
    """Run Nmap, persist assets/services, analyse vulnerabilities and raise alerts."""
    scan.status = "running"
    db.commit()
    try:
        scanner = NetworkScanner(get_scope(settings), settings.nmap_host_timeout, scanner_factory)
        result = scanner.scan(targets, profile)
    except (ScanError, ScopeError, ValueError) as exc:
        logger.warning("Network scan %s failed: %s", scan.id, exc)
        return repository.fail_scan(db, scan, str(exc))
    for asset in result.assets:
        repository.upsert_asset(db, asset.model_dump())
    return record_vulnerability_analysis(
        db,
        settings,
        scan,
        result.assets,
        extra={
            "targets": result.targets,
            "profile": profile,
            "command_line": result.command_line,
            "hosts_up": result.hosts_up,
            "hosts_total": result.hosts_total,
        },
    )


def record_vulnerability_analysis(
    db: Session,
    settings: Settings,
    scan: Scan,
    assets: Sequence[Any],
    *,
    extra: dict[str, Any] | None = None,
    is_demo: bool = False,
    now: datetime | None = None,
) -> Scan:
    report = VulnerabilityAnalyzer(get_cve_db(settings)).analyze(assets)
    stats = repository.sync_findings(
        db,
        findings=report.findings,
        source="vulnerability_analyzer",
        assets_in_scope=[a.ip for a in assets],
        scan=scan,
        is_demo=is_demo,
        seen_at=now,
    )
    summary = {
        **(extra or {}),
        "assets": [a.ip for a in assets],
        "services_analyzed": report.services_analyzed,
        "severity_counts": report.severity_counts,
        "risk_score": report.risk_score,
        "asset_risk": report.asset_risk,
        "recommendations": report.recommendations,
        "finding_changes": stats,
    }
    repository.complete_scan(db, scan, summary, finished_at=now)
    build_alert_manager(db, settings, is_demo=is_demo).dispatch_many(alerts_from_findings(report.findings))
    run_compliance(db, settings, scan.requested_by, is_demo=is_demo, now=now)
    return scan


# =============================================================================
# Traffic
# =============================================================================


def record_traffic(
    db: Session,
    settings: Settings,
    summary: TrafficSummary,
    actor: str,
    *,
    is_demo: bool = False,
    now: datetime | None = None,
) -> TrafficSnapshot:
    data = summary.model_dump(mode="json")
    snapshot = repository.save_traffic_snapshot(db, data, summary.source, is_demo=is_demo, created_at=now)
    observed = {t["ip"] for t in summary.top_talkers if t.get("internal")}
    observed |= {f.asset for f in summary.anomalies}
    repository.sync_findings(
        db,
        findings=summary.anomalies,
        source="traffic_monitor",
        assets_in_scope=observed,
        is_demo=is_demo,
        seen_at=now,
    )
    build_alert_manager(db, settings, is_demo=is_demo).dispatch_many(
        alerts_from_findings(summary.anomalies, min_severity=Severity.MEDIUM)
    )
    run_compliance(db, settings, actor, is_demo=is_demo, now=now)
    return snapshot


def analyze_traffic_file(db: Session, settings: Settings, actor: str, path: Path) -> TrafficSnapshot:
    summary = analyze_pcap(path, traffic_thresholds(settings), get_iocs(settings), settings.traffic_max_packets)
    return record_traffic(db, settings, summary, actor)


# =============================================================================
# Compliance
# =============================================================================


def _latest_scan(db: Session, scan_type: str) -> Scan | None:
    query = (
        select(Scan)
        .where(Scan.scan_type == scan_type, Scan.status == "completed")
        .order_by(Scan.started_at.desc(), Scan.id.desc())
        .limit(1)
    )
    return db.scalars(query).first()


def latest_host_audit(db: Session) -> dict[str, Any] | None:
    scan = _latest_scan(db, "host_audit")
    return scan.summary if scan else None


def latest_compliance_report(db: Session) -> dict[str, Any] | None:
    scan = _latest_scan(db, "compliance")
    return scan.summary if scan else None


def latest_traffic(db: Session) -> TrafficSnapshot | None:
    return db.scalars(select(TrafficSnapshot).order_by(TrafficSnapshot.created_at.desc()).limit(1)).first()


def run_compliance(
    db: Session, settings: Settings, actor: str, *, is_demo: bool = False, now: datetime | None = None
) -> ComplianceReport:
    now = now or utcnow()
    host = latest_host_audit(db)
    statuses: dict[str, CheckStatus] = {}
    if host:
        statuses.update({c["check_id"]: CheckStatus(c["status"]) for c in host.get("checks", [])})
    findings = [repository.record_to_finding(r) for r in repository.open_findings(db)]
    vuln_scan = _latest_scan(db, "network")
    traffic = latest_traffic(db)
    statuses.update(
        derive_signals(
            findings,
            last_vulnerability_scan=(vuln_scan.finished_at or vuln_scan.started_at) if vuln_scan else None,
            last_traffic_capture=traffic.created_at if traffic else None,
            now=now,
        )
    )
    report = ComplianceChecker().evaluate(statuses, findings)
    scan = repository.create_scan(db, scan_type="compliance", requested_by=actor, is_demo=is_demo)
    scan.started_at = now
    repository.complete_scan(db, scan, report.model_dump(mode="json"), finished_at=now)
    repository.save_compliance(
        db, [fw.model_dump(mode="json") for fw in report.frameworks], is_demo=is_demo, created_at=now
    )
    scores = {fw.name: fw.score for fw in report.frameworks if fw.passed + fw.partial + fw.failed > 0}
    build_alert_manager(db, settings, is_demo=is_demo).dispatch_many(
        alerts_from_compliance(scores, settings.compliance_alert_threshold)
    )
    return report


# =============================================================================
# Reports
# =============================================================================


def asset_dicts(db: Session) -> list[dict[str, Any]]:
    assets = db.scalars(select(Asset).options(selectinload(Asset.services)).order_by(Asset.ip))
    return [
        {
            "id": a.id,
            "ip": a.ip,
            "hostname": a.hostname,
            "os_guess": a.os_guess,
            "risk_score": a.risk_score,
            "tags": a.tags,
            "last_seen": a.last_seen.isoformat(),
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "name": s.name,
                    "product": s.product,
                    "version": s.version,
                    "extrainfo": s.extrainfo,
                    "cpe": s.cpe,
                }
                for s in a.services
            ],
        }
        for a in assets
    ]


def generate_reports(
    db: Session,
    settings: Settings,
    actor: str,
    report_type: ReportType | str,
    formats: Iterable[ReportFormat | str],
) -> list[ReportRecord]:
    findings: list[Finding] = [repository.record_to_finding(r) for r in repository.open_findings(db)]
    traffic = latest_traffic(db)
    data = build_report(
        ReportType(report_type),
        findings,
        organization=settings.organization,
        generated_by=actor,
        compliance=latest_compliance_report(db),
        assets=asset_dicts(db),
        host_audit=latest_host_audit(db),
        traffic=traffic.summary if traffic else None,
    )
    outputs = ReportEngine(settings.reports_dir).generate(data, formats)
    return [
        repository.save_report_record(
            db,
            report_type=o.report_type.value,
            fmt=o.format.value,
            filename=o.filename,
            sha256=o.sha256,
            size=o.size_bytes,
            created_by=actor,
        )
        for o in outputs
    ]
