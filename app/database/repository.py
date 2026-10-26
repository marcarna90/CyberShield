"""Data-access helpers shared by the API, CLI, sensor and demo seeder."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.models import Finding, Severity, risk_score, severity_counts, utcnow
from app.core.security import hash_password
from app.database.models import (
    Alert,
    Asset,
    ComplianceResult,
    FindingRecord,
    ReportRecord,
    RevokedToken,
    Scan,
    Service,
    TrafficSnapshot,
    User,
)

# =============================================================================
# Users & tokens
# =============================================================================


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalars(select(User).where(User.username == username)).first()


def create_user(db: Session, *, username: str, email: str, password: str, role: str) -> User:
    user = User(username=username, email=email, hashed_password=hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def count_users(db: Session) -> int:
    return db.scalar(select(func.count(User.id))) or 0


def revoke_token(db: Session, jti: str, expires_at: datetime) -> None:
    if db.get(RevokedToken, jti) is None:
        db.add(RevokedToken(jti=jti, expires_at=expires_at))
    # Opportunistic clean-up of expired revocations.
    for stale in db.scalars(select(RevokedToken).where(RevokedToken.expires_at < utcnow())):
        db.delete(stale)
    db.commit()


def is_token_revoked(db: Session, jti: str) -> bool:
    return db.get(RevokedToken, jti) is not None


# =============================================================================
# Scans
# =============================================================================


def create_scan(
    db: Session,
    *,
    scan_type: str,
    target: str = "",
    profile: str = "",
    requested_by: str = "system",
    status: str = "running",
    is_demo: bool = False,
) -> Scan:
    scan = Scan(
        scan_type=scan_type,
        target=target[:1024],
        profile=profile,
        requested_by=requested_by,
        status=status,
        is_demo=is_demo,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def complete_scan(db: Session, scan: Scan, summary: dict[str, Any], finished_at: datetime | None = None) -> Scan:
    scan.status = "completed"
    scan.finished_at = finished_at or utcnow()
    scan.summary = summary
    db.commit()
    return scan


def fail_scan(db: Session, scan: Scan, error: str) -> Scan:
    scan.status = "failed"
    scan.finished_at = utcnow()
    scan.error = error[:2000]
    db.commit()
    return scan


# =============================================================================
# Assets & services
# =============================================================================


def upsert_asset(db: Session, data: dict[str, Any], *, tags: Sequence[str] = ()) -> Asset:
    """Create or update an asset and its services from scanner output."""
    asset = db.scalars(select(Asset).where(Asset.ip == data["ip"])).first()
    now = utcnow()
    if asset is None:
        asset = Asset(ip=data["ip"], first_seen=now, tags=list(tags))
        db.add(asset)
    for key in ("hostname", "mac", "vendor", "os_guess"):
        if data.get(key):
            setattr(asset, key, data[key])
    asset.status = data.get("status", "up")
    asset.last_seen = now
    if tags:
        asset.tags = sorted(set(asset.tags or []) | set(tags))
    existing = {(s.port, s.protocol): s for s in asset.services}
    for svc in data.get("services", []):
        key = (int(svc["port"]), svc.get("protocol", "tcp"))
        record = existing.get(key)
        if record is None:
            record = Service(port=key[0], protocol=key[1])
            asset.services.append(record)
        for field in ("state", "name", "product", "version", "extrainfo", "cpe"):
            setattr(record, field, str(svc.get(field) or "")[:255])
        record.last_seen = now
    db.commit()
    db.refresh(asset)
    return asset


def update_asset_risk(db: Session) -> None:
    """Recompute each asset's risk score from its open findings."""
    open_by_asset: dict[str, list[Finding]] = defaultdict(list)
    for record in db.scalars(select(FindingRecord).where(FindingRecord.status == "open")):
        open_by_asset[record.asset].append(record_to_finding(record))
    for asset in db.scalars(select(Asset)):
        asset.risk_score = risk_score(open_by_asset.get(asset.ip, []))
    db.commit()


# =============================================================================
# Findings
# =============================================================================


def record_to_finding(record: FindingRecord) -> Finding:
    return Finding(
        finding_id=record.finding_id,
        title=record.title,
        severity=Severity.parse(record.severity),
        category=record.category,
        source=record.source,
        asset=record.asset,
        description=record.description,
        evidence=record.evidence,
        recommendation=record.recommendation,
        references=list(record.references or []),
        cve=record.cve,
        cvss=record.cvss,
        port=record.port,
        confidence=record.confidence,  # type: ignore[arg-type]
        detected_at=record.first_seen,
    )


def sync_findings(
    db: Session,
    *,
    findings: Iterable[Finding],
    source: str,
    assets_in_scope: Iterable[str],
    scan: Scan | None = None,
    is_demo: bool = False,
    seen_at: datetime | None = None,
) -> dict[str, int]:
    """Upsert findings by fingerprint and auto-resolve those no longer observed.

    Only findings from the same ``source`` and for assets covered by this run
    are auto-resolved, so a host audit never closes vulnerability findings.
    Returns counters ``{"new", "updated", "resolved", "reopened"}``.
    """
    now = seen_at or utcnow()
    stats = {"new": 0, "updated": 0, "resolved": 0, "reopened": 0}
    seen: set[str] = set()
    for finding in findings:
        fp = finding.fingerprint
        seen.add(fp)
        record = db.scalars(select(FindingRecord).where(FindingRecord.fingerprint == fp)).first()
        if record is None:
            record = FindingRecord(fingerprint=fp, first_seen=now, is_demo=is_demo)
            db.add(record)
            stats["new"] += 1
        elif record.status == "resolved":
            record.status = "open"
            record.resolved_at = None
            stats["reopened"] += 1
        else:
            stats["updated"] += 1
        record.scan_id = scan.id if scan else None
        record.finding_id = finding.finding_id
        record.title = finding.title[:300]
        record.severity = Severity.parse(finding.severity).value
        record.category = finding.category
        record.source = finding.source
        record.asset = finding.asset
        record.description = finding.description
        record.evidence = finding.evidence
        record.recommendation = finding.recommendation
        record.references = list(finding.references)
        record.cve = finding.cve
        record.cvss = finding.cvss
        record.port = finding.port
        record.confidence = finding.confidence
        record.last_seen = now
    scope = set(assets_in_scope)
    if scope:
        stale_query = select(FindingRecord).where(
            FindingRecord.source == source,
            FindingRecord.status == "open",
            FindingRecord.asset.in_(scope),
        )
        for record in db.scalars(stale_query):
            if record.fingerprint not in seen:
                record.status = "resolved"
                record.resolved_at = now
                stats["resolved"] += 1
    db.commit()
    update_asset_risk(db)
    return stats


def open_findings(db: Session, *, source: str | None = None) -> list[FindingRecord]:
    query = select(FindingRecord).where(FindingRecord.status == "open")
    if source:
        query = query.where(FindingRecord.source == source)
    return list(db.scalars(query))


# =============================================================================
# Compliance, traffic, alerts, reports
# =============================================================================


def save_compliance(
    db: Session, framework_reports: Iterable[dict[str, Any]], is_demo: bool = False, created_at: datetime | None = None
) -> list[ComplianceResult]:
    rows = []
    for report in framework_reports:
        row = ComplianceResult(
            framework=report["framework"],
            score=report["score"],
            passed=report["passed"],
            failed=report["failed"],
            partial=report.get("partial", 0),
            not_assessed=report.get("not_assessed", 0),
            details=report,
            is_demo=is_demo,
            created_at=created_at or utcnow(),
        )
        db.add(row)
        rows.append(row)
    db.commit()
    return rows


def latest_compliance(db: Session) -> list[ComplianceResult]:
    """Most recent result per framework."""
    latest_ids = select(func.max(ComplianceResult.id)).group_by(ComplianceResult.framework).scalar_subquery()
    return list(db.scalars(select(ComplianceResult).where(ComplianceResult.id.in_(latest_ids))))


def save_traffic_snapshot(
    db: Session, summary: dict[str, Any], source: str, is_demo: bool = False, created_at: datetime | None = None
) -> TrafficSnapshot:
    snapshot = TrafficSnapshot(
        source=source[:255],
        packets=int(summary.get("total_packets", 0)),
        bytes=int(summary.get("total_bytes", 0)),
        health_score=float(summary.get("health_score", 100.0)),
        summary=summary,
        is_demo=is_demo,
        created_at=created_at or utcnow(),
    )
    db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def alert_recently_raised(db: Session, fingerprint: str, cooldown_minutes: int) -> bool:
    if cooldown_minutes <= 0:
        return False
    since = utcnow() - timedelta(minutes=cooldown_minutes)
    query = select(Alert.id).where(Alert.fingerprint == fingerprint, Alert.created_at >= since).limit(1)
    return db.scalar(query) is not None


def save_report_record(
    db: Session, *, report_type: str, fmt: str, filename: str, sha256: str, size: int, created_by: str
) -> ReportRecord:
    record = ReportRecord(
        report_type=report_type, format=fmt, filename=filename, sha256=sha256, size_bytes=size, created_by=created_by
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


# =============================================================================
# Dashboard aggregates
# =============================================================================


def findings_trend(db: Session, days: int = 14) -> list[dict[str, Any]]:
    """Open-finding counts per severity for each of the last ``days`` days.

    A finding counts as open on day *d* if it was first seen on/before *d*
    and not resolved before the end of *d*.
    """
    today = utcnow().replace(hour=23, minute=59, second=59, microsecond=0)
    start = today - timedelta(days=days - 1)
    records = list(db.scalars(select(FindingRecord).where(FindingRecord.last_seen >= start - timedelta(days=90))))
    trend = []
    for offset in range(days):
        day_end = start + timedelta(days=offset)
        counts = {sev.value: 0 for sev in Severity.ordered()}
        for record in records:
            if record.first_seen <= day_end and (record.resolved_at is None or record.resolved_at > day_end):
                counts[record.severity] = counts.get(record.severity, 0) + 1
        trend.append({"date": day_end.date().isoformat(), **counts})
    return trend


def overview(db: Session) -> dict[str, Any]:
    """Aggregated metrics for the dashboard overview panel."""
    open_records = open_findings(db)
    findings = [record_to_finding(r) for r in open_records]
    by_source: dict[str, int] = defaultdict(int)
    for record in open_records:
        by_source[record.source] += 1
    latest_traffic = db.scalars(select(TrafficSnapshot).order_by(TrafficSnapshot.id.desc()).limit(1)).first()
    compliance = {row.framework: round(row.score, 1) for row in latest_compliance(db)}
    last_scans = db.scalars(select(Scan).order_by(Scan.id.desc()).limit(8))
    risk = risk_score(findings)
    return {
        "generated_at": utcnow().isoformat(),
        "risk_score": risk,
        "posture_score": round(100 - risk, 1),
        "assets": db.scalar(select(func.count(Asset.id))) or 0,
        "services": db.scalar(select(func.count(Service.id))) or 0,
        "open_findings": len(findings),
        "severity_counts": severity_counts(findings),
        "findings_by_source": dict(by_source),
        "open_alerts": db.scalar(select(func.count(Alert.id)).where(Alert.acknowledged.is_(False))) or 0,
        "compliance": compliance,
        "traffic": (
            {
                "health_score": latest_traffic.health_score,
                "packets": latest_traffic.packets,
                "bytes": latest_traffic.bytes,
                "captured_at": latest_traffic.created_at.isoformat(),
                "source": latest_traffic.source,
            }
            if latest_traffic
            else None
        ),
        "trend": findings_trend(db),
        "recent_scans": [
            {
                "id": s.id,
                "type": s.scan_type,
                "status": s.status,
                "target": s.target,
                "started_at": s.started_at.isoformat(),
                "requested_by": s.requested_by,
            }
            for s in last_scans
        ],
    }
