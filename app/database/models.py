"""ORM models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.core.models import utcnow


class UTCDateTime(TypeDecorator[datetime]):
    """Store naive UTC, always return timezone-aware UTC (portable across SQLite/PG)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255))
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class AuditEvent(Base):
    """Append-only, hash-chained audit trail."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource: Mapped[str] = mapped_column(String(255), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os_guess: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="up")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    services: Mapped[list[Service]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", order_by="Service.port"
    )


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("asset_id", "port", "protocol", name="uq_service_port"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="open")
    name: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(128), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    extrainfo: Mapped[str] = mapped_column(String(255), default="")
    cpe: Mapped[str] = mapped_column(String(255), default="")
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="services")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_type: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(1024), default="")
    profile: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    requested_by: Mapped[str] = mapped_column(String(64), default="system")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)


class FindingRecord(Base):
    """Current state of each unique finding (upserted by fingerprint)."""

    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_status_severity", "status", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    finding_id: Mapped[str] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(64), index=True)
    asset: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    cve: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[str] = mapped_column(String(8), default="high")
    status: Mapped[str] = mapped_column(String(16), default="open")
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    trigger: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    message: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="")
    asset: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    channels: Mapped[list[str]] = mapped_column(JSON, default=list)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)


class ReportRecord(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    report_type: Mapped[str] = mapped_column(String(32))
    format: Mapped[str] = mapped_column(String(8))
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[str] = mapped_column(String(64))


class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    framework: Mapped[str] = mapped_column(String(64), index=True)
    score: Mapped[float] = mapped_column(Float)
    passed: Mapped[int] = mapped_column(Integer)
    failed: Mapped[int] = mapped_column(Integer)
    partial: Mapped[int] = mapped_column(Integer, default=0)
    not_assessed: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)


class TrafficSnapshot(Base):
    __tablename__ = "traffic_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(255))
    packets: Mapped[int] = mapped_column(Integer)
    bytes: Mapped[int] = mapped_column(Integer)
    health_score: Mapped[float] = mapped_column(Float)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False)
