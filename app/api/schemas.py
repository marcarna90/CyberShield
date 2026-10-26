"""Request/response schemas with strict input validation (OWASP ASVS V5)."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.rbac import Role
from app.modules.reporting_engine.models import ReportFormat, ReportType

USERNAME_PATTERN = r"^[A-Za-z0-9_.\-]{3,64}$"
EMAIL_PATTERN = r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}$"
_INDICATOR_RE = re.compile(r"^[A-Za-z0-9.:\-]{2,253}$")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int


# ------------------------------------------------------------------ auth/users
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int
    role: str


class UserOut(ORMModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None


class MeOut(UserOut):
    permissions: list[str]


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(..., pattern=USERNAME_PATTERN)
    email: str = Field(..., pattern=EMAIL_PATTERN, max_length=255)
    password: str = Field(..., min_length=12, max_length=128)
    role: Role = Role.VIEWER


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(..., max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)


# ---------------------------------------------------------------- assets/scans
class ServiceOut(ORMModel):
    port: int
    protocol: str
    state: str
    name: str
    product: str
    version: str
    extrainfo: str
    cpe: str


class AssetOut(ORMModel):
    id: int
    ip: str
    hostname: str | None
    mac: str | None
    vendor: str | None
    os_guess: str | None
    status: str
    risk_score: float
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    services: list[ServiceOut]


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[str] = Field(..., min_length=1, max_length=64)
    profile: Literal["discovery", "quick", "standard", "full"] = "standard"
    authorization_confirmed: bool = Field(
        ..., description="Must be true: you confirm you are authorised to scan these targets."
    )

    @field_validator("targets")
    @classmethod
    def _targets(cls, value: list[str]) -> list[str]:
        cleaned = [t.strip() for t in value]
        if any(not t or len(t) > 255 for t in cleaned):
            raise ValueError("Each target must be 1-255 characters")
        return cleaned

    @field_validator("authorization_confirmed")
    @classmethod
    def _confirmed(cls, value: bool) -> bool:
        if not value:
            raise ValueError("Scanning requires explicit confirmation of authorisation")
        return value


class ScanOut(ORMModel):
    id: int
    scan_type: str
    target: str
    profile: str
    status: str
    requested_by: str
    started_at: datetime
    finished_at: datetime | None
    error: str | None
    summary: dict[str, Any]


class ScanBrief(ORMModel):
    id: int
    scan_type: str
    target: str
    profile: str
    status: str
    requested_by: str
    started_at: datetime
    finished_at: datetime | None
    error: str | None


# --------------------------------------------------------------------- findings
FindingStatus = Literal["open", "resolved", "accepted_risk", "false_positive"]


class FindingOut(ORMModel):
    id: int
    finding_id: str
    title: str
    severity: str
    category: str
    source: str
    asset: str
    description: str
    evidence: str
    recommendation: str
    references: list[str]
    cve: str | None
    cvss: float | None
    port: int | None
    confidence: str
    status: str
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None


class FindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    comment: str | None = Field(default=None, max_length=500)


# ----------------------------------------------------------------------- alerts
class AlertOut(ORMModel):
    id: int
    created_at: datetime
    severity: str
    trigger: str
    title: str
    message: str
    source: str
    asset: str | None
    channels: list[str]
    acknowledged: bool
    acknowledged_by: str | None
    acknowledged_at: datetime | None


# ---------------------------------------------------------------------- reports
class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_type: ReportType = ReportType.EXECUTIVE
    formats: list[ReportFormat] = Field(default_factory=lambda: [ReportFormat.PDF], min_length=1, max_length=3)


class ReportOut(ORMModel):
    id: int
    created_at: datetime
    report_type: str
    format: str
    filename: str
    sha256: str
    size_bytes: int
    created_by: str


# ---------------------------------------------------------------- traffic/intel
class TrafficSnapshotOut(ORMModel):
    id: int
    created_at: datetime
    source: str
    packets: int
    bytes: int
    health_score: float


class TrafficSnapshotDetail(TrafficSnapshotOut):
    summary: dict[str, Any]


class IndicatorQuery(BaseModel):
    indicator: str

    @field_validator("indicator")
    @classmethod
    def _indicator(cls, value: str) -> str:
        if not _INDICATOR_RE.match(value):
            raise ValueError("Indicator must be an IP address or domain name")
        return value


# ------------------------------------------------------------------ audit trail
class AuditEventOut(ORMModel):
    id: int
    timestamp: datetime
    actor: str
    action: str
    resource: str
    outcome: str
    ip: str | None
    details: dict[str, Any]
    hash: str


class MessageOut(BaseModel):
    detail: str
