"""Report data model shared by the HTML, PDF and JSON renderers."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.core.models import Finding


class ReportType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"


class ReportFormat(StrEnum):
    PDF = "pdf"
    HTML = "html"
    JSON = "json"


class TableSection(BaseModel):
    """Generic tabular section (asset inventory, audit checks, traffic stats...)."""

    title: str
    columns: list[str]
    rows: list[list[Any]]
    note: str = ""


class ReportData(BaseModel):
    report_type: ReportType
    title: str
    organization: str
    generated_at: datetime
    generated_by: str
    scope: str
    classification: str = "CONFIDENTIAL"
    summary: dict[str, Any] = Field(default_factory=dict)
    narrative: str = ""
    findings: list[Finding] = Field(default_factory=list)
    findings_total: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    severity_matrix: dict[str, dict[str, int]] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    remediation_priorities: list[dict[str, Any]] = Field(default_factory=list)
    compliance: list[dict[str, Any]] = Field(default_factory=list)
    risk_matrix: dict[str, Any] | None = None
    sections: list[TableSection] = Field(default_factory=list)


class GeneratedReport(BaseModel):
    report_type: ReportType
    format: ReportFormat
    path: str
    filename: str
    sha256: str
    size_bytes: int
