"""Domain models shared by every module (severity, findings, check results)."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


class Severity(StrEnum):
    """Five-level severity scale aligned with CVSS v3 qualitative ratings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

    @property
    def rank(self) -> int:
        """Numeric rank: 4 = critical ... 0 = informational."""
        return _RANK[self]

    @property
    def weight(self) -> int:
        """Weight used in risk scoring (non-linear on purpose)."""
        return _WEIGHT[self]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Map a CVSS v3 base score to a qualitative severity."""
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        """Case-insensitive parsing with common aliases (``info``, ``moderate``)."""
        if isinstance(value, Severity):
            return value
        normalized = str(value).strip().lower()
        aliases = {"info": "informational", "moderate": "medium", "none": "informational"}
        normalized = aliases.get(normalized, normalized)
        try:
            return cls(normalized)
        except ValueError as exc:
            raise ValueError(f"Unknown severity: {value!r}") from exc

    @classmethod
    def ordered(cls) -> list[Severity]:
        """Severities from most to least severe."""
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO]


_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class CheckStatus(StrEnum):
    """Outcome of an individual configuration check."""

    PASS = "pass"  # noqa: S105  # enum value, not a password  # nosec B105
    FAIL = "fail"
    WARN = "warn"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Finding(BaseModel):
    """A security issue detected by any module."""

    finding_id: str = Field(..., max_length=128, description="Stable identifier, e.g. SSH-001 or CVE-2024-6387")
    title: str = Field(..., max_length=300)
    severity: Severity
    category: str = Field(..., max_length=64)
    source: str = Field(..., max_length=64, description="Module that produced the finding")
    asset: str = Field("localhost", max_length=255)
    description: str = ""
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    cve: str | None = None
    cvss: float | None = Field(default=None, ge=0, le=10)
    port: int | None = Field(default=None, ge=0, le=65535)
    confidence: Literal["high", "medium", "low"] = "high"
    detected_at: datetime = Field(default_factory=utcnow)

    @property
    def fingerprint(self) -> str:
        """Stable de-duplication key (asset + id + port)."""
        raw = f"{self.source}|{self.asset}|{self.finding_id}|{self.port or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class CheckResult(BaseModel):
    """Result of a single configuration check (host audit)."""

    check_id: str
    title: str
    category: str
    status: CheckStatus
    severity: Severity
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)

    @property
    def is_issue(self) -> bool:
        return self.status in (CheckStatus.FAIL, CheckStatus.WARN)

    def to_finding(self, asset: str, source: str = "system_auditor") -> Finding | None:
        """Convert a failed/warning check to a :class:`Finding` (``None`` otherwise)."""
        if not self.is_issue:
            return None
        severity = self.severity
        if self.status is CheckStatus.WARN and severity.rank > Severity.LOW.rank:
            # A warning is a weaker signal than a failure: downgrade one level.
            severity = Severity.ordered()[Severity.ordered().index(severity) + 1]
        return Finding(
            finding_id=self.check_id,
            title=self.title,
            severity=severity,
            category=self.category,
            source=source,
            asset=asset,
            description=self.title,
            evidence=self.evidence,
            recommendation=self.recommendation,
            references=self.references,
        )


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings per severity (all levels present, most severe first)."""
    counts = {sev.value: 0 for sev in Severity.ordered()}
    for finding in findings:
        counts[Severity.parse(finding.severity).value] += 1
    return counts


def risk_score(findings: Iterable[Finding]) -> float:
    """Saturating risk score in [0, 100] (higher = riskier).

    ``100 * (1 - exp(-sum(weights) / 50))``: one critical finding gives ~18,
    five give ~63 and the curve never exceeds 100.
    """
    total = sum(Severity.parse(f.severity).weight for f in findings)
    return round(100.0 * (1.0 - math.exp(-total / 50.0)), 1)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first, then by CVSS (desc), then by id for determinism."""
    return sorted(
        findings,
        key=lambda f: (-Severity.parse(f.severity).rank, -(f.cvss or 0.0), f.asset, f.finding_id),
    )
