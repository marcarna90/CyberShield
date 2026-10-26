"""Compliance scoring, gap analysis and risk matrix (CIS v8, NIST CSF 2.0, ISO/IEC 27001:2022)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from app.core.models import CheckStatus, Finding, Severity, utcnow

CONTROLS_FILE = Path(__file__).parent / "data" / "controls.yaml"
ControlStatus = Literal["pass", "partial", "fail", "not_assessed"]

_STATUS_VALUE = {"pass": 1.0, "partial": 0.5, "fail": 0.0}  # status weights, not secrets  # nosec B105
INSECURE_EXPOSURES = {"EXP-TELNET", "EXP-FTP", "EXP-RSERVICES", "EXP-LDAP", "EXP-HTTP-NOTLS"}
LIKELIHOOD_LABELS = ["Rare", "Unlikely", "Possible", "Likely", "Almost certain"]
IMPACT_LABELS = ["Negligible", "Minor", "Moderate", "Major", "Severe"]


class Control(BaseModel):
    id: str
    framework: str
    title: str
    checks: list[str]
    weight: int = Field(1, ge=1, le=5)
    recommendation: str = ""


class ControlResult(BaseModel):
    control_id: str
    framework: str
    title: str
    status: ControlStatus
    weight: int
    evidence: dict[str, str]
    recommendation: str


class FrameworkReport(BaseModel):
    framework: str
    name: str
    version: str
    score: float
    passed: int
    partial: int
    failed: int
    not_assessed: int
    controls: list[ControlResult]
    gaps: list[dict[str, Any]]


class ComplianceReport(BaseModel):
    generated_at: datetime
    overall_score: float
    frameworks: list[FrameworkReport]
    executive_summary: str
    risk_matrix: dict[str, Any]
    recommendations: list[str]


@lru_cache(maxsize=4)
def load_controls(path: Path = CONTROLS_FILE) -> tuple[dict[str, dict[str, str]], tuple[Control, ...]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    frameworks = data["frameworks"]
    controls = tuple(Control.model_validate(item) for item in data["controls"])
    unknown = {c.framework for c in controls} - set(frameworks)
    if unknown:
        raise ValueError(f"Controls reference undefined frameworks: {sorted(unknown)}")
    return frameworks, controls


def derive_signals(
    findings: Iterable[Finding],
    *,
    last_vulnerability_scan: datetime | None,
    last_traffic_capture: datetime | None,
    now: datetime | None = None,
) -> dict[str, CheckStatus]:
    """Turn platform-wide state into pseudo-checks used by the control mapping."""
    now = now or utcnow()
    findings = list(findings)
    signals: dict[str, CheckStatus] = {}
    vulns = [f for f in findings if f.cve]
    if last_vulnerability_scan is None:
        signals.update({"VULN-001": CheckStatus.UNKNOWN, "VULN-002": CheckStatus.UNKNOWN, "VULN-003": CheckStatus.FAIL})
    else:
        age = now - last_vulnerability_scan
        signals["VULN-003"] = (
            CheckStatus.PASS
            if age <= timedelta(days=30)
            else CheckStatus.WARN
            if age <= timedelta(days=90)
            else CheckStatus.FAIL
        )
        signals["VULN-001"] = (
            CheckStatus.FAIL if any(f.severity is Severity.CRITICAL for f in vulns) else CheckStatus.PASS
        )
        signals["VULN-002"] = CheckStatus.FAIL if any(f.severity is Severity.HIGH for f in vulns) else CheckStatus.PASS
    if last_traffic_capture is None:
        signals["NET-010"] = CheckStatus.FAIL
        signals["NET-011"] = CheckStatus.UNKNOWN
    else:
        signals["NET-010"] = CheckStatus.PASS if now - last_traffic_capture <= timedelta(days=7) else CheckStatus.WARN
        signals["NET-011"] = (
            CheckStatus.FAIL if any(f.finding_id.startswith("TRF-IOC") for f in findings) else CheckStatus.PASS
        )
    insecure = [f for f in findings if f.finding_id in INSECURE_EXPOSURES]
    weak_transit = [f for f in findings if f.finding_id in ("TRF-LEGACY-TLS", "TRF-CLEARTEXT-HTTP")]
    if insecure:
        signals["NET-012"] = CheckStatus.FAIL
    elif weak_transit:
        signals["NET-012"] = CheckStatus.WARN
    elif last_vulnerability_scan is not None or last_traffic_capture is not None:
        signals["NET-012"] = CheckStatus.PASS
    else:
        signals["NET-012"] = CheckStatus.UNKNOWN
    return signals


def _control_status(statuses: list[CheckStatus]) -> ControlStatus:
    assessed = [s for s in statuses if s in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.WARN)]
    if not assessed:
        return "not_assessed"
    if CheckStatus.FAIL in assessed:
        return "fail"
    if CheckStatus.WARN in assessed:
        return "partial"
    return "pass"


def _likelihood(finding: Finding) -> int:
    rank = Severity.parse(finding.severity).rank  # 0..4
    if finding.finding_id.startswith("TRF-IOC"):
        return 5  # already observed in the environment
    if finding.cve and "public exploit" in finding.description.lower():
        return min(5, rank + 2)
    if finding.source == "system_auditor":
        return max(1, min(4, rank + 1)) if rank < 4 else 4
    return max(1, rank + 1)


def build_risk_matrix(findings: Iterable[Finding]) -> dict[str, Any]:
    """5x5 likelihood x impact matrix with counts and the highest-risk items."""
    cells = [[0] * 5 for _ in range(5)]  # cells[likelihood-1][impact-1]
    scored = []
    for finding in findings:
        impact = Severity.parse(finding.severity).rank + 1
        likelihood = _likelihood(finding)
        cells[likelihood - 1][impact - 1] += 1
        scored.append((likelihood * impact, likelihood, impact, finding))
    scored.sort(key=lambda item: (-item[0], item[3].finding_id))
    return {
        "likelihood_labels": LIKELIHOOD_LABELS,
        "impact_labels": IMPACT_LABELS,
        "cells": cells,
        "high_risk_count": sum(1 for s in scored if s[0] >= 15),
        "top_risks": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "asset": f.asset,
                "likelihood": lk,
                "impact": im,
                "score": score,
            }
            for score, lk, im, f in scored[:10]
        ],
    }


class ComplianceChecker:
    """Evaluate check results against the control catalogue."""

    def __init__(self, controls_path: Path = CONTROLS_FILE) -> None:
        self.frameworks, self.controls = load_controls(controls_path)

    def evaluate(
        self, check_statuses: Mapping[str, CheckStatus | str], findings: Iterable[Finding] = ()
    ) -> ComplianceReport:
        statuses = {k: CheckStatus(v) for k, v in check_statuses.items()}
        findings = list(findings)
        reports: list[FrameworkReport] = []
        for key, meta in self.frameworks.items():
            results: list[ControlResult] = []
            earned = possible = 0.0
            for control in (c for c in self.controls if c.framework == key):
                evidence = {cid: statuses.get(cid, CheckStatus.UNKNOWN).value for cid in control.checks}
                status = _control_status([CheckStatus(v) for v in evidence.values()])
                if status != "not_assessed":
                    possible += control.weight
                    earned += control.weight * _STATUS_VALUE[status]
                results.append(
                    ControlResult(
                        control_id=control.id,
                        framework=key,
                        title=control.title,
                        status=status,
                        weight=control.weight,
                        evidence=evidence,
                        recommendation=control.recommendation,
                    )
                )
            gaps = [
                {
                    "control_id": r.control_id,
                    "title": r.title,
                    "status": r.status,
                    "priority": "P1"
                    if r.status == "fail" and r.weight >= 3
                    else "P2"
                    if r.status == "fail" or r.weight >= 3
                    else "P3",
                    "failing_checks": [cid for cid, st in r.evidence.items() if st in ("fail", "warn")],
                    "recommendation": r.recommendation,
                }
                for r in results
                if r.status in ("fail", "partial")
            ]
            gaps.sort(key=lambda g: (g["priority"], g["control_id"]))
            reports.append(
                FrameworkReport(
                    framework=key,
                    name=meta["name"],
                    version=str(meta["version"]),
                    score=round(100.0 * earned / possible, 1) if possible else 0.0,
                    passed=sum(r.status == "pass" for r in results),
                    partial=sum(r.status == "partial" for r in results),
                    failed=sum(r.status == "fail" for r in results),
                    not_assessed=sum(r.status == "not_assessed" for r in results),
                    controls=results,
                    gaps=gaps,
                )
            )
        assessed = [r for r in reports if r.passed + r.partial + r.failed > 0]
        overall = round(sum(r.score for r in assessed) / len(assessed), 1) if assessed else 0.0
        matrix = build_risk_matrix(findings)
        recommendations = list(
            dict.fromkeys(g["recommendation"] for r in reports for g in r.gaps if g["priority"] == "P1")
        ) + list(dict.fromkeys(g["recommendation"] for r in reports for g in r.gaps if g["priority"] == "P2"))
        return ComplianceReport(
            generated_at=utcnow(),
            overall_score=overall,
            frameworks=reports,
            executive_summary=self._summary(overall, reports, matrix),
            risk_matrix=matrix,
            recommendations=list(dict.fromkeys(recommendations))[:12],
        )

    @staticmethod
    def _summary(overall: float, reports: list[FrameworkReport], matrix: dict[str, Any]) -> str:
        level = "strong" if overall >= 85 else "moderate" if overall >= 70 else "weak" if overall >= 50 else "critical"
        parts = [f"Overall technical compliance is {overall:.0f}% ({level} posture)."]
        for report in reports:
            parts.append(
                f"{report.name}: {report.score:.0f}% ({report.passed} passed, {report.partial} partial, "
                f"{report.failed} failed, {report.not_assessed} not assessed)."
            )
        p1 = [g for r in reports for g in r.gaps if g["priority"] == "P1"]
        if p1:
            parts.append(
                f"{len(p1)} priority-1 gap(s) require immediate attention, notably: "
                + "; ".join(f"{g['control_id']} {g['title']}" for g in p1[:3])
                + "."
            )
        if matrix["high_risk_count"]:
            parts.append(f"{matrix['high_risk_count']} finding(s) sit in the high-risk zone of the risk matrix.")
        return " ".join(parts)
