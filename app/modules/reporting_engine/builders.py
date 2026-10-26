"""Assemble :class:`ReportData` for the four report types from module outputs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from app.core.models import Finding, Severity, risk_score, severity_counts, sort_findings, utcnow
from app.modules.reporting_engine.models import ReportData, ReportType, TableSection

PRIORITIES = [
    (Severity.CRITICAL, "P1", "Immediate", "Within 24-72 hours"),
    (Severity.HIGH, "P2", "Urgent", "Within 7 days"),
    (Severity.MEDIUM, "P3", "Planned", "Within 30 days"),
    (Severity.LOW, "P4", "Routine", "Within 90 days"),
    (Severity.INFO, "P5", "Track", "Next maintenance window"),
]
TITLES = {
    ReportType.EXECUTIVE: "Executive Security Report",
    ReportType.TECHNICAL: "Technical Security Report",
    ReportType.VULNERABILITY: "Vulnerability Assessment Report",
    ReportType.COMPLIANCE: "Compliance Assessment Report",
}


def severity_matrix(findings: Iterable[Finding]) -> dict[str, dict[str, int]]:
    """``{category: {severity: count}}`` with every severity present."""
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: {s.value: 0 for s in Severity.ordered()})
    for finding in findings:
        matrix[finding.category][Severity.parse(finding.severity).value] += 1
    return dict(sorted(matrix.items()))


def remediation_priorities(findings: Sequence[Finding], max_items: int = 8) -> list[dict[str, Any]]:
    priorities = []
    for severity, code, label, sla in PRIORITIES:
        matching = [f for f in findings if f.severity is severity]
        if not matching:
            continue
        priorities.append(
            {
                "priority": code,
                "label": label,
                "severity": severity.value,
                "sla": sla,
                "count": len(matching),
                "items": [f"{f.title} ({f.asset})" for f in matching[:max_items]],
            }
        )
    return priorities


def top_recommendations(findings: Sequence[Finding], limit: int = 12) -> list[str]:
    seen: dict[str, None] = {}
    for finding in findings:
        if finding.recommendation and finding.recommendation not in seen:
            seen[finding.recommendation] = None
        if len(seen) >= limit:
            break
    return list(seen)


def _compliance_summaries(compliance: dict[str, Any] | None, executive: bool = False) -> list[dict[str, Any]]:
    """Framework summaries; the executive view keeps only the top priority-1 gaps."""
    if not compliance:
        return []

    def gaps(fw: dict[str, Any]) -> list[dict[str, Any]]:
        all_gaps = fw.get("gaps", [])
        return [g for g in all_gaps if g.get("priority") == "P1"][:5] if executive else all_gaps

    return [
        {
            "framework": fw["framework"],
            "name": fw["name"],
            "score": fw["score"],
            "passed": fw["passed"],
            "partial": fw["partial"],
            "failed": fw["failed"],
            "not_assessed": fw["not_assessed"],
            "gaps": gaps(fw),
            "controls": fw.get("controls", []),
        }
        for fw in compliance.get("frameworks", [])
    ]


def build_report(
    report_type: ReportType,
    findings: Iterable[Finding],
    *,
    organization: str,
    generated_by: str,
    compliance: dict[str, Any] | None = None,
    assets: Sequence[dict[str, Any]] = (),
    host_audit: dict[str, Any] | None = None,
    traffic: dict[str, Any] | None = None,
    max_findings: int = 500,
) -> ReportData:
    """Build the data model for one report type.

    ``compliance``, ``host_audit`` and ``traffic`` are the JSON-serialised
    outputs of the corresponding modules (as stored in the database).
    """
    all_findings = sort_findings(findings)
    if report_type is ReportType.VULNERABILITY:
        scoped = [f for f in all_findings if f.source == "vulnerability_analyzer"]
    else:
        scoped = all_findings
    counts = severity_counts(scoped)
    risk = risk_score(scoped)
    comp = _compliance_summaries(compliance, executive=report_type is ReportType.EXECUTIVE)
    overall_compliance = compliance.get("overall_score") if compliance else None

    summary: dict[str, Any] = {
        "Risk score": f"{risk:.0f}/100",
        "Security posture": f"{100 - risk:.0f}/100",
        "Open findings": len(scoped),
        "Critical": counts["critical"],
        "High": counts["high"],
    }
    if assets:
        summary["Assets"] = len(assets)
    if overall_compliance is not None:
        summary["Compliance"] = f"{overall_compliance:.0f}%"
    if traffic:
        summary["Network health"] = f"{traffic.get('health_score', 100):.0f}/100"

    narrative = _narrative(report_type, scoped, counts, risk, compliance, traffic)
    sections = _sections(report_type, assets, host_audit, traffic)
    displayed = scoped
    if report_type is ReportType.EXECUTIVE:
        displayed = [f for f in scoped if f.severity in (Severity.CRITICAL, Severity.HIGH)][:15]
    recommendations = top_recommendations(scoped)
    if report_type is ReportType.COMPLIANCE and compliance:
        recommendations = list(compliance.get("recommendations", [])) or recommendations
    return ReportData(
        report_type=report_type,
        title=TITLES[report_type],
        organization=organization,
        generated_at=utcnow(),
        generated_by=generated_by,
        scope=_scope(assets, host_audit, traffic),
        summary=summary,
        narrative=narrative,
        findings=displayed[:max_findings],
        findings_total=len(scoped),
        severity_counts=counts,
        severity_matrix=severity_matrix(scoped),
        recommendations=recommendations,
        remediation_priorities=remediation_priorities(scoped),
        compliance=comp if report_type in (ReportType.COMPLIANCE, ReportType.EXECUTIVE) else [],
        risk_matrix=(compliance or {}).get("risk_matrix") if report_type is not ReportType.VULNERABILITY else None,
        sections=sections,
    )


def _scope(assets: Sequence[dict[str, Any]], host_audit: dict[str, Any] | None, traffic: dict[str, Any] | None) -> str:
    parts = []
    if assets:
        parts.append(f"{len(assets)} network asset(s)")
    if host_audit:
        parts.append(f"host audit of {host_audit.get('hostname', 'local host')}")
    if traffic:
        parts.append(f"traffic capture '{traffic.get('source', 'n/a')}'")
    return ", ".join(parts) or "Platform-wide open findings"


def _narrative(
    report_type: ReportType,
    findings: Sequence[Finding],
    counts: dict[str, int],
    risk: float,
    compliance: dict[str, Any] | None,
    traffic: dict[str, Any] | None,
) -> str:
    level = "critical" if risk >= 75 else "high" if risk >= 50 else "moderate" if risk >= 25 else "low"
    text = (
        f"The assessment identified {len(findings)} open finding(s): {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium and {counts['low']} low. The aggregated risk "
        f"score is {risk:.0f}/100, which corresponds to a {level} level of risk."
    )
    if counts["critical"]:
        text += " Critical findings must be remediated immediately (P1, 24-72 hours)."
    if compliance and report_type in (ReportType.EXECUTIVE, ReportType.COMPLIANCE):
        text += " " + compliance.get("executive_summary", "")
    if traffic and report_type is not ReportType.VULNERABILITY:
        text += (
            f" Network health score of the latest capture is {traffic.get('health_score', 100):.0f}/100 "
            f"with {len(traffic.get('anomalies', []))} anomaly(ies)."
        )
    return text.strip()


def _sections(
    report_type: ReportType,
    assets: Sequence[dict[str, Any]],
    host_audit: dict[str, Any] | None,
    traffic: dict[str, Any] | None,
) -> list[TableSection]:
    sections: list[TableSection] = []
    if assets and report_type in (ReportType.VULNERABILITY, ReportType.TECHNICAL):
        sections.append(
            TableSection(
                title="Asset inventory",
                columns=["IP", "Hostname", "Open services", "Risk score"],
                rows=[
                    [
                        a.get("ip"),
                        a.get("hostname") or "-",
                        ", ".join(
                            f"{s['port']}/{s.get('protocol', 'tcp')} {s.get('product') or s.get('name', '')} "
                            f"{s.get('version', '')}".strip()
                            for s in a.get("services", [])
                        )[:300]
                        or "-",
                        f"{a.get('risk_score', 0):.0f}",
                    ]
                    for a in assets
                ],
            )
        )
    if host_audit and report_type is ReportType.TECHNICAL:
        sections.append(
            TableSection(
                title=f"Host audit checks - {host_audit.get('hostname', '')} (hardening score "
                f"{host_audit.get('score', 0):.0f}/100)",
                columns=["Check", "Title", "Status", "Severity", "Evidence"],
                rows=[
                    [c["check_id"], c["title"], c["status"].upper(), c["severity"], (c.get("evidence") or "")[:220]]
                    for c in host_audit.get("checks", [])
                ],
            )
        )
    if traffic and report_type is ReportType.TECHNICAL:
        rows = [
            [proto, count, traffic.get("protocol_bytes", {}).get(proto, 0)]
            for proto, count in traffic.get("protocols", {}).items()
        ]
        sections.append(
            TableSection(
                title=f"Traffic protocol mix - {traffic.get('source', '')}",
                columns=["Protocol", "Packets", "Bytes"],
                rows=rows,
                note=f"{traffic.get('total_packets', 0)} packets / {traffic.get('total_bytes', 0)} bytes analysed; "
                f"health score {traffic.get('health_score', 100):.0f}/100.",
            )
        )
        sections.append(
            TableSection(
                title="Top talkers",
                columns=["Host", "Bytes", "Packets", "Internal"],
                rows=[
                    [t["ip"], t["bytes"], t["packets"], "yes" if t.get("internal") else "no"]
                    for t in traffic.get("top_talkers", [])
                ],
            )
        )
    return sections
