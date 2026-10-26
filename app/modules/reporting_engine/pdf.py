"""PDF rendering with ReportLab (pure Python, no system dependencies)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape  # escaping output only, never parsing XML  # nosec B406

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app import __version__
from app.core.models import Severity
from app.modules.reporting_engine.models import ReportData

BRAND = colors.HexColor("#0b3d91")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#b91c1c"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "informational": colors.HexColor("#64748b"),
}
STATUS_COLORS = {
    "pass": colors.HexColor("#15803d"),
    "fail": colors.HexColor("#b91c1c"),
    "partial": colors.HexColor("#ca8a04"),
    "warn": colors.HexColor("#ca8a04"),
}
GRID = colors.HexColor("#e2e8f0")
PANEL = colors.HexColor("#f1f5f9")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], textColor=BRAND, fontSize=24, leading=28, spaceAfter=6),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], textColor=BRAND, fontSize=15, spaceBefore=14),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=12, spaceBefore=10),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=9.5, leading=13),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontSize=8, leading=10.5),
        "cell": ParagraphStyle("c", parent=base["BodyText"], fontSize=8, leading=10),
        "center": ParagraphStyle("ce", parent=base["BodyText"], fontSize=9, alignment=TA_CENTER),
        "badge": ParagraphStyle(
            "bd",
            parent=base["BodyText"],
            fontSize=7.5,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
    }


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    """Paragraph with XML-escaped content (ReportLab interprets markup)."""
    return Paragraph(escape(str(text if text is not None else "")), style)


def _table(
    rows: list[list[Any]], widths: list[float], header: bool = True, extra: list[tuple[Any, ...]] | None = None
) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), PANEL), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    table.setStyle(TableStyle(style + (extra or [])))
    return table


def _page_decorations(report: ReportData):
    def draw(canvas, doc) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setFillColor(BRAND)
        canvas.rect(0, height - 8 * mm, width, 8 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(15 * mm, height - 5.5 * mm, "CYBERSHIELD ENTERPRISE SECURITY PLATFORM")
        canvas.drawRightString(width - 15 * mm, height - 5.5 * mm, report.classification)
        canvas.setFillColor(colors.HexColor("#475569"))
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(15 * mm, 10 * mm, f"{report.title} - {report.organization}")
        canvas.drawRightString(width - 15 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    return draw


def render_pdf(report: ReportData, path: Path) -> None:
    s = _styles()
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=report.title,
        author="CyberShield",
        subject=report.scope,
    )
    usable = A4[0] - 30 * mm
    story: list[Any] = []

    # ---------------------------------------------------------------- cover
    story += [
        Spacer(1, 20 * mm),
        _p(report.title, s["title"]),
        _p(report.organization, s["h2"]),
        _p(f"Generated {report.generated_at:%Y-%m-%d %H:%M} UTC by {report.generated_by}", s["body"]),
        _p(f"Scope: {report.scope}", s["body"]),
        Spacer(1, 8 * mm),
    ]
    cards = list(report.summary.items())
    card_rows = [[_p(k.upper(), s["small"]) for k, _ in cards], [_p(v, s["h2"]) for _, v in cards]]
    if cards:
        story.append(
            _table(
                card_rows,
                [usable / len(cards)] * len(cards),
                header=False,
                extra=[("BACKGROUND", (0, 0), (-1, -1), PANEL)],
            )
        )
    story += [Spacer(1, 6 * mm), _p("Summary", s["h1"]), _p(report.narrative, s["body"])]

    # ------------------------------------------------------ severity matrix
    severities = [sev.value for sev in Severity.ordered()]
    story.append(_p("Severity matrix", s["h1"]))
    header = ["Category", *[sev.capitalize() for sev in severities], "Total"]
    rows: list[list[Any]] = [header]
    for category, counts in report.severity_matrix.items():
        rows.append([category, *[counts.get(sev, 0) or "" for sev in severities], sum(counts.values())])
    rows.append(["Total", *[report.severity_counts.get(sev, 0) for sev in severities], report.findings_total])
    widths = [usable * 0.28] + [usable * 0.12] * 6
    extra = [("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"), ("ALIGN", (1, 0), (-1, -1), "CENTER")]
    for idx, sev in enumerate(severities, start=1):
        extra.append(("TEXTCOLOR", (idx, 0), (idx, 0), SEVERITY_COLORS[sev]))
    story.append(_table(rows, widths, extra=extra))

    if report.risk_matrix:
        matrix = report.risk_matrix
        rows = [["Likelihood \\ Impact", *matrix["impact_labels"]]]
        heat = []
        for row_idx, li in enumerate(range(4, -1, -1), start=1):
            rows.append([matrix["likelihood_labels"][li], *[matrix["cells"][li][im] or "" for im in range(5)]])
            for im in range(5):
                score = (li + 1) * (im + 1)
                fill = "#fecaca" if score >= 15 else "#fed7aa" if score >= 8 else "#fef9c3" if score >= 4 else "#dcfce7"
                heat.append(("BACKGROUND", (im + 1, row_idx), (im + 1, row_idx), colors.HexColor(fill)))
        heat_table = _table(
            rows, [usable * 0.25] + [usable * 0.15] * 5, extra=[*heat, ("ALIGN", (1, 1), (-1, -1), "CENTER")]
        )
        story.append(KeepTogether([_p("Risk matrix (likelihood x impact)", s["h2"]), heat_table]))

    # ------------------------------------------------------------ compliance
    if report.compliance:
        story.append(_p("Compliance", s["h1"]))
        rows = [["Framework", "Score", "Passed", "Partial", "Failed", "Not assessed"]]
        for fw in report.compliance:
            rows.append(
                [
                    _p(fw["name"], s["cell"]),
                    f"{fw['score']:.0f}%",
                    fw["passed"],
                    fw["partial"],
                    fw["failed"],
                    fw["not_assessed"],
                ]
            )
        story.append(_table(rows, [usable * 0.4] + [usable * 0.12] * 5))
        for fw in report.compliance:
            if not fw["gaps"]:
                continue
            story.append(_p(f"Gap analysis - {fw['name']}", s["h2"]))
            rows = [["Priority", "Control", "Status", "Recommendation"]]
            extra = []
            for i, gap in enumerate(fw["gaps"], start=1):
                rows.append(
                    [
                        gap["priority"],
                        _p(f"{gap['control_id']} {gap['title']}", s["cell"]),
                        gap["status"].upper(),
                        _p(gap["recommendation"], s["cell"]),
                    ]
                )
                extra.append(("TEXTCOLOR", (2, i), (2, i), STATUS_COLORS.get(gap["status"], colors.black)))
            story.append(_table(rows, [usable * 0.1, usable * 0.35, usable * 0.12, usable * 0.43], extra=extra))

    # -------------------------------------------------------------- findings
    story.append(PageBreak())
    title = "Findings"
    if len(report.findings) < report.findings_total:
        title += f" (top {len(report.findings)} of {report.findings_total})"
    story.append(_p(title, s["h1"]))
    if not report.findings:
        story.append(_p("No open findings in scope.", s["body"]))
    for finding in report.findings:
        badge = Table([[_p(finding.severity.value.upper(), s["badge"])]], colWidths=[24 * mm])
        badge.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS[finding.severity.value]),
                    ("TOPPADDING", (0, 0), (-1, -1), 1),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        ident = finding.finding_id + (f" | CVSS {finding.cvss:.1f}" if finding.cvss is not None else "")
        location = finding.asset + (f":{finding.port}" if finding.port is not None else "")
        details = [
            ["Identifier", _p(f"{ident} | confidence {finding.confidence}", s["cell"])],
            ["Asset", _p(f"{location} | {finding.category} | {finding.source}", s["cell"])],
        ]
        if finding.description and finding.description != finding.title:
            details.append(["Description", _p(finding.description, s["cell"])])
        if finding.evidence:
            details.append(["Evidence", _p(finding.evidence, s["cell"])])
        details.append(["Recommendation", _p(finding.recommendation, s["cell"])])
        if finding.references:
            details.append(["References", _p(" | ".join(finding.references[:4]), s["cell"])])
        head = Table([[badge, _p(finding.title, s["h2"])]], colWidths=[28 * mm, usable - 28 * mm])
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        body = _table(
            details,
            [28 * mm, usable - 28 * mm],
            header=False,
            extra=[("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#475569"))],
        )
        story.append(KeepTogether([head, body, Spacer(1, 4 * mm)]))

    # ------------------------------------------------ recommendations & plan
    story.append(_p("Recommendations", s["h1"]))
    for index, rec in enumerate(report.recommendations or ["No action required."], start=1):
        story.append(_p(f"{index}. {rec}", s["body"]))
    story.append(_p("Remediation priorities", s["h1"]))
    rows = [["Priority", "Severity", "Target", "Count", "Examples"]]
    extra = []
    for i, item in enumerate(report.remediation_priorities, start=1):
        rows.append(
            [
                f"{item['priority']} {item['label']}",
                item["severity"].upper(),
                item["sla"],
                item["count"],
                _p("; ".join(item["items"][:5]), s["cell"]),
            ]
        )
        extra.append(("TEXTCOLOR", (1, i), (1, i), SEVERITY_COLORS[item["severity"]]))
    story.append(_table(rows, [usable * 0.15, usable * 0.13, usable * 0.17, usable * 0.08, usable * 0.47], extra=extra))

    # ------------------------------------------------------- extra sections
    for section in report.sections:
        story.append(_p(section.title, s["h1"]))
        if section.note:
            story.append(_p(section.note, s["small"]))
        width = usable / max(1, len(section.columns))
        rows = [section.columns] + [[_p(cell, s["cell"]) for cell in row] for row in section.rows]
        story.append(_table(rows, [width] * len(section.columns)))

    story += [
        Spacer(1, 8 * mm),
        _p(
            f"Produced by CyberShield {__version__} for authorised defensive use only. Automated findings should be "
            "validated by a qualified analyst before remediation decisions.",
            s["small"],
        ),
    ]
    decorate = _page_decorations(report)
    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
