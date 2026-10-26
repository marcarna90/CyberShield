"""Report rendering (PDF / HTML / JSON) with integrity hashes."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Iterable
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app import __version__
from app.core.models import Severity
from app.modules.reporting_engine.models import GeneratedReport, ReportData, ReportFormat
from app.modules.reporting_engine.pdf import render_pdf

TEMPLATES = Path(__file__).parent / "templates"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_\-]+\.(pdf|html|json)$")


class ReportEngine:
    """Render :class:`ReportData` into files under ``output_dir``."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # autoescape=True is mandatory: findings contain attacker-influenced data
        # (banners, DNS names, HTTP hosts) that must never execute in a browser.
        self._env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True, undefined=StrictUndefined)

    def render_html(self, report: ReportData) -> str:
        template = self._env.get_template("report.html.j2")
        return template.render(report=report, severities=[s.value for s in Severity.ordered()], version=__version__)

    @staticmethod
    def render_json(report: ReportData) -> str:
        return report.model_dump_json(indent=2)

    def filename_for(self, report: ReportData, fmt: ReportFormat) -> str:
        stamp = report.generated_at.strftime("%Y%m%dT%H%M%SZ")
        return f"{report.report_type.value}_{stamp}_{secrets.token_hex(3)}.{fmt.value}"

    def resolve(self, filename: str) -> Path:
        """Safely resolve a stored report filename (prevents path traversal)."""
        if not _SAFE_NAME.match(filename):
            raise ValueError("Invalid report filename")
        path = (self.output_dir / filename).resolve()
        if path.parent != self.output_dir.resolve():
            raise ValueError("Invalid report path")
        return path

    def generate(self, report: ReportData, formats: Iterable[ReportFormat | str]) -> list[GeneratedReport]:
        outputs = []
        for fmt in dict.fromkeys(ReportFormat(f) for f in formats):
            filename = self.filename_for(report, fmt)
            path = self.output_dir / filename
            if fmt is ReportFormat.PDF:
                render_pdf(report, path)
            elif fmt is ReportFormat.HTML:
                path.write_text(self.render_html(report), encoding="utf-8")
            else:
                path.write_text(self.render_json(report), encoding="utf-8")
            data = path.read_bytes()
            outputs.append(
                GeneratedReport(
                    report_type=report.report_type,
                    format=fmt,
                    path=str(path),
                    filename=filename,
                    sha256=hashlib.sha256(data).hexdigest(),
                    size_bytes=len(data),
                )
            )
        return outputs
