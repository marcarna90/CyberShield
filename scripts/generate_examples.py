"""Regenerate the documentation examples in docs/examples from the demo scenario.

    python scripts/generate_examples.py

Runs entirely in a temporary directory (SQLite), replays the demo scenario
through the real pipelines, then exports: every report type in PDF/HTML/JSON,
module JSON outputs (host audit, vulnerability scan, traffic, compliance,
alerts, dashboard overview) and a sample PCAP.

Note: report JSON files are named ``<type>_report.json``; module outputs use
distinct names (``compliance_evaluation.json``, ``vulnerability_scan.json``...).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "docs" / "examples"


def main() -> None:
    logging.getLogger().addHandler(logging.NullHandler())  # keep alert logs off the console
    with tempfile.TemporaryDirectory(prefix="cybershield-examples-") as tmp:
        os.environ.update(
            {
                "CYBERSHIELD_DATA_DIR": f"{tmp}/data",
                "CYBERSHIELD_REPORTS_DIR": f"{tmp}/reports",
                "CYBERSHIELD_LOGS_DIR": f"{tmp}/logs",
                "CYBERSHIELD_ADMIN_PASSWORD": "Ex4mple-Passw0rd-Demo!",
                "CYBERSHIELD_ORGANIZATION": "ACME Corp (demo)",
                "CYBERSHIELD_LOG_LEVEL": "ERROR",
            }
        )
        from sqlalchemy import select

        from app.core.config import get_settings
        from app.database import repository
        from app.database.init_db import init_database
        from app.database.models import Alert, Scan
        from app.database.session import configure_database, session_scope
        from app.modules.traffic_monitor.synthetic import write_sample_pcap
        from app.services import demo, operations

        settings = get_settings()
        settings.ensure_directories()
        configure_database(settings.sqlalchemy_url)
        init_database(settings)
        OUT.mkdir(parents=True, exist_ok=True)

        def dump(name: str, data: object) -> None:
            (OUT / name).write_text(json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8")

        with session_scope() as db:
            demo.seed_demo_data(db, settings)
            host = operations.latest_host_audit(db)
            dump("host_audit.json", host)
            scan = db.scalars(
                select(Scan).where(Scan.scan_type == "network").order_by(Scan.started_at.desc()).limit(1)
            ).first()
            dump("vulnerability_scan.json", {"scan_id": scan.id, "status": scan.status, **scan.summary})
            vuln_findings = [
                repository.record_to_finding(r).model_dump(mode="json")
                for r in repository.open_findings(db, source="vulnerability_analyzer")
            ]
            dump("vulnerability_findings.json", vuln_findings)
            dump("traffic_analysis.json", operations.latest_traffic(db).summary)
            dump("compliance_evaluation.json", operations.latest_compliance_report(db))
            alerts = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(15))
            dump(
                "alerts.json",
                [
                    {
                        k: getattr(a, k)
                        for k in ("id", "created_at", "severity", "trigger", "title", "asset", "channels")
                    }
                    for a in alerts
                ],
            )
            dump("dashboard_overview.json", repository.overview(db))
            for report_type in ("executive", "technical", "vulnerability", "compliance"):
                for record in operations.generate_reports(
                    db, settings, "examples", report_type, ["pdf", "html", "json"]
                ):
                    shutil.copy(settings.reports_dir / record.filename, OUT / f"{report_type}_report.{record.format}")
        write_sample_pcap(OUT / "sample_traffic.pcap")
    print(f"Examples written to {OUT}")


if __name__ == "__main__":
    main()
