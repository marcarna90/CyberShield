"""``cybershield`` command-line interface.

Designed for native use on Kali Linux / Parrot OS / Ubuntu / Debian, CI jobs
and the Docker entrypoint. Every state-changing command is written to the
tamper-evident audit trail with the invoking OS user.

Examples::

    cybershield init-db
    sudo cybershield audit host --pdf host.pdf --json host.json
    cybershield scan network 192.168.1.0/24 --profile standard --i-am-authorized
    cybershield traffic pcap capture.pcap
    sudo cybershield traffic capture --iface eth0 --duration 120
    cybershield report generate --type executive --format pdf html json
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from app import __version__
from app.core.audit import record_event, verify_chain
from app.core.config import Settings, get_settings
from app.core.logging import setup_logging
from app.core.models import Severity
from app.core.rbac import Role
from app.core.security import password_policy_violations
from app.database import repository
from app.database.init_db import init_database
from app.database.session import session_scope

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 2


def _actor() -> str:
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:  # pragma: no cover - exotic environments
        return "cli:unknown"


def _emit(data: Any, as_json: bool = True) -> None:
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


def _write(path: str | None, content: str) -> None:
    if path:
        Path(path).write_text(content, encoding="utf-8")
        print(f"Written: {path}", file=sys.stderr)


def _audit(action: str, resource: str = "", details: dict[str, Any] | None = None, outcome: str = "success") -> None:
    with session_scope() as db:
        record_event(db, actor=_actor(), action=action, resource=resource, outcome=outcome, details=details)


# =============================================================================
# Command handlers
# =============================================================================


def cmd_init_db(args: argparse.Namespace, settings: Settings) -> int:
    result = init_database(settings)
    if result.admin_created and result.password_file:
        print(f"Administrator '{settings.admin_username}' created. Password file: {result.password_file}")
    elif result.admin_created:
        print(f"Administrator '{settings.admin_username}' created from configured secret.")
    else:
        print("Database ready (users already exist).")
    return EXIT_OK


def cmd_create_user(args: argparse.Namespace, settings: Settings) -> int:
    init_database(settings)
    password = sys.stdin.readline().rstrip("\n") if args.password_stdin else getpass.getpass("Password: ")
    problems = password_policy_violations(password, args.username)
    if problems:
        print("Password rejected: " + "; ".join(problems), file=sys.stderr)
        return EXIT_ERROR
    with session_scope() as db:
        if repository.get_user_by_username(db, args.username):
            print(f"User {args.username!r} already exists", file=sys.stderr)
            return EXIT_ERROR
        repository.create_user(db, username=args.username, email=args.email, password=password, role=args.role)
        record_event(db, actor=_actor(), action="user.create", resource=args.username, details={"role": args.role})
    print(f"User {args.username!r} created with role {args.role}.")
    return EXIT_OK


def cmd_secrets_init(args: argparse.Namespace, settings: Settings) -> int:
    from app.services.secrets_init import init_secrets

    created = init_secrets(Path(args.dir), args.app_owner, args.db_owner)
    for name, was_created in created.items():
        print(f"{name}: {'created' if was_created else 'kept'}")
    return EXIT_OK


def cmd_audit_host(args: argparse.Namespace, settings: Settings) -> int:
    from app.modules.reporting_engine import ReportEngine, ReportType, build_report
    from app.modules.system_auditor import AuditContext, HostAuditor

    root = Path(args.host_root) if args.host_root else settings.host_root
    if args.no_save:
        report = HostAuditor(AuditContext(host_root=root)).run()
    else:
        from app.services import operations

        init_database(settings)
        with session_scope() as db:
            _, report = operations.run_host_audit(db, settings, _actor(), host_root=root)
            record_event(db, actor=_actor(), action="audit.host", resource=str(root), details={"score": report.score})
    _write(args.json, report.model_dump_json(indent=2))
    if args.pdf or args.html:
        data = build_report(
            ReportType.TECHNICAL,
            report.findings,
            organization=settings.organization,
            generated_by=_actor(),
            host_audit=report.model_dump(mode="json"),
        )
        engine = ReportEngine(settings.reports_dir)
        for fmt, target in (("pdf", args.pdf), ("html", args.html)):
            if target:
                generated = engine.generate(data, [fmt])[0]
                Path(target).write_bytes(Path(generated.path).read_bytes())
                print(f"Written: {target}", file=sys.stderr)
    print(f"Host: {report.hostname} ({report.os_name})  Hardening score: {report.score}/100")
    for check in report.checks:
        print(f"  [{check.status.value.upper():<14}] {check.check_id:<9} {check.severity.value:<13} {check.title}")
    worst = max((f.severity.rank for f in report.findings), default=0)
    return EXIT_FINDINGS if args.fail_on and worst >= Severity.parse(args.fail_on).rank else EXIT_OK


def cmd_scan_network(args: argparse.Namespace, settings: Settings) -> int:
    if not args.i_am_authorized:
        print(
            "Refusing to scan: confirm you are authorised to scan these targets with --i-am-authorized.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    from app.services import operations

    init_database(settings)
    with session_scope() as db:
        scan = operations.queue_network_scan(db, _actor(), args.targets, args.profile)
        record_event(
            db,
            actor=_actor(),
            action="scan.network",
            resource=",".join(args.targets),
            details={"profile": args.profile, "scan_id": scan.id},
        )
        scan = operations.execute_network_scan(db, settings, scan, args.targets, args.profile)
        result = {"scan_id": scan.id, "status": scan.status, "error": scan.error, **(scan.summary or {})}
    _write(args.json, json.dumps(result, indent=2, default=str))
    _emit({k: result.get(k) for k in ("scan_id", "status", "error", "assets", "severity_counts", "risk_score")})
    return EXIT_OK if result["status"] == "completed" else EXIT_ERROR


def _print_traffic(summary: Any) -> None:
    print(f"Packets: {summary.total_packets}  Bytes: {summary.total_bytes}  Health: {summary.health_score}/100")
    print("Protocols: " + ", ".join(f"{k}={v}" for k, v in summary.protocols.items()))
    for finding in summary.anomalies:
        print(f"  [{finding.severity.value.upper():<8}] {finding.finding_id:<18} {finding.title}")


def cmd_traffic_pcap(args: argparse.Namespace, settings: Settings) -> int:
    from app.modules.traffic_monitor.capture import CaptureError, analyze_pcap
    from app.services import operations
    from app.services.context import get_iocs, traffic_thresholds

    path = Path(args.file)
    try:
        summary = analyze_pcap(path, traffic_thresholds(settings), get_iocs(settings), settings.traffic_max_packets)
    except CaptureError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    if not args.no_save:
        init_database(settings)
        with session_scope() as db:
            operations.record_traffic(db, settings, summary, _actor())
            record_event(db, actor=_actor(), action="traffic.pcap", resource=path.name)
    _write(args.json, summary.model_dump_json(indent=2))
    _print_traffic(summary)
    return EXIT_OK


def cmd_traffic_capture(args: argparse.Namespace, settings: Settings) -> int:
    from app.modules.traffic_monitor.capture import CaptureError, live_capture
    from app.services import operations
    from app.services.context import get_iocs, traffic_thresholds

    try:
        summary = live_capture(
            args.iface,
            args.duration,
            traffic_thresholds(settings),
            get_iocs(settings),
            bpf_filter=args.filter,
            max_packets=settings.traffic_max_packets,
        )
    except CaptureError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_ERROR
    if not args.no_save:
        init_database(settings)
        with session_scope() as db:
            operations.record_traffic(db, settings, summary, _actor())
            record_event(db, actor=_actor(), action="traffic.capture", resource=args.iface or "default")
    _write(args.json, summary.model_dump_json(indent=2))
    _print_traffic(summary)
    return EXIT_OK


def cmd_sensor(args: argparse.Namespace, settings: Settings) -> int:
    from app.services.sensor import Sensor

    init_database(settings)
    windows = Sensor(settings).run_forever(max_windows=args.windows)
    print(f"Sensor stopped after {windows} window(s).")
    return EXIT_OK


def cmd_compliance(args: argparse.Namespace, settings: Settings) -> int:
    from app.services import operations

    init_database(settings)
    with session_scope() as db:
        report = operations.run_compliance(db, settings, _actor())
        record_event(db, actor=_actor(), action="compliance.evaluate", details={"score": report.overall_score})
    _write(args.json, report.model_dump_json(indent=2))
    print(report.executive_summary)
    return EXIT_OK


def cmd_report(args: argparse.Namespace, settings: Settings) -> int:
    from app.services import operations

    init_database(settings)
    with session_scope() as db:
        records = operations.generate_reports(db, settings, _actor(), args.type, args.format)
        record_event(db, actor=_actor(), action="report.generate", resource=args.type, details={"formats": args.format})
        for record in records:
            print(f"{settings.reports_dir / record.filename}  sha256={record.sha256}")
    return EXIT_OK


def cmd_cve_import(args: argparse.Namespace, settings: Settings) -> int:
    from app.modules.vulnerability_analyzer.cve_db import CVEDatabase
    from app.services.context import cve_db_path, reset_caches

    target = cve_db_path(settings)
    db = CVEDatabase.load_json(target) if target.is_file() else CVEDatabase()
    added = db.merge_file(Path(args.file))
    db.save(target)
    reset_caches()
    print(f"Imported {added} CVE/product records into {target} (total {len(db)}).")
    _audit("cve.import", Path(args.file).name, {"records": added})
    return EXIT_OK


def cmd_cve_lookup(args: argparse.Namespace, settings: Settings) -> int:
    from app.services.context import get_cve_db

    matches = get_cve_db(settings).lookup(args.vendor, args.product, args.version)
    _emit(
        [
            {
                "cve": r.cve_id,
                "cvss": r.cvss,
                "severity": r.severity.value,
                "range": m.describe(),
                "fixed_version": r.fixed_version,
            }
            for r, m in matches
        ]
    )
    return EXIT_OK


def cmd_intel_refresh(args: argparse.Namespace, settings: Settings) -> int:
    from app.services.context import get_iocs, ioc_cache_dir, reset_caches

    if not settings.threat_feed_list:
        print("No feeds configured (set CYBERSHIELD_THREAT_FEEDS).", file=sys.stderr)
        return EXIT_ERROR
    results = get_iocs(settings).refresh_from_feeds(settings.threat_feed_list, ioc_cache_dir(settings))
    reset_caches()
    _emit(results)
    _audit("intel.refresh", details={"feeds": len(results)})
    return EXIT_OK if all(v >= 0 for v in results.values()) else EXIT_ERROR


def cmd_intel_lookup(args: argparse.Namespace, settings: Settings) -> int:
    from app.services.context import get_iocs

    _emit(get_iocs(settings).lookup(args.indicator))
    return EXIT_OK


def cmd_demo(args: argparse.Namespace, settings: Settings) -> int:
    from app.services import demo

    init_database(settings)
    with session_scope() as db:
        result = demo.seed_demo_data(db, settings) if args.action == "seed" else demo.purge_demo_data(db)
        record_event(db, actor=_actor(), action=f"demo.{args.action}", details=result)
    _emit(result)
    return EXIT_OK


def cmd_verify_trail(args: argparse.Namespace, settings: Settings) -> int:
    init_database(settings)
    with session_scope() as db:
        result = verify_chain(db)
    _emit(result.__dict__)
    return EXIT_OK if result.valid else EXIT_FINDINGS


def cmd_sample_pcap(args: argparse.Namespace, settings: Settings) -> int:
    from app.modules.traffic_monitor.synthetic import write_sample_pcap

    print(f"Written: {write_sample_pcap(Path(args.path))}")
    return EXIT_OK


# =============================================================================
# Parser
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cybershield", description="CyberShield Enterprise Security Platform CLI")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create tables and the initial administrator").set_defaults(func=cmd_init_db)

    p = sub.add_parser("create-user", help="create a user account")
    p.add_argument("--username", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--role", choices=[r.value for r in Role], default=Role.VIEWER.value)
    p.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    p.set_defaults(func=cmd_create_user)

    p = sub.add_parser("secrets", help="secret management")
    s = p.add_subparsers(dest="action", required=True)
    q = s.add_parser("init", help="generate missing secrets (Docker init container)")
    q.add_argument("--dir", required=True)
    q.add_argument("--app-owner", help="UID:GID owning application secrets")
    q.add_argument("--db-owner", help="UID:GID owning the database password")
    q.set_defaults(func=cmd_secrets_init)

    p = sub.add_parser("audit", help="host security audit")
    s = p.add_subparsers(dest="action", required=True)
    q = s.add_parser("host", help="audit the local host configuration")
    q.add_argument("--host-root", help="filesystem root to audit (default: CYBERSHIELD_HOST_ROOT or /)")
    q.add_argument("--json", help="write the JSON report to this file")
    q.add_argument("--pdf", help="write a PDF report to this file")
    q.add_argument("--html", help="write an HTML report to this file")
    q.add_argument("--no-save", action="store_true", help="do not store results in the database")
    q.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="exit with code 2 if a finding of this severity or worse exists (CI gate)",
    )
    q.set_defaults(func=cmd_audit_host)

    p = sub.add_parser("scan", help="authorised network scanning")
    s = p.add_subparsers(dest="action", required=True)
    q = s.add_parser("network", help="discover hosts/services and analyse vulnerabilities")
    q.add_argument("targets", nargs="+", help="IP, CIDR or hostname inside CYBERSHIELD_ALLOWED_TARGETS")
    q.add_argument("--profile", default="standard", choices=["discovery", "quick", "standard", "full"])
    q.add_argument("--i-am-authorized", action="store_true", help="confirm you are authorised to scan the targets")
    q.add_argument("--json", help="write the scan summary to this file")
    q.set_defaults(func=cmd_scan_network)

    p = sub.add_parser("traffic", help="passive traffic analysis")
    s = p.add_subparsers(dest="action", required=True)
    q = s.add_parser("pcap", help="analyse a PCAP/PCAPNG file")
    q.add_argument("file")
    q.add_argument("--json")
    q.add_argument("--no-save", action="store_true")
    q.set_defaults(func=cmd_traffic_pcap)
    q = s.add_parser("capture", help="live passive capture (root / CAP_NET_RAW)")
    q.add_argument("--iface", default=None)
    q.add_argument("--duration", type=int, default=60)
    q.add_argument("--filter", default=None, help="BPF filter, e.g. 'not port 22'")
    q.add_argument("--json")
    q.add_argument("--no-save", action="store_true")
    q.set_defaults(func=cmd_traffic_capture)

    p = sub.add_parser("sensor", help="continuous capture loop (CYBERSHIELD_SENSOR_INTERFACE)")
    p.add_argument("--windows", type=int, default=None, help="stop after N windows (default: run forever)")
    p.set_defaults(func=cmd_sensor)

    p = sub.add_parser("compliance", help="compliance evaluation")
    s = p.add_subparsers(dest="action", required=True)
    q = s.add_parser("evaluate")
    q.add_argument("--json")
    q.set_defaults(func=cmd_compliance)

    p = sub.add_parser("report", help="report generation")
    s = p.add_subparsers(dest="action", required=True)
    q = s.add_parser("generate")
    q.add_argument("--type", default="executive", choices=["executive", "technical", "vulnerability", "compliance"])
    q.add_argument("--format", nargs="+", default=["pdf", "html", "json"], choices=["pdf", "html", "json"])
    q.set_defaults(func=cmd_report)

    p = sub.add_parser("cve", help="CVE database")
    s = p.add_subparsers(dest="action", required=True)
    q = s.add_parser("import", help="import NVD JSON (API 2.0) or CyberShield JSON")
    q.add_argument("file")
    q.set_defaults(func=cmd_cve_import)
    q = s.add_parser("lookup")
    q.add_argument("--vendor", required=True)
    q.add_argument("--product", required=True)
    q.add_argument("--version", required=True)
    q.set_defaults(func=cmd_cve_lookup)

    p = sub.add_parser("intel", help="threat intelligence")
    s = p.add_subparsers(dest="action", required=True)
    s.add_parser("refresh", help="download configured HTTPS feeds").set_defaults(func=cmd_intel_refresh)
    q = s.add_parser("lookup")
    q.add_argument("indicator")
    q.set_defaults(func=cmd_intel_lookup)

    p = sub.add_parser("demo", help="load or remove the demo dataset")
    p.add_argument("action", choices=["seed", "purge"])
    p.set_defaults(func=cmd_demo)

    sub.add_parser("verify-audit-trail", help="verify the audit trail hash chain").set_defaults(func=cmd_verify_trail)

    p = sub.add_parser("sample-pcap", help="write a synthetic sample capture")
    p.add_argument("path")
    p.set_defaults(func=cmd_sample_pcap)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    settings.ensure_directories()
    setup_logging(settings, stream=sys.stderr)
    try:
        return int(args.func(args, settings))
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
