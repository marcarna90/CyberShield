"""Compliance checker, alert manager and reporting engine."""

from __future__ import annotations

import smtplib
from datetime import timedelta
from pathlib import Path

import pytest

from app.core.models import CheckStatus, Finding, Severity, utcnow
from app.modules.alert_manager import (
    AlertEvent,
    AlertManager,
    AlertTrigger,
    ChannelRoute,
    DashboardChannel,
    EmailChannel,
    LogChannel,
    alerts_from_compliance,
    alerts_from_findings,
)
from app.modules.compliance_checker import ComplianceChecker, build_risk_matrix, derive_signals, load_controls
from app.modules.reporting_engine import (
    ReportData,
    ReportEngine,
    ReportFormat,
    ReportType,
    build_report,
    remediation_priorities,
    severity_matrix,
)
from app.modules.system_auditor import AuditContext, HostAuditor


def finding(fid: str, sev: Severity, source: str = "system_auditor", **kw) -> Finding:
    return Finding(
        finding_id=fid,
        title=kw.pop("title", fid),
        severity=sev,
        category=kw.pop("category", "test"),
        source=source,
        asset=kw.pop("asset", "host-1"),
        recommendation=kw.pop("recommendation", f"Fix {fid}"),
        **kw,
    )


# =============================================================================
# Compliance
# =============================================================================


class TestCompliance:
    checker = ComplianceChecker()

    def all_checks(self, status: CheckStatus) -> dict[str, CheckStatus]:
        _, controls = load_controls()
        return {cid: status for control in controls for cid in control.checks}

    def test_everything_passing_scores_100(self) -> None:
        report = self.checker.evaluate(self.all_checks(CheckStatus.PASS))
        assert report.overall_score == 100.0
        assert {fw.framework for fw in report.frameworks} == {"CIS", "NIST_CSF", "ISO27001"}
        assert all(not fw.gaps for fw in report.frameworks)
        assert "strong posture" in report.executive_summary

    def test_everything_failing_scores_0_with_p1_gaps(self) -> None:
        report = self.checker.evaluate(self.all_checks(CheckStatus.FAIL))
        assert report.overall_score == 0.0
        cis = next(fw for fw in report.frameworks if fw.framework == "CIS")
        assert cis.failed == len(cis.controls)
        assert cis.gaps[0]["priority"] == "P1"
        assert "priority-1" in report.executive_summary and report.recommendations

    def test_partial_and_not_assessed(self) -> None:
        report = self.checker.evaluate({"FW-001": CheckStatus.WARN, "SSH-007": CheckStatus.PASS})
        cis = next(fw for fw in report.frameworks if fw.framework == "CIS")
        statuses = {c.control_id: c.status for c in cis.controls}
        assert statuses["CIS-4.4"] == "partial" and statuses["CIS-4.3"] == "pass"
        assert statuses["CIS-7.7"] == "not_assessed"
        assert cis.score == pytest.approx(100 * (3 * 0.5 + 1) / 4, rel=1e-3)
        assert self.checker.evaluate({}).overall_score == 0.0

    def test_derive_signals(self) -> None:
        now = utcnow()
        none = derive_signals([], last_vulnerability_scan=None, last_traffic_capture=None, now=now)
        assert none == {
            "VULN-001": CheckStatus.UNKNOWN,
            "VULN-002": CheckStatus.UNKNOWN,
            "VULN-003": CheckStatus.FAIL,
            "NET-010": CheckStatus.FAIL,
            "NET-011": CheckStatus.UNKNOWN,
            "NET-012": CheckStatus.UNKNOWN,
        }
        findings = [
            finding("CVE-1", Severity.CRITICAL, "vulnerability_analyzer", cve="CVE-2099-0001"),
            finding("EXP-TELNET", Severity.HIGH, "vulnerability_analyzer"),
            finding("TRF-IOC-IP", Severity.CRITICAL, "traffic_monitor"),
        ]
        bad = derive_signals(
            findings,
            last_vulnerability_scan=now - timedelta(days=60),
            last_traffic_capture=now - timedelta(days=10),
            now=now,
        )
        assert bad["VULN-001"] is CheckStatus.FAIL and bad["VULN-002"] is CheckStatus.PASS
        assert bad["VULN-003"] is CheckStatus.WARN and bad["NET-010"] is CheckStatus.WARN
        assert bad["NET-011"] is CheckStatus.FAIL and bad["NET-012"] is CheckStatus.FAIL
        old = derive_signals(
            [finding("TRF-LEGACY-TLS", Severity.MEDIUM, "traffic_monitor")],
            last_vulnerability_scan=now - timedelta(days=200),
            last_traffic_capture=now,
            now=now,
        )
        assert old["VULN-003"] is CheckStatus.FAIL and old["NET-012"] is CheckStatus.WARN
        good = derive_signals([], last_vulnerability_scan=now, last_traffic_capture=now, now=now)
        assert all(v is CheckStatus.PASS for v in good.values())

    def test_risk_matrix(self) -> None:
        matrix = build_risk_matrix(
            [
                finding("TRF-IOC-IP", Severity.CRITICAL, "traffic_monitor"),
                finding(
                    "CVE-X",
                    Severity.HIGH,
                    "vulnerability_analyzer",
                    cve="CVE-2099-1",
                    description="A public exploit is available.",
                ),
                finding("SSH-001", Severity.CRITICAL),
                finding("USR-004", Severity.INFO),
                finding("EXP-FTP", Severity.MEDIUM, "vulnerability_analyzer"),
            ]
        )
        assert matrix["cells"][4][4] == 1  # IOC: almost certain x severe
        assert matrix["cells"][4][3] == 1  # public exploit high: likelihood 5, impact 4
        assert matrix["cells"][3][4] == 1  # config critical capped at "likely"
        assert matrix["cells"][0][0] == 1
        assert matrix["high_risk_count"] == 3 and matrix["top_risks"][0]["score"] == 25

    def test_invalid_catalogue(self, tmp_path: Path) -> None:
        bad = tmp_path / "controls.yaml"
        bad.write_text(
            "frameworks: {A: {name: a, version: 1}}\ncontrols:\n  - {id: x, framework: B, title: t, checks: []}\n"
        )
        with pytest.raises(ValueError, match="undefined frameworks"):
            load_controls(bad)


# =============================================================================
# Alerting
# =============================================================================


class RecordingChannel:
    def __init__(self, name: str, fail: bool = False, explode: bool = False) -> None:
        self.name, self.fail, self.explode, self.sent = name, fail, explode, []

    def send(self, alert: AlertEvent) -> bool:
        if self.explode:
            raise RuntimeError("channel down")
        self.sent.append(alert)
        return not self.fail


def alert(sev: Severity = Severity.HIGH, title: str = "t") -> AlertEvent:
    return AlertEvent(severity=sev, trigger=AlertTrigger.UNSAFE_CONFIGURATION, title=title, asset="h")


class TestAlerts:
    def test_routing_thresholds_and_dedup(self) -> None:
        low, high = RecordingChannel("log"), RecordingChannel("email")
        manager = AlertManager([ChannelRoute(low), ChannelRoute(high, Severity.HIGH)])
        assert manager.dispatch(alert(Severity.MEDIUM, "a"))
        assert manager.dispatch(alert(Severity.CRITICAL, "b"))
        assert not manager.dispatch(alert(Severity.CRITICAL, "b"))  # duplicate in-process
        assert not manager.dispatch(alert(Severity.INFO, "c"))  # never alerted
        assert len(low.sent) == 2 and [a.title for a in high.sent] == ["b"]

    def test_external_dedup_and_channel_failures(self) -> None:
        manager = AlertManager(
            [ChannelRoute(RecordingChannel("x", explode=True)), ChannelRoute(RecordingChannel("y", fail=True))],
            is_duplicate=lambda fp: False,
        )
        assert not manager.dispatch(alert())
        suppressed = AlertManager([ChannelRoute(RecordingChannel("z"))], is_duplicate=lambda fp: True)
        result = suppressed.dispatch_many([alert(title="1"), alert(title="2")])
        assert not result.sent and len(result.suppressed) == 2

    def test_dashboard_and_log_channels(self, caplog: pytest.LogCaptureFixture) -> None:
        persisted = []
        dashboard = DashboardChannel(lambda a, channels: persisted.append((a.title, channels)))
        manager = AlertManager([ChannelRoute(LogChannel()), ChannelRoute(dashboard)])
        with caplog.at_level("WARNING", logger="cybershield.alerts"):
            manager.dispatch(alert(Severity.CRITICAL, "crit"))
            manager.dispatch(alert(Severity.LOW, "low"))
        assert persisted == [("crit", ["log", "dashboard"]), ("low", ["log", "dashboard"])]
        assert any("CRITICAL" in r.message for r in caplog.records)

    def test_email_channel(self) -> None:
        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout):
                sent["server"] = (host, port, timeout)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def starttls(self, context):
                sent["tls"] = context is not None

            def login(self, user, password):
                sent["login"] = (user, password)

            def send_message(self, message):
                sent["message"] = message

        channel = EmailChannel(
            "smtp.example", 587, "soc@corp.example", ["ciso@corp.example"], "u", "p", smtp_factory=FakeSMTP
        )
        assert channel.send(alert(Severity.CRITICAL, "Injected\r\nBcc: attacker@evil.example"))
        message = sent["message"]
        assert sent["tls"] and sent["login"] == ("u", "p") and "\n" not in message["Subject"]
        assert message["Bcc"] is None and "ciso@corp.example" in message["To"]

        class BrokenSMTP(FakeSMTP):
            def send_message(self, message):
                raise smtplib.SMTPException("relay denied")

        assert not EmailChannel("h", 25, "a@b.example", ["c@d.example"], starttls=False, smtp_factory=BrokenSMTP).send(
            alert()
        )

    def test_email_validation(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            EmailChannel("h", 25, "not-an-email", ["c@d.example"])
        with pytest.raises(ValueError, match="recipient"):
            EmailChannel("h", 25, "a@b.example", [])

    def test_trigger_builders(self) -> None:
        alerts = alerts_from_findings(
            [
                finding("SSH-001", Severity.HIGH),
                finding("CVE-1", Severity.CRITICAL, "vulnerability_analyzer"),
                finding("TRF-IOC-IP", Severity.CRITICAL, "traffic_monitor"),
                finding("TRF-SPIKE", Severity.MEDIUM, "traffic_monitor"),
                finding("TRF-DGA", Severity.MEDIUM, "traffic_monitor"),
                finding("LOW-1", Severity.LOW),
                finding("INFO-1", Severity.INFO),
            ],
            min_severity=Severity.MEDIUM,
        )
        triggers = [a.trigger for a in alerts]
        assert triggers == [
            AlertTrigger.UNSAFE_CONFIGURATION,
            AlertTrigger.VULNERABILITY_DISCOVERED,
            AlertTrigger.THREAT_INTEL_MATCH,
            AlertTrigger.TRAFFIC_SPIKE,
            AlertTrigger.TRAFFIC_ANOMALY,
        ]
        compliance = alerts_from_compliance({"CIS": 30.0, "NIST": 65.0, "ISO": 90.0}, threshold=70)
        assert [(a.severity, a.trigger) for a in compliance] == [
            (Severity.HIGH, AlertTrigger.COMPLIANCE_FAILURE),
            (Severity.MEDIUM, AlertTrigger.COMPLIANCE_FAILURE),
        ]
        assert alert().fingerprint == alert().fingerprint != alert(title="other").fingerprint


# =============================================================================
# Reporting
# =============================================================================


@pytest.fixture
def sample_inputs(weak_root: Path):
    audit = HostAuditor(AuditContext(host_root=weak_root)).run()
    compliance = ComplianceChecker().evaluate(audit.check_statuses(), audit.findings)
    vuln = finding(
        "CVE-2021-41773",
        Severity.HIGH,
        "vulnerability_analyzer",
        cve="CVE-2021-41773",
        cvss=7.5,
        port=80,
        asset="10.0.0.5",
        category="vulnerability",
        title="<script>alert('xss')</script> Apache 2.4.49",
        evidence="banner <b>Apache</b> & co",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    )
    traffic = {
        "source": "pcap:x",
        "health_score": 42.0,
        "total_packets": 10,
        "total_bytes": 1000,
        "protocols": {"TLS": 8, "DNS": 2},
        "protocol_bytes": {"TLS": 900, "DNS": 100},
        "top_talkers": [{"ip": "10.0.0.5", "bytes": 900, "packets": 8, "internal": True}],
        "anomalies": [],
    }
    assets = [
        {
            "ip": "10.0.0.5",
            "hostname": "web",
            "risk_score": 55.0,
            "services": [
                {"port": 80, "protocol": "tcp", "name": "http", "product": "Apache httpd", "version": "2.4.49"}
            ],
        }
    ]
    return {
        "findings": [*audit.findings, vuln],
        "compliance": compliance.model_dump(mode="json"),
        "host_audit": audit.model_dump(mode="json"),
        "traffic": traffic,
        "assets": assets,
    }


class TestReporting:
    def test_helpers(self) -> None:
        findings = [finding("A", Severity.CRITICAL), finding("B", Severity.LOW, category="x")]
        assert severity_matrix(findings)["test"]["critical"] == 1
        priorities = remediation_priorities(findings)
        assert [p["priority"] for p in priorities] == ["P1", "P4"]

    @pytest.mark.parametrize("report_type", list(ReportType))
    def test_build_each_type(self, sample_inputs, report_type: ReportType) -> None:
        data = build_report(
            report_type,
            sample_inputs["findings"],
            organization="ACME",
            generated_by="tester",
            compliance=sample_inputs["compliance"],
            assets=sample_inputs["assets"],
            host_audit=sample_inputs["host_audit"],
            traffic=sample_inputs["traffic"],
        )
        assert data.summary and data.narrative and data.remediation_priorities and data.recommendations
        assert data.severity_counts["critical"] >= (0 if report_type is ReportType.VULNERABILITY else 1)
        if report_type is ReportType.VULNERABILITY:
            assert all(f.source == "vulnerability_analyzer" for f in data.findings)
            assert data.sections[0].title == "Asset inventory" and data.risk_matrix is None
        if report_type is ReportType.EXECUTIVE:
            assert len(data.findings) <= 15 and data.compliance
            assert all(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in data.findings)
        if report_type is ReportType.TECHNICAL:
            assert {s.title.split(" -")[0] for s in data.sections} >= {
                "Asset inventory",
                "Host audit checks",
                "Traffic protocol mix",
                "Top talkers",
            }
        if report_type is ReportType.COMPLIANCE:
            assert data.compliance and data.risk_matrix

    def test_empty_report(self) -> None:
        data = build_report(ReportType.TECHNICAL, [], organization="ACME", generated_by="t")
        assert data.findings_total == 0 and data.scope == "Platform-wide open findings"

    def test_render_all_formats(self, sample_inputs, tmp_path: Path) -> None:
        engine = ReportEngine(tmp_path / "out")
        for report_type in ReportType:
            data = build_report(
                report_type,
                sample_inputs["findings"],
                organization="ACME <Corp>",
                generated_by="tester",
                compliance=sample_inputs["compliance"],
                assets=sample_inputs["assets"],
                host_audit=sample_inputs["host_audit"],
                traffic=sample_inputs["traffic"],
            )
            outputs = engine.generate(data, ["pdf", ReportFormat.HTML, "json", "pdf"])
            assert [o.format for o in outputs] == [ReportFormat.PDF, ReportFormat.HTML, ReportFormat.JSON]
            for output in outputs:
                content = Path(output.path).read_bytes()
                assert len(content) == output.size_bytes > 500
                assert engine.resolve(output.filename) == Path(output.path).resolve()
            pdf = Path(outputs[0].path).read_bytes()
            assert pdf.startswith(b"%PDF")
            html = Path(outputs[1].path).read_text()
            assert "<script>alert" not in html and "&lt;script&gt;" in html  # autoescaped (XSS)
            assert ReportData.model_validate_json(Path(outputs[2].path).read_text()).organization == "ACME <Corp>"

    @pytest.mark.parametrize("name", ["../etc/passwd", "a/b.pdf", "x.exe", ".pdf", "report.pdf/.."])
    def test_resolve_rejects_traversal(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(ValueError):
            ReportEngine(tmp_path).resolve(name)
