"""CLI commands, service layer (operations, sensor, demo, secrets), repository and bootstrap."""

from __future__ import annotations

import io
import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.cli import main
from app.core.config import Settings
from app.core.models import Finding, Severity, utcnow
from app.database import repository
from app.database.init_db import bootstrap_admin
from app.database.models import Alert, Asset, FindingRecord, User
from app.database.session import session_scope
from app.modules.traffic_monitor.analyzer import TrafficAnalyzer
from app.modules.traffic_monitor.capture import CaptureError
from app.modules.traffic_monitor.synthetic import write_sample_pcap
from app.services import demo, operations
from app.services.secrets_init import init_secrets
from app.services.sensor import Sensor
from tests.conftest import FakeNmap

# =============================================================================
# CLI
# =============================================================================


class TestCLI:
    def test_init_db_and_create_user(self, settings: Settings, monkeypatch, capsys) -> None:
        assert main(["init-db"]) == 0
        assert "Administrator 'admin' created" in capsys.readouterr().out
        assert main(["init-db"]) == 0
        assert "already exist" in capsys.readouterr().out
        monkeypatch.setattr("sys.stdin", io.StringIO("Secure-Passw0rd!!\n"))
        assert (
            main(
                [
                    "create-user",
                    "--username",
                    "ana",
                    "--email",
                    "ana@corp.example",
                    "--role",
                    "analyst",
                    "--password-stdin",
                ]
            )
            == 0
        )
        monkeypatch.setattr("sys.stdin", io.StringIO("Secure-Passw0rd!!\n"))
        assert main(["create-user", "--username", "ana", "--email", "a@corp.example", "--password-stdin"]) == 1
        monkeypatch.setattr("sys.stdin", io.StringIO("weak\n"))
        assert main(["create-user", "--username", "bo", "--email", "b@corp.example", "--password-stdin"]) == 1
        monkeypatch.setattr("getpass.getpass", lambda prompt: "Interactive-Passw0rd!")
        assert main(["create-user", "--username", "eve", "--email", "e@corp.example"]) == 0

    def test_generated_admin_password_file(self, settings: Settings, monkeypatch, capsys) -> None:
        monkeypatch.delenv("CYBERSHIELD_ADMIN_PASSWORD")
        from app.core.config import get_settings

        get_settings.cache_clear()
        assert main(["init-db"]) == 0
        password_file = settings.data_dir / "initial_admin_password"
        assert "Password file" in capsys.readouterr().out
        assert password_file.stat().st_mode & 0o777 == 0o600

    def test_audit_host_offline_outputs(self, settings: Settings, weak_root: Path, tmp_path: Path, capsys) -> None:
        out = tmp_path / "out"
        out.mkdir()
        code = main(
            [
                "audit",
                "host",
                "--host-root",
                str(weak_root),
                "--no-save",
                "--json",
                str(out / "a.json"),
                "--pdf",
                str(out / "a.pdf"),
                "--html",
                str(out / "a.html"),
                "--fail-on",
                "high",
            ]
        )
        assert code == 2  # CI gate tripped
        assert json.loads((out / "a.json").read_text())["hostname"] == "web-prod-01"
        assert (out / "a.pdf").read_bytes().startswith(b"%PDF") and "<html" in (out / "a.html").read_text()
        assert "Hardening score" in capsys.readouterr().out

    def test_audit_host_saved(self, settings: Settings, hardened_root: Path) -> None:
        assert main(["audit", "host", "--host-root", str(hardened_root), "--fail-on", "low"]) == 0
        assert main(["audit", "host"]) == 0  # default root from settings (weak demo root)
        with session_scope() as db:
            assert repository.open_findings(db, source="system_auditor")

    def test_scan_requires_authorisation(self, settings: Settings, capsys) -> None:
        assert main(["scan", "network", "10.0.0.1"]) == 1
        assert "--i-am-authorized" in capsys.readouterr().err

    def test_scan(self, settings: Settings, fake_nmap: FakeNmap, tmp_path: Path, capsys) -> None:
        assert main(["scan", "network", "10.0.0.0/29", "--i-am-authorized", "--json", str(tmp_path / "s.json")]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["status"] == "completed" and result["severity_counts"]["critical"] >= 1
        assert main(["scan", "network", "8.8.8.8", "--i-am-authorized"]) == 1

    def test_traffic_and_reports(self, settings: Settings, tmp_path: Path, capsys) -> None:
        pcap = tmp_path / "s.pcap"
        assert main(["sample-pcap", str(pcap)]) == 0
        assert main(["traffic", "pcap", str(pcap), "--json", str(tmp_path / "t.json")]) == 0
        assert "TRF-PORTSCAN" in capsys.readouterr().out
        assert main(["traffic", "pcap", str(pcap), "--no-save"]) == 0
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"junk")
        assert main(["traffic", "pcap", str(bad)]) == 1
        assert main(["compliance", "evaluate", "--json", str(tmp_path / "c.json")]) == 0
        assert main(["report", "generate", "--type", "compliance", "--format", "json"]) == 0
        assert "sha256=" in capsys.readouterr().out

    def test_traffic_capture(self, settings: Settings, monkeypatch, tmp_path: Path) -> None:
        from app.modules.traffic_monitor import capture

        summary = TrafficAnalyzer(source="live:eth0").summarize()
        monkeypatch.setattr(capture, "live_capture", lambda *a, **k: summary)
        assert (
            main(["traffic", "capture", "--iface", "eth0", "--duration", "1", "--json", str(tmp_path / "live.json")])
            == 0
        )
        assert main(["traffic", "capture", "--no-save"]) == 0

        def denied(*args, **kwargs):
            raise CaptureError("needs root")

        monkeypatch.setattr(capture, "live_capture", denied)
        assert main(["traffic", "capture"]) == 1

    def test_cve_and_intel(self, settings: Settings, tmp_path: Path, capsys) -> None:
        feed = tmp_path / "nvd.json"
        feed.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2099-7777",
                                "descriptions": [{"lang": "en", "value": "x"}],
                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0}}]},
                                "configurations": [
                                    {
                                        "nodes": [
                                            {
                                                "cpeMatch": [
                                                    {
                                                        "vulnerable": True,
                                                        "criteria": "cpe:2.3:a:acme:gizmo:2.0:*:*:*:*:*:*:*",
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        }
                    ]
                }
            )
        )
        assert main(["cve", "import", str(feed)]) == 0
        capsys.readouterr()
        assert main(["cve", "lookup", "--vendor", "acme", "--product", "gizmo", "--version", "2.0"]) == 0
        assert json.loads(capsys.readouterr().out)[0]["cve"] == "CVE-2099-7777"
        assert main(["cve", "import", str(feed)]) == 0  # merges into existing DB
        assert main(["intel", "lookup", "203.0.113.66"]) == 0
        assert json.loads(capsys.readouterr().out.split("\n", 1)[1] or "{}") is not None
        assert main(["intel", "refresh"]) == 1

    def test_intel_refresh_configured(self, settings: Settings, monkeypatch) -> None:
        from app.core.config import get_settings
        from app.modules.threat_intelligence.intel import IOCDatabase

        monkeypatch.setenv("CYBERSHIELD_THREAT_FEEDS", "https://feeds.example/a.txt")
        get_settings.cache_clear()
        monkeypatch.setattr(IOCDatabase, "refresh_from_feeds", lambda self, urls, cache: {urls[0]: 3})
        assert main(["intel", "refresh"]) == 0
        monkeypatch.setattr(IOCDatabase, "refresh_from_feeds", lambda self, urls, cache: {urls[0]: -1})
        assert main(["intel", "refresh"]) == 1

    def test_demo_trail_secrets_and_sensor(self, settings: Settings, tmp_path: Path, monkeypatch, capsys) -> None:
        assert main(["demo", "seed"]) == 0
        assert json.loads(capsys.readouterr().out)["assets"] == 8
        assert main(["demo", "purge"]) == 0
        assert main(["verify-audit-trail"]) == 0
        assert main(["secrets", "init", "--dir", str(tmp_path / "secrets")]) == 0
        assert "jwt_secret: created" in capsys.readouterr().out
        monkeypatch.setattr(Sensor, "run_forever", lambda self, max_windows=None: 2)
        assert main(["sensor", "--windows", "2"]) == 0

    def test_verify_trail_detects_tampering(self, settings: Settings) -> None:
        from app.database.models import AuditEvent

        main(["demo", "seed"])
        with session_scope() as db:
            event = db.scalars(select(AuditEvent)).first()
            event.actor = "mallory"
        assert main(["verify-audit-trail"]) == 2


# =============================================================================
# Services
# =============================================================================


class TestServices:
    def test_alert_manager_includes_email_when_configured(self, settings: Settings, db) -> None:
        configured = settings.model_copy(update={"smtp_host": "smtp.example", "alert_email_to": "soc@corp.example"})
        manager = operations.build_alert_manager(db, configured)
        assert [r.channel.name for r in manager.routes] == ["log", "dashboard", "email"]
        assert manager.routes[-1].min_severity is Severity.HIGH
        demo_manager = operations.build_alert_manager(db, configured, is_demo=True)
        assert "email" not in [r.channel.name for r in demo_manager.routes]

    def test_alert_cooldown_uses_database(self, settings: Settings, db) -> None:
        from app.modules.alert_manager import alerts_from_findings

        finding = Finding(finding_id="X-1", title="Exposed", severity=Severity.HIGH, category="c", source="s")
        operations.build_alert_manager(db, settings).dispatch_many(alerts_from_findings([finding]))
        operations.build_alert_manager(db, settings).dispatch_many(alerts_from_findings([finding]))  # new process
        assert len(list(db.scalars(select(Alert)))) == 1
        zero = settings.model_copy(update={"alert_cooldown_minutes": 0})
        operations.build_alert_manager(db, zero).dispatch_many(alerts_from_findings([finding]))
        assert len(list(db.scalars(select(Alert)))) == 2

    def test_execute_scan_with_scope_error_fails_cleanly(self, settings: Settings, db) -> None:
        scan = operations.queue_network_scan(db, "t", ["8.8.8.8"], "quick")
        result = operations.execute_network_scan(db, settings, scan, ["8.8.8.8"], "quick", scanner_factory=FakeNmap)
        assert result.status == "failed" and "outside" in result.error
        with pytest.raises(ValueError):
            operations.queue_network_scan(db, "t", ["10.0.0.1"], "nope")

    def test_host_audit_failure_marks_scan_failed(self, settings: Settings, db, monkeypatch) -> None:
        from app.modules.system_auditor import auditor

        def boom(self):
            raise RuntimeError("disk on fire")

        monkeypatch.setattr(auditor.HostAuditor, "run", boom)
        with pytest.raises(RuntimeError):
            operations.run_host_audit(db, settings, "t")
        scans = operations._latest_scan(db, "host_audit")
        assert scans is None

    def test_sensor(self, settings: Settings, tmp_path: Path) -> None:
        summary = TrafficAnalyzer(source="live:test").summarize()
        calls = []

        def fake_capture(interface, duration, thresholds, iocs, max_packets):
            calls.append((interface, duration, max_packets))
            if len(calls) == 2:
                raise CaptureError("interface down")
            return summary

        sensor = Sensor(settings, capture=fake_capture)
        sensor._stop.wait = lambda timeout: None  # don't sleep on retry
        assert sensor.run_forever(max_windows=3) == 3
        assert calls[0] == (None, 60, settings.traffic_max_packets)
        with session_scope() as db:
            assert operations.latest_traffic(db).source == "live:test"
        sensor.stop()
        assert sensor.run_forever() == 0

    def test_demo_seed_and_purge(self, settings: Settings, db) -> None:
        assert not demo.has_demo_data(db)
        result = demo.seed_demo_data(db, settings)
        assert result["assets"] == 8 and demo.has_demo_data(db)
        backup = db.scalars(select(Asset).where(Asset.ip == "10.10.0.30")).first()
        assert [s.port for s in backup.services] == [22]  # stale services removed after "patch"
        resolved = db.scalars(
            select(FindingRecord).where(FindingRecord.asset == "10.10.0.30", FindingRecord.status == "resolved")
        ).all()
        assert resolved  # OpenSSH CVEs auto-resolved after upgrade
        again = demo.seed_demo_data(db, settings)  # idempotent: purges then reseeds
        assert again["assets"] == 8
        counts = demo.purge_demo_data(db)
        assert counts["assets"] == 8 and not demo.has_demo_data(db)

    def test_secrets_init(self, tmp_path: Path, monkeypatch) -> None:
        target = tmp_path / "secrets"
        first = init_secrets(target)
        assert first == {"jwt_secret": True, "admin_password": True, "db_password": True}
        jwt_value = (target / "jwt_secret").read_text()
        assert init_secrets(target) == {"jwt_secret": False, "admin_password": False, "db_password": False}
        assert (target / "jwt_secret").read_text() == jwt_value
        assert (target / "admin_password").stat().st_mode & 0o777 == 0o400
        assert (target / "db_password").stat().st_mode & 0o777 == 0o440
        chowned = []
        monkeypatch.setattr(os, "chown", lambda path, uid, gid: chowned.append((Path(path).name, uid, gid)))
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        init_secrets(tmp_path / "s2", app_owner="10001:10001", db_owner="70")
        assert ("db_password", 70, 10001) in chowned and ("jwt_secret", 10001, 10001) in chowned
        chowned.clear()
        init_secrets(tmp_path / "s3", app_owner="10001:10001")
        assert ("db_password", 0, 10001) in chowned and ("s3", 0, 10001) in chowned


# =============================================================================
# Repository & bootstrap
# =============================================================================


class TestRepository:
    def test_sync_findings_lifecycle(self, settings: Settings, db) -> None:
        a = Finding(finding_id="A", title="A", severity=Severity.HIGH, category="c", source="src", asset="h1")
        b = Finding(finding_id="B", title="B", severity=Severity.LOW, category="c", source="src", asset="h1")
        other = Finding(finding_id="C", title="C", severity=Severity.LOW, category="c", source="other", asset="h1")
        repository.sync_findings(db, findings=[other], source="other", assets_in_scope=["h1"])
        stats = repository.sync_findings(db, findings=[a, b], source="src", assets_in_scope=["h1"])
        assert stats == {"new": 2, "updated": 0, "resolved": 0, "reopened": 0}
        stats = repository.sync_findings(db, findings=[a], source="src", assets_in_scope=["h1"])
        assert stats == {"new": 0, "updated": 1, "resolved": 1, "reopened": 0}
        stats = repository.sync_findings(db, findings=[a, b], source="src", assets_in_scope=[])
        assert stats["reopened"] == 1
        assert len(repository.open_findings(db)) == 3  # other source untouched

    def test_trend_and_overview(self, settings: Settings, db) -> None:
        old = utcnow() - timedelta(days=5)
        f = Finding(finding_id="A", title="A", severity=Severity.CRITICAL, category="c", source="s", asset="h")
        repository.sync_findings(db, findings=[f], source="s", assets_in_scope=["h"], seen_at=old)
        repository.sync_findings(db, findings=[], source="s", assets_in_scope=["h"], seen_at=old + timedelta(days=2))
        trend = repository.findings_trend(db, days=7)
        assert [p["critical"] for p in trend] == [0, 1, 1, 0, 0, 0, 0]
        overview = repository.overview(db)
        assert overview["open_findings"] == 0 and overview["risk_score"] == 0.0

    def test_revocation_cleanup(self, settings: Settings, db) -> None:
        repository.revoke_token(db, "old", utcnow() - timedelta(minutes=1))
        repository.revoke_token(db, "new", utcnow() + timedelta(minutes=10))
        repository.revoke_token(db, "new", utcnow() + timedelta(minutes=10))
        assert repository.is_token_revoked(db, "new") and not repository.is_token_revoked(db, "old")

    def test_bootstrap_rejects_weak_configured_password(self, settings: Settings, db) -> None:
        weak = settings.model_copy(update={"admin_password": None, "admin_password_file": None})
        weak_pw = Settings(admin_password="weakpassword", data_dir=settings.data_dir)
        with pytest.raises(ValueError, match="policy"):
            bootstrap_admin(db, weak_pw)
        result = bootstrap_admin(db, weak)
        assert result.admin_created and result.password_file is not None
        assert db.scalars(select(User)).first().role == "admin"
        assert not bootstrap_admin(db, weak).admin_created


def test_sample_pcap_is_deterministic(tmp_path: Path) -> None:
    a = write_sample_pcap(tmp_path / "a.pcap").read_bytes()
    b = write_sample_pcap(tmp_path / "b.pcap").read_bytes()
    assert a == b
