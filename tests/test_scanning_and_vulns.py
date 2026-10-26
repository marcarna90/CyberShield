"""Network scanner (Nmap wrapper) and vulnerability analyzer (versions, CVE DB, NVD import, exposure)."""

from __future__ import annotations

import http.server
import json
import shutil
import threading
from pathlib import Path

import nmap
import pytest

from app.core.models import Severity
from app.core.scope import ScopeError, TargetScope
from app.modules.network_scanner import SCAN_PROFILES, NetworkScanner, ScanError, parse_nmap_result
from app.modules.network_scanner.scanner import DiscoveredAsset, DiscoveredService, ip_sort_key
from app.modules.vulnerability_analyzer import (
    CVEDatabase,
    CVERecord,
    VulnerabilityAnalyzer,
    compare_versions,
    extract_version,
    load_cve_database,
    parse_nvd_feed,
    version_in_range,
)
from app.modules.vulnerability_analyzer.analyzer import identify_components
from tests.conftest import SAMPLE_NMAP, FakeNmap

PRIVATE = TargetScope(["10.0.0.0/8", "127.0.0.0/8"])


# =============================================================================
# Network scanner
# =============================================================================


class TestNetworkScanner:
    def test_parse_result(self) -> None:
        assets = parse_nmap_result(SAMPLE_NMAP)
        assert [a.ip for a in assets] == ["10.0.0.5", "10.0.0.6"]  # numeric order
        web = assets[0]
        assert web.hostname == "web.lab.example" and web.vendor == "Acme Networks" and web.os_guess == "Linux 5.4"
        assert [s.port for s in web.services] == [22, 80]  # closed 443 dropped
        assert web.services[0].cpe == "cpe:/a:openbsd:openssh:8.9p1"
        assert parse_nmap_result({}) == []

    def test_cpe_list_and_sort_key(self) -> None:
        raw = {
            "scan": {
                "10.0.0.1": {
                    "addresses": {},
                    "tcp": {80: {"state": "open", "cpe": ["cpe:/a:x:y:1", "z"]}},
                    "udp": {53: {"state": "open|filtered", "name": "domain", "cpe": []}},
                }
            }
        }
        asset = parse_nmap_result(raw)[0]
        assert asset.ip == "10.0.0.1" and asset.services[0].cpe == "cpe:/a:x:y:1" and asset.services[1].cpe == ""
        assert ip_sort_key("garbage")[0] == 9
        assert ip_sort_key("10.0.0.2") < ip_sort_key("10.0.0.10")

    def test_scan_uses_validated_targets_and_fixed_profiles(self) -> None:
        fake = FakeNmap()
        result = NetworkScanner(PRIVATE, "2m", lambda: fake).scan(["10.0.0.0/29", "10.0.0.5"], "standard")
        hosts, arguments = fake.calls[0]
        assert hosts == "10.0.0.0/29 10.0.0.5"
        assert arguments == SCAN_PROFILES["standard"].arguments + " --host-timeout 2m"
        assert result.hosts_up == 2 and result.hosts_total == 8 and len(result.assets) == 2

    def test_scope_and_profile_enforced(self) -> None:
        scanner = NetworkScanner(PRIVATE, scanner_factory=FakeNmap)
        with pytest.raises(ScopeError):
            scanner.scan(["8.8.8.8"])
        with pytest.raises(ValueError, match="Unknown scan profile"):
            scanner.scan(["10.0.0.1"], "aggressive")

    def test_nmap_errors(self) -> None:
        failing = NetworkScanner(PRIVATE, scanner_factory=lambda: FakeNmap(error=nmap.PortScannerError("boom")))
        with pytest.raises(ScanError, match="boom"):
            failing.scan(["10.0.0.1"])
        reported = NetworkScanner(PRIVATE, scanner_factory=lambda: FakeNmap({"nmap": {"scaninfo": {"error": ["x"]}}}))
        with pytest.raises(ScanError):
            reported.scan(["10.0.0.1"])

    def test_missing_nmap_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def missing():
            raise nmap.PortScannerError("nmap program was not found in path")

        monkeypatch.setattr(nmap, "PortScanner", missing)
        with pytest.raises(ScanError, match="not installed"):
            NetworkScanner(PRIVATE).scan(["10.0.0.1"])

    @pytest.mark.integration
    @pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed")
    def test_real_nmap_against_local_http_server(self) -> None:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            scanner = NetworkScanner(TargetScope(["127.0.0.0/8"]), "60s")
            scanner_args = SCAN_PROFILES["quick"]
            assert "-sT" in scanner_args.arguments
            raw = nmap.PortScanner().scan(hosts="127.0.0.1", arguments=f"-sT -sV -p {port} --host-timeout 60s")
            assets = parse_nmap_result(raw)
            service = assets[0].services[0]
            assert service.port == port and "http" in service.name
            assert scanner.scan(["127.0.0.1"], "discovery").hosts_up == 1
        finally:
            server.shutdown()


# =============================================================================
# Versions
# =============================================================================


class TestVersions:
    @pytest.mark.parametrize(
        "left,right,expected",
        [
            ("2.4.49", "2.4.5", 1),
            ("8.9p1", "9.8p1", -1),
            ("9.8", "9.8p1", -1),
            ("9.8p1", "9.8p1", 0),
            ("1.0.1f", "1.0.1g", -1),
            ("1.0.1", "1.0.1f", -1),
            ("9.0.0.M1", "9.0.0", -1),
            ("1.0rc1", "1.0", -1),
            ("1.0", "1.0.0", 0),
            ("1.20.0", "1.18.0", 1),
            ("7.4", "7.7", -1),
            ("1.0.1.1", "1.0.1f", 1),
        ],
    )
    def test_compare(self, left: str, right: str, expected: int) -> None:
        assert compare_versions(left, right) == expected

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("8.9p1 Ubuntu 3ubuntu0.6", "8.9p1"),
            ("1.18.0 (Ubuntu)", "1.18.0"),
            ("v2.4.49", "2.4.49"),
            ("4.5.9-Debian", "4.5.9"),
            ("3.X - 4.X", None),
            ("", None),
            (None, None),
            ("unknown", None),
        ],
    )
    def test_extract(self, raw: str | None, expected: str | None) -> None:
        assert extract_version(raw) == expected

    def test_ranges(self) -> None:
        assert version_in_range("8.9p1", start_including="8.5p1", end_excluding="9.8p1")
        assert not version_in_range("9.8p1", start_including="8.5p1", end_excluding="9.8p1")
        assert not version_in_range("8.4p1", start_including="8.5p1", end_excluding="9.8p1")
        assert version_in_range("4.91", start_excluding="4.86", end_including="4.91")
        assert not version_in_range("4.86", start_excluding="4.86")
        assert not version_in_range("4.92", end_including="4.91")
        assert version_in_range("2.4.49", exact=["2.4.49", "2.4.50"])
        assert not version_in_range("1.0")


# =============================================================================
# CVE database
# =============================================================================

NVD_SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2099-0001",
                "published": "2099-01-02T00:00:00.000",
                "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Sample overflow."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"type": "Secondary", "cvssData": {"baseScore": 5.0}},
                        {"type": "Primary", "cvssData": {"baseScore": 9.1}},
                    ]
                },
                "references": [{"url": "https://example.org/a"}, {}],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "1.0",
                                        "versionEndExcluding": "1.5",
                                    },
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:7.2:p2:*:*:*:*:*:*"},
                                    {"vulnerable": True, "criteria": "cpe:2.3:a:acme:any:*:*:*:*:*:*:*:*"},
                                    {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
                                    {"vulnerable": True, "criteria": "cpe:2.3:o:acme:os:1.0:*:*:*:*:*:*:*"},
                                ]
                            }
                        ]
                    }
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2099-0002",
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 4.3}}]},
                "configurations": [],
            }
        },
        {
            "cve": {
                "id": "BAD-ID",
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"}]}]}
                ],
            }
        },
    ]
}


class TestCVEDatabase:
    def test_sample_database_loads(self) -> None:
        db = load_cve_database()
        assert len(db) >= 15 and ("openbsd", "openssh") in db.products()
        ids = [r.cve_id for r, _ in db.lookup("openbsd", "openssh", "8.9p1")]
        assert "CVE-2024-6387" in ids and "CVE-2018-15473" not in ids
        assert [r.cve_id for r, _ in db.lookup("openbsd", "openssh", "9.8p1")] == []
        assert db.lookup("igor_sysoev", "nginx", "1.18.0")[0][0].cve_id == "CVE-2021-23017"  # vendor alias

    def test_product_only_fallback_but_not_for_generic_products(self) -> None:
        db = load_cve_database()
        assert db.lookup("vsftpd", "vsftpd", "2.3.4")[0][0].cve_id == "CVE-2011-2523"
        assert db.lookup("unknown_vendor", "http_server", "2.4.49") == []

    def test_parse_nvd_feed(self) -> None:
        records = parse_nvd_feed(NVD_SAMPLE)
        widget = next(r for r in records if r.product == "widget")
        assert widget.cvss == 9.1 and widget.severity is Severity.CRITICAL and widget.fixed_version == "1.5"
        assert widget.description == "Sample overflow." and widget.published == "2099-01-02"
        assert widget.references == ["https://example.org/a"]
        ssh = next(r for r in records if r.product == "openssh")
        assert ssh.affected[0].versions == ["7.2p2"]
        assert all(r.cve_id != "BAD-ID" for r in records)
        assert not any(r.product in ("any", "linux_kernel", "os") for r in records)

    def test_merge_save_and_reload(self, tmp_path: Path) -> None:
        feed = tmp_path / "nvd.json"
        feed.write_text(json.dumps(NVD_SAMPLE))
        db = CVEDatabase()
        assert db.merge_file(feed) == 2
        target = tmp_path / "out" / "cve_db.json"
        db.save(target)
        reloaded = load_cve_database(target)
        assert reloaded.lookup("acme", "widget", "1.2")[0][0].cve_id == "CVE-2099-0001"
        assert reloaded.lookup("acme", "widget", "1.5") == []

    def test_record_helpers(self) -> None:
        record = CVERecord.model_validate(
            {
                "cve_id": "CVE-2099-1234",
                "vendor": "F5",
                "product": "NGINX",
                "affected": [{"version_start_excluding": "1.0", "version_end_including": "2.0"}],
            }
        )
        assert record.affected[0].describe() == "> 1.0 and <= 2.0"
        assert record.matching_range("3.0") is None
        assert record.severity is Severity.INFO
        db = CVEDatabase([record])
        assert db.products() == [("nginx", "nginx")]
        with pytest.raises(ValueError):
            CVERecord(cve_id="not-a-cve", vendor="x", product="y")


# =============================================================================
# Analyzer
# =============================================================================


def _asset(ip: str, *services: DiscoveredService) -> DiscoveredAsset:
    return DiscoveredAsset(ip=ip, services=list(services))


class TestVulnerabilityAnalyzer:
    analyzer = VulnerabilityAnalyzer(load_cve_database())

    def test_sample_scan(self) -> None:
        report = self.analyzer.analyze(parse_nmap_result(SAMPLE_NMAP))
        by_id = {(f.finding_id, f.asset) for f in report.findings}
        for expected in ("CVE-2021-41773", "CVE-2021-42013", "CVE-2014-0160", "CVE-2024-6387", "EXP-HTTP-NOTLS"):
            assert (expected, "10.0.0.5") in by_id, expected
        assert ("EXP-TELNET", "10.0.0.6") in by_id
        regre = next(f for f in report.findings if f.finding_id == "CVE-2024-6387")
        assert regre.confidence == "medium" and "backported" in regre.recommendation
        heartbleed = next(f for f in report.findings if f.finding_id == "CVE-2014-0160")
        assert heartbleed.port == 80 and "1.0.1g" in heartbleed.recommendation
        assert report.findings[0].severity is Severity.CRITICAL
        assert report.assets_analyzed == 2 and report.services_analyzed == 3
        assert report.asset_risk[0]["ip"] == "10.0.0.5"
        assert report.recommendations["patching"] and report.recommendations["best_practices"]
        assert any("Telnet" in r for r in report.recommendations["configuration_hardening"])

    @pytest.mark.parametrize(
        "service,rule",
        [
            (DiscoveredService(port=2375, name="docker"), "EXP-DOCKER"),
            (DiscoveredService(port=6380, name="redis"), "EXP-REDIS"),
            (DiscoveredService(port=27017, name="mongod"), "EXP-MONGODB"),
            (DiscoveredService(port=9200, name="http", product="Elasticsearch REST API"), "EXP-ELASTIC"),
            (DiscoveredService(port=3389, name="ms-wbt-server"), "EXP-RDP"),
            (DiscoveredService(port=5901, name="vnc"), "EXP-VNC"),
            (DiscoveredService(port=445, name="microsoft-ds"), "EXP-SMB"),
            (DiscoveredService(port=2121, name="ftp", product="ProFTPD", version="1.3.5"), "EXP-FTP"),
            (DiscoveredService(port=5432, name="postgresql"), "EXP-DATABASE"),
        ],
    )
    def test_exposure_rules(self, service: DiscoveredService, rule: str) -> None:
        ids = {f.finding_id for f in self.analyzer.analyze([_asset("10.0.0.9", service)]).findings}
        assert rule in ids

    def test_https_present_suppresses_http_finding(self) -> None:
        asset = _asset("10.0.0.9", DiscoveredService(port=80, name="http"), DiscoveredService(port=443, name="https"))
        assert "EXP-HTTP-NOTLS" not in {f.finding_id for f in self.analyzer.analyze([asset]).findings}

    def test_component_identification(self) -> None:
        svc = DiscoveredService(
            port=443,
            name="https",
            product="Apache httpd",
            version="2.4.58",
            extrainfo="(Debian) OpenSSL/3.0.2 PHP/8.2.7",
        )
        components = identify_components(svc)
        assert ("apache", "http_server", "2.4.58", "Apache HTTP Server") in components
        assert ("openssl", "openssl", "3.0.2", "OpenSSL") in components
        assert ("php", "php", "8.2.7", "PHP") in components
        assert identify_components(DiscoveredService(port=1, product="Mystery", version="1.0")) == []
        no_version = DiscoveredService(port=22, product="OpenSSH", cpe="cpe:/a:openbsd:openssh")
        assert identify_components(no_version) == []
        heartbleed_ids = {f.finding_id for f in self.analyzer.analyze([_asset("10.0.0.2", svc)]).findings}
        assert "CVE-2022-3602" in heartbleed_ids  # OpenSSL 3.0.2 is in 3.0.0-3.0.6

    def test_clean_host_has_no_findings(self) -> None:
        clean = _asset("10.0.0.3", DiscoveredService(port=22, name="ssh", product="OpenSSH", version="9.8p1"))
        report = self.analyzer.analyze([clean])
        assert report.findings == [] and report.risk_score == 0.0
        assert any("SSH" in r for r in report.recommendations["configuration_hardening"])
