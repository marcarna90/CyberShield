"""Passive traffic analysis (parsers, detections, PCAP, capture) and threat intelligence."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from app.modules.threat_intelligence import IOCDatabase, load_default_iocs
from app.modules.traffic_monitor import capture as cap
from app.modules.traffic_monitor.analyzer import (
    TrafficAnalyzer,
    TrafficThresholds,
    categorize,
    looks_like_dga,
    registered_domain,
    shannon_entropy,
)
from app.modules.traffic_monitor.packets import PacketRecord, from_scapy, parse_http_request, parse_tls_client_hello
from app.modules.traffic_monitor.synthetic import (
    baseline_packets,
    build_client_hello,
    exfiltration_records,
    incident_packets,
    write_sample_pcap,
)

START = 1_767_225_600.0
ETH = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


# =============================================================================
# Parsers
# =============================================================================


class TestParsers:
    def test_tls_client_hello(self) -> None:
        assert parse_tls_client_hello(build_client_hello("www.example.com")) == ("www.example.com", "TLS 1.3")
        assert parse_tls_client_hello(build_client_hello("old.example", 0x0301)) == ("old.example", "TLS 1.0")
        assert parse_tls_client_hello(build_client_hello(None, 0x0303)) == (None, "TLS 1.2")

    def test_tls_grease_and_malformed(self) -> None:
        hello = bytearray(build_client_hello("a.example"))
        assert parse_tls_client_hello(bytes(hello[:20])) is None
        assert parse_tls_client_hello(b"\x17" + bytes(hello[1:])) is None
        truncated = bytes(hello[:50])
        assert parse_tls_client_hello(truncated) in (None, (None, "TLS 1.2"))
        assert parse_tls_client_hello(bytes(hello[:44]) + b"\xff") is None

    def test_http_request(self) -> None:
        raw = b"POST /login?user=a&pw=b HTTP/1.1\r\nHOST: Portal.Example\r\nCookie: s=1\r\n\r\nuser=a&pw=b"
        assert parse_http_request(raw) == ("POST", "portal.example", "/login")
        assert parse_http_request(b"GET / HTTP/1.0\r\n\r\n") == ("GET", None, "/")
        assert parse_http_request(b"GET nothing\r\n") is None
        assert parse_http_request(b"\x16\x03\x01") is None

    def test_from_scapy_layers(self) -> None:
        dns = from_scapy(
            Ether(**ETH)
            / IP(src="10.0.0.2", dst="10.0.0.53")
            / UDP(sport=5353, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="Example.COM."))
        )
        assert dns.dns_query == "example.com" and not dns.dns_is_response and dns.transport == "UDP"
        nx = from_scapy(
            Ether(**ETH)
            / IP(src="10.0.0.53", dst="10.0.0.2")
            / UDP(sport=53, dport=5353)
            / DNS(qr=1, rcode=3, qd=DNSQR(qname="x.example"))
        )
        assert nx.dns_is_response and nx.dns_rcode == 3
        empty = from_scapy(Ether(**ETH) / IP(src="10.0.0.53", dst="10.0.0.2") / UDP(sport=53, dport=5353) / DNS(qd=[]))
        assert empty.dns_query is None
        arp = from_scapy(Ether(**ETH) / ARP(psrc="10.0.0.1", pdst="10.0.0.2"))
        assert arp.network == "ARP" and arp.src == "10.0.0.1"
        icmp = from_scapy(Ether(**ETH) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())
        assert icmp.transport == "ICMP"
        v6 = from_scapy(Ether(**ETH) / IPv6(src="fd00::1", dst="fd00::2") / TCP(sport=1234, dport=443, flags="S"))
        assert v6.network == "IPv6" and v6.tcp_flags == "S"
        http = from_scapy(
            Ether(**ETH)
            / IP(src="10.0.0.1", dst="192.0.2.1")
            / TCP(dport=80, flags="PA")
            / Raw(b"GET /a?b=c HTTP/1.1\r\nHost: h.example\r\n\r\n")
        )
        assert (http.http_method, http.http_host, http.http_path) == ("GET", "h.example", "/a")
        tls = from_scapy(
            Ether(**ETH)
            / IP(src="10.0.0.1", dst="192.0.2.1")
            / TCP(dport=443, flags="PA")
            / Raw(build_client_hello("s.example"))
        )
        assert tls.tls_sni == "s.example" and tls.tls_version == "TLS 1.3"
        other = from_scapy(Ether(**ETH) / Raw(b"x" * 20))
        assert other.network == "other"


# =============================================================================
# Analyzer
# =============================================================================


def rec(**kwargs) -> PacketRecord:
    base = {
        "timestamp": START,
        "length": 100,
        "network": "IPv4",
        "transport": "TCP",
        "src": "10.0.0.1",
        "dst": "192.0.2.1",
        "sport": 40000,
        "dport": 443,
    }
    base.update(kwargs)
    return PacketRecord(**base)


class TestAnalyzer:
    def test_full_incident_scenario(self) -> None:
        analyzer = TrafficAnalyzer(iocs=load_default_iocs(), source="test")
        for packet in baseline_packets(START) + incident_packets(START):
            analyzer.ingest(from_scapy(packet))
        analyzer.ingest_many(exfiltration_records(START + 420))
        summary = analyzer.summarize()
        ids = {f.finding_id for f in summary.anomalies}
        assert ids >= {
            "TRF-IOC-IP",
            "TRF-IOC-DOMAIN",
            "TRF-EXFIL",
            "TRF-PORTSCAN",
            "TRF-DNS-TUNNEL",
            "TRF-DGA",
            "TRF-NXDOMAIN",
            "TRF-LEGACY-TLS",
            "TRF-CLEARTEXT-HTTP",
            "TRF-SUSP-PORT",
            "TRF-SPIKE",
        }
        assert summary.health_score == 0.0
        assert summary.top_talkers[0]["ip"] == "10.10.0.13"
        assert summary.tls["versions"]["TLS 1.0"] == 1 and summary.http["requests"] == 1
        assert summary.http["top_hosts"][0]["host"] == "downloads.example.net"
        assert summary.severity_counts["critical"] >= 2
        assert summary.anomalies[0].severity.value == "critical"

    def test_baseline_is_healthy(self) -> None:
        summary = (
            TrafficAnalyzer(iocs=load_default_iocs())
            .ingest_many(from_scapy(p) for p in baseline_packets(START, duration=120))
            .summarize()
        )
        assert summary.anomalies == [] and summary.health_score == 100.0
        assert summary.protocols["TLS"] > 0 and summary.dns["queries"] > 0
        assert summary.duration_seconds > 100 and summary.trends

    def test_empty_capture(self) -> None:
        summary = TrafficAnalyzer().summarize()
        assert summary.total_packets == 0 and summary.trends == [] and summary.started_at is None

    def test_trend_downsampling(self) -> None:
        analyzer = TrafficAnalyzer(TrafficThresholds(bucket_seconds=1, max_trend_points=10))
        analyzer.ingest_many(rec(timestamp=START + i) for i in range(100))
        trends = analyzer.summarize().trends
        assert len(trends) == 10 and sum(p["packets"] for p in trends) == 100

    def test_inbound_ioc_and_thresholds(self) -> None:
        iocs = IOCDatabase()
        iocs.add("198.51.100.7")
        analyzer = TrafficAnalyzer(TrafficThresholds(large_transfer_bytes=1000), iocs)
        analyzer.ingest(rec(src="198.51.100.7", dst="10.0.0.9", sport=443, dport=50000))
        analyzer.ingest_many(rec(length=600) for _ in range(2))
        findings = analyzer.summarize().anomalies
        ioc = next(f for f in findings if f.finding_id == "TRF-IOC-IP")
        assert ioc.asset == "10.0.0.9"
        assert any(f.finding_id == "TRF-EXFIL" for f in findings)

    @pytest.mark.parametrize(
        "record,category",
        [
            (rec(network="ARP", transport="other"), "ARP"),
            (rec(transport="UDP", dport=53), "DNS"),
            (rec(http_method="GET", dport=8081), "HTTP"),
            (rec(tls_version="TLS 1.2", dport=8444), "TLS"),
            (rec(transport="ICMP", sport=None, dport=None), "ICMP"),
            (rec(transport="UDP", dport=443), "QUIC"),
            (rec(dport=22), "SSH"),
            (rec(dport=60000, sport=50000), "TCP-other"),
            (rec(network="other", transport="other", sport=None, dport=None), "other"),
        ],
    )
    def test_categorize(self, record: PacketRecord, category: str) -> None:
        assert categorize(record) == category

    def test_dns_heuristics(self) -> None:
        assert registered_domain("a.b.example.co.uk") == "example.co.uk"
        assert registered_domain("www.example.com.") == "example.com"
        assert shannon_entropy("") == 0.0 and shannon_entropy("aaaa") == 0.0
        assert looks_like_dga("q7x2k9v4m1z8r5t3.example")
        assert not looks_like_dga("stackoverflow.com")
        assert not looks_like_dga("short.example")

    def test_arp_and_missing_addresses_are_counted_only(self) -> None:
        analyzer = TrafficAnalyzer()
        analyzer.ingest(rec(network="ARP", transport="other"))
        analyzer.ingest(rec(src=None, dst=None, timestamp=0))
        summary = analyzer.summarize()
        assert summary.total_packets == 2 and summary.top_talkers == []


class TestPcapAndCapture:
    def test_pcap_roundtrip(self, tmp_path: Path) -> None:
        path = write_sample_pcap(tmp_path / "sample.pcap")
        summary = cap.analyze_pcap(path, iocs=load_default_iocs())
        assert summary.source == "pcap:sample.pcap" and summary.total_packets > 500
        assert {"TRF-IOC-IP", "TRF-PORTSCAN", "TRF-DNS-TUNNEL"} <= {f.finding_id for f in summary.anomalies}
        truncated = cap.analyze_pcap(path, max_packets=10)
        assert truncated.total_packets == 10

    def test_corrupt_pcap(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.pcap"
        bad.write_bytes(b"not a capture at all")
        with pytest.raises(cap.CaptureError):
            cap.analyze_pcap(bad)
        with pytest.raises(cap.CaptureError):
            cap.analyze_pcap(tmp_path / "missing.pcap")

    def test_live_capture_requires_privileges(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cap, "has_capture_privileges", lambda: False)
        with pytest.raises(cap.CaptureError, match="CAP_NET_RAW"):
            cap.live_capture("eth0", 1)

    def test_live_capture_with_mocked_sniffer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cap, "has_capture_privileges", lambda: True)
        packets = baseline_packets(START, duration=20)

        def fake_sniff(**kwargs):
            assert kwargs["store"] is False and kwargs["timeout"] == 5
            for packet in packets:
                kwargs["prn"](packet)

        monkeypatch.setattr(cap, "sniff", fake_sniff)
        summary = cap.live_capture("eth0", 5, bpf_filter="not port 22")
        assert summary.total_packets == len(packets) and summary.source == "live:eth0"

        def broken_sniff(**kwargs):
            raise OSError("No such device")

        monkeypatch.setattr(cap, "sniff", broken_sniff)
        with pytest.raises(cap.CaptureError, match="No such device"):
            cap.live_capture("nope0", 1)

    def test_privilege_detection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cap.os, "geteuid", lambda: 0)
        assert cap.has_capture_privileges()
        monkeypatch.setattr(cap.os, "geteuid", lambda: 1000)
        assert isinstance(cap.has_capture_privileges(), bool)

        def no_proc(*args, **kwargs):
            raise OSError

        monkeypatch.setattr("builtins.open", no_proc)
        assert cap.has_capture_privileges() is False


# =============================================================================
# Threat intelligence
# =============================================================================


class TestThreatIntel:
    def test_indicators_and_matching(self, tmp_path: Path) -> None:
        db = IOCDatabase()
        assert (
            db.load_lines(
                [
                    "# comment",
                    "",
                    "203.0.113.9,C2 server,feodo",
                    "198.51.100.0/30",
                    "Evil.Example.",
                    "2001:db8::/32",
                    "not an indicator!",
                    "bad/cidr/x",
                ]
            )
            == 4
        )
        assert db.match_ip("203.0.113.9").source == "feodo"
        assert db.match_ip("198.51.100.2").ioc_type == "network"
        assert db.match_ip("2001:db8::5") is not None
        assert db.match_ip("10.0.0.1") is None and db.match_ip("garbage") is None
        assert db.match_domain("a.b.evil.example").indicator == "evil.example"
        assert db.match_domain("notevil.example") is None
        assert db.lookup("evil.example")["malicious"] is True
        assert db.lookup("8.8.8.8") == {
            "indicator": "8.8.8.8",
            "classification": "public",
            "malicious": False,
            "match": None,
        }
        assert db.stats() == {"ips": 1, "networks": 2, "domains": 1} and len(db) == 4
        assert not db.add("  ")

    def test_default_and_extra_files(self, tmp_path: Path) -> None:
        extra = tmp_path / "mine.txt"
        extra.write_text("192.0.2.200\n")
        cache = tmp_path / "cache"
        cache.mkdir()
        (cache / "feed_0.txt").write_text("bad-cached.example\n")
        db = load_default_iocs([extra, tmp_path / "missing.txt"], cache)
        assert db.match_ip("203.0.113.66") and db.match_ip("192.0.2.200")
        assert db.match_domain("bad-cached.example").source == "cached:feed_0"

    def test_feed_refresh(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "broken" in str(request.url):
                return httpx.Response(500)
            return httpx.Response(200, text="# feed\n203.0.113.77\nbad.feed.example\n")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        db = IOCDatabase()
        results = db.refresh_from_feeds(
            ["https://feeds.example/ok.txt", "http://insecure.example/x", "https://feeds.example/broken"],
            tmp_path / "cache",
            client=client,
        )
        assert results == {
            "https://feeds.example/ok.txt": 2,
            "http://insecure.example/x": -1,
            "https://feeds.example/broken": -1,
        }
        assert (tmp_path / "cache" / "feed_0.txt").exists() and db.match_ip("203.0.113.77")

    def test_feed_refresh_with_own_client(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(200, text="203.0.113.88\n"))
        original = httpx.Client
        monkeypatch.setattr(httpx, "Client", lambda **kw: original(transport=transport, **kw))
        assert IOCDatabase().refresh_from_feeds(["https://f.example/a"], tmp_path) == {"https://f.example/a": 1}
