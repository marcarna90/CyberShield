"""Streaming traffic analytics and anomaly detection.

The analyzer consumes :class:`PacketRecord` objects one at a time with bounded
memory, then produces a :class:`TrafficSummary`: protocol mix, top talkers,
DNS/HTTP/TLS statistics, per-interval trends, anomalies (as findings) and a
network health score.

Detection heuristics (all thresholds configurable):

* communication with IOC-listed IPs/domains (threat intelligence)
* TCP SYN port-scan patterns
* large outbound transfers (internal -> external)
* traffic spikes vs. median baseline
* DGA-like and tunnelling-like DNS activity, high NXDOMAIN ratio
* legacy TLS (SSL 3.0 / TLS 1.0 / 1.1) and cleartext HTTP to the Internet
* connections to ports commonly used by malware / backdoors
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.models import Finding, Severity, severity_counts, sort_findings
from app.core.netutils import is_internal
from app.modules.threat_intelligence.intel import IOCDatabase
from app.modules.traffic_monitor.packets import PacketRecord

SOURCE = "traffic_monitor"

PORT_CATEGORIES = {
    22: "SSH",
    25: "SMTP",
    465: "SMTP",
    587: "SMTP",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    8080: "HTTP",
    123: "NTP",
    139: "SMB",
    445: "SMB",
    161: "SNMP",
    162: "SNMP",
    443: "TLS",
    8443: "TLS",
    993: "TLS",
    1900: "SSDP",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    5432: "PostgreSQL",
}
SUSPICIOUS_PORTS = {
    23: "Telnet",
    2323: "Telnet alternate (IoT botnets)",
    4444: "Metasploit default handler",
    5555: "Android Debug Bridge",
    1337: "Common backdoor port",
    31337: "Back Orifice / backdoor",
    6667: "IRC (botnet C2)",
    6697: "IRC over TLS (botnet C2)",
    9001: "Tor relay (default ORPort)",
    9050: "Tor SOCKS proxy",
}
LEGACY_TLS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu"}
_PENALTY = {Severity.CRITICAL: 25, Severity.HIGH: 12, Severity.MEDIUM: 5, Severity.LOW: 2, Severity.INFO: 0}


@dataclass
class TrafficThresholds:
    large_transfer_bytes: int = 50 * 1024 * 1024
    spike_factor: float = 3.0
    spike_min_bytes: int = 256 * 1024
    portscan_threshold: int = 25
    bucket_seconds: int = 10
    dga_min_length: int = 12
    dga_min_entropy: float = 3.3
    tunnel_unique_subdomains: int = 50
    tunnel_qname_length: int = 100
    nxdomain_ratio: float = 0.3
    nxdomain_min_responses: int = 20
    max_trend_points: int = 360


class TrafficSummary(BaseModel):
    source: str
    started_at: datetime | None
    ended_at: datetime | None
    duration_seconds: float
    total_packets: int
    total_bytes: int
    protocols: dict[str, int]
    protocol_bytes: dict[str, int]
    top_talkers: list[dict[str, Any]]
    top_destinations: list[dict[str, Any]]
    top_ports: list[dict[str, Any]]
    dns: dict[str, Any]
    http: dict[str, Any]
    tls: dict[str, Any]
    trends: list[dict[str, Any]]
    anomalies: list[Finding] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    health_score: float = Field(100.0, ge=0, le=100)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values())


def registered_domain(name: str) -> str:
    labels = name.lower().rstrip(".").split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def looks_like_dga(name: str, min_length: int = 12, min_entropy: float = 3.3) -> bool:
    """Heuristic: long, high-entropy registered label with many digits or few vowels."""
    label = registered_domain(name).split(".")[0]
    if len(label) < min_length:
        return False
    digits = sum(c.isdigit() for c in label) / len(label)
    vowels = sum(c in "aeiou" for c in label) / len(label)
    return shannon_entropy(label) >= min_entropy and (digits >= 0.2 or vowels <= 0.2)


def categorize(record: PacketRecord) -> str:
    if record.network == "ARP":
        return "ARP"
    if record.dns_query is not None or 53 in (record.sport, record.dport):
        return "DNS"
    if record.http_method:
        return "HTTP"
    if record.tls_version:
        return "TLS"
    if record.transport == "ICMP":
        return "ICMP"
    if record.transport == "UDP" and 443 in (record.sport, record.dport):
        return "QUIC"
    for port in (record.dport, record.sport):
        if port in PORT_CATEGORIES:
            return PORT_CATEGORIES[port]
    return f"{record.transport}-other" if record.transport != "other" else "other"


def _ts(value: float | None) -> datetime | None:
    return datetime.fromtimestamp(value, tz=UTC) if value else None


class TrafficAnalyzer:
    """Incremental, bounded-memory traffic analyzer."""

    _MAX_TRACKED = 50_000

    def __init__(
        self,
        thresholds: TrafficThresholds | None = None,
        iocs: IOCDatabase | None = None,
        source: str = "capture",
    ) -> None:
        self.t = thresholds or TrafficThresholds()
        self.iocs = iocs or IOCDatabase()
        self.source = source
        self.packets = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.proto_packets: Counter[str] = Counter()
        self.proto_bytes: Counter[str] = Counter()
        self.talker_bytes: Counter[str] = Counter()
        self.talker_packets: Counter[str] = Counter()
        self.dest_bytes: Counter[str] = Counter()
        self.port_packets: Counter[tuple[str, int]] = Counter()
        self.outbound: Counter[tuple[str, str]] = Counter()
        self.syn_probes: dict[str, set[tuple[str, int]]] = defaultdict(set)
        self.dns_queries: Counter[str] = Counter()
        self.dns_first_client: dict[str, str] = {}
        self.dns_responses = 0
        self.dns_nxdomain = 0
        self.dns_subdomains: dict[str, set[str]] = defaultdict(set)
        self.long_qnames: dict[str, str] = {}
        self.http_hosts: Counter[str] = Counter()
        self.http_methods: Counter[str] = Counter()
        self.cleartext_external: set[tuple[str, str]] = set()
        self.tls_versions: Counter[str] = Counter()
        self.tls_sni: Counter[str] = Counter()
        self.legacy_tls: set[tuple[str, str, str]] = set()
        self.buckets: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        self.ioc_ip_hits: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
        self.ioc_domain_hits: dict[tuple[str, str], str] = {}
        self.suspicious_ports: set[tuple[str, str, int]] = set()

    # ---------------------------------------------------------------- ingest
    def ingest(self, rec: PacketRecord) -> None:
        self.packets += 1
        self.bytes += rec.length
        if rec.timestamp:
            self.first_ts = rec.timestamp if self.first_ts is None else min(self.first_ts, rec.timestamp)
            self.last_ts = rec.timestamp if self.last_ts is None else max(self.last_ts, rec.timestamp)
            bucket = self.buckets[int(rec.timestamp // self.t.bucket_seconds)]
            bucket[0] += 1
            bucket[1] += rec.length
        category = categorize(rec)
        self.proto_packets[category] += 1
        self.proto_bytes[category] += rec.length
        if rec.src is None or rec.dst is None or rec.network == "ARP":
            return
        self.talker_bytes[rec.src] += rec.length
        self.talker_packets[rec.src] += 1
        self.dest_bytes[rec.dst] += rec.length
        if rec.dport is not None:
            self.port_packets[(rec.transport, min(rec.dport, rec.sport or rec.dport))] += 1
        src_internal, dst_internal = is_internal(rec.src), is_internal(rec.dst)
        if src_internal and not dst_internal:
            self.outbound[(rec.src, rec.dst)] += rec.length
        self._threat_intel(rec, src_internal, dst_internal)
        self._tcp_patterns(rec, dst_internal)
        self._dns(rec)
        self._application(rec, dst_internal)

    def ingest_many(self, records: Iterable[PacketRecord]) -> TrafficAnalyzer:
        for record in records:
            self.ingest(record)
        return self

    def _threat_intel(self, rec: PacketRecord, src_internal: bool, dst_internal: bool) -> None:
        for remote, local in ((rec.dst, rec.src), (rec.src, rec.dst)):
            if remote and local and self.iocs.match_ip(remote) is not None:
                hit = self.ioc_ip_hits[(remote, local)]
                hit[0] += 1
                hit[1] += rec.length
                break

    def _tcp_patterns(self, rec: PacketRecord, dst_internal: bool) -> None:
        if rec.transport != "TCP" or rec.dport is None:
            return
        if rec.tcp_flags == "S":
            probes = self.syn_probes[rec.src]  # type: ignore[index]
            if len(probes) < self.t.portscan_threshold * 4:
                probes.add((rec.dst, rec.dport))  # type: ignore[arg-type]
            if rec.dport in SUSPICIOUS_PORTS and len(self.suspicious_ports) < self._MAX_TRACKED:
                self.suspicious_ports.add((rec.src, rec.dst, rec.dport))  # type: ignore[arg-type]

    def _dns(self, rec: PacketRecord) -> None:
        if rec.dns_query is None:
            return
        name = rec.dns_query
        if rec.dns_is_response:
            self.dns_responses += 1
            if rec.dns_rcode == 3:
                self.dns_nxdomain += 1
            return
        if len(self.dns_queries) < self._MAX_TRACKED or name in self.dns_queries:
            self.dns_queries[name] += 1
            self.dns_first_client.setdefault(name, rec.src or "unknown")
        parent = registered_domain(name)
        subs = self.dns_subdomains[parent]
        if len(subs) <= self.t.tunnel_unique_subdomains * 2:
            subs.add(name)
        if len(name) >= self.t.tunnel_qname_length:
            self.long_qnames.setdefault(parent, rec.src or "unknown")
        ioc = self.iocs.match_domain(name)
        if ioc is not None:
            self.ioc_domain_hits.setdefault((name, rec.src or "unknown"), f"DNS query ({ioc.description})")

    def _application(self, rec: PacketRecord, dst_internal: bool) -> None:
        if rec.http_method:
            host = rec.http_host or rec.dst or "unknown"
            self.http_hosts[host] += 1
            self.http_methods[rec.http_method] += 1
            if not dst_internal and len(self.cleartext_external) < self._MAX_TRACKED:
                self.cleartext_external.add((rec.src or "unknown", host))
            ioc = self.iocs.match_domain(host)
            if ioc is not None:
                self.ioc_domain_hits.setdefault((host, rec.src or "unknown"), f"HTTP request ({ioc.description})")
        if rec.tls_version:
            self.tls_versions[rec.tls_version] += 1
            if rec.tls_sni:
                self.tls_sni[rec.tls_sni] += 1
                ioc = self.iocs.match_domain(rec.tls_sni)
                if ioc is not None:
                    self.ioc_domain_hits.setdefault(
                        (rec.tls_sni, rec.src or "unknown"), f"TLS connection ({ioc.description})"
                    )
            if rec.tls_version in LEGACY_TLS and len(self.legacy_tls) < self._MAX_TRACKED:
                self.legacy_tls.add((rec.src or "unknown", rec.tls_sni or rec.dst or "unknown", rec.tls_version))

    # -------------------------------------------------------------- results
    def _finding(
        self,
        finding_id: str,
        title: str,
        severity: Severity,
        asset: str,
        evidence: str,
        recommendation: str,
        description: str = "",
    ) -> Finding:
        return Finding(
            finding_id=finding_id,
            title=title,
            severity=severity,
            category="traffic",
            source=SOURCE,
            asset=asset,
            description=description or title,
            evidence=evidence[:2000],
            recommendation=recommendation,
        )

    def _trend_points(self) -> list[dict[str, Any]]:
        if not self.buckets:
            return []
        keys = sorted(self.buckets)
        step = max(1, math.ceil(len(keys) / self.t.max_trend_points))
        points = []
        for i in range(0, len(keys), step):
            chunk = keys[i : i + step]
            points.append(
                {
                    "ts": datetime.fromtimestamp(chunk[0] * self.t.bucket_seconds, tz=UTC).isoformat(),
                    "packets": sum(self.buckets[k][0] for k in chunk),
                    "bytes": sum(self.buckets[k][1] for k in chunk),
                }
            )
        return points

    def detect_anomalies(self) -> list[Finding]:
        findings: list[Finding] = []
        for (remote, local), (packets, size) in self.ioc_ip_hits.items():
            ioc = self.iocs.match_ip(remote)
            if ioc is None:  # IOC list reloaded since ingestion
                continue
            findings.append(
                self._finding(
                    "TRF-IOC-IP",
                    f"Communication with known malicious IP {remote}",
                    Severity.CRITICAL,
                    local,
                    f"{packets} packets / {size} bytes exchanged with {remote} (IOC {ioc.indicator}, "
                    f"source {ioc.source}: {ioc.description})",
                    "Isolate the host, block the indicator at the perimeter, and start incident response "
                    "(collect volatile evidence before remediation).",
                )
            )
        for (domain, client), context in self.ioc_domain_hits.items():
            findings.append(
                self._finding(
                    "TRF-IOC-DOMAIN",
                    f"Access to known malicious domain {domain}",
                    Severity.HIGH,
                    client,
                    f"{context} from {client}",
                    "Sinkhole/block the domain in DNS, investigate the client for compromise and reset exposed "
                    "credentials.",
                )
            )
        for src, probes in self.syn_probes.items():
            if len(probes) >= self.t.portscan_threshold:
                targets = sorted({dst for dst, _ in probes})
                findings.append(
                    self._finding(
                        "TRF-PORTSCAN",
                        f"Possible port scan from {src}",
                        Severity.HIGH,
                        src,
                        f"{len(probes)}+ distinct SYN probes to {len(targets)} host(s): {', '.join(targets[:10])}",
                        "Confirm whether the scan is authorised; if not, block the source and investigate the host.",
                    )
                )
        for (src, dst), size in self.outbound.most_common():
            if size < self.t.large_transfer_bytes:
                break
            findings.append(
                self._finding(
                    "TRF-EXFIL",
                    f"Large outbound transfer from {src} to {dst}",
                    Severity.HIGH,
                    src,
                    f"{size / 1_048_576:.1f} MB sent to external address {dst}",
                    "Verify the transfer is business-justified (backup, update). Otherwise treat as potential "
                    "data exfiltration: block the destination and review the host.",
                )
            )
        spike = self._spike()
        if spike:
            findings.append(spike)
        findings.extend(self._dns_findings())
        if self.legacy_tls:
            sample = sorted(self.legacy_tls)[:10]
            clients = sorted({c for c, _, _ in self.legacy_tls})
            findings.append(
                self._finding(
                    "TRF-LEGACY-TLS",
                    "Legacy TLS/SSL protocol in use",
                    Severity.MEDIUM,
                    clients[0],
                    "; ".join(f"{c} -> {s} ({v})" for c, s, v in sample),
                    "Disable SSL 3.0/TLS 1.0/1.1 on clients and servers; require TLS 1.2+ (RFC 8996).",
                )
            )
        if self.cleartext_external:
            clients = sorted({c for c, _ in self.cleartext_external})
            hosts = sorted({h for _, h in self.cleartext_external})
            findings.append(
                self._finding(
                    "TRF-CLEARTEXT-HTTP",
                    "Cleartext HTTP to Internet hosts",
                    Severity.LOW,
                    clients[0],
                    f"{len(self.cleartext_external)} client/host pairs, e.g. {', '.join(hosts[:10])}",
                    "Enforce HTTPS (HSTS, browser policies, egress proxy) to protect data in transit.",
                )
            )
        for src, dst, port in sorted(self.suspicious_ports)[:20]:
            findings.append(
                self._finding(
                    "TRF-SUSP-PORT",
                    f"Connection attempt to suspicious port {port}",
                    Severity.MEDIUM,
                    src,
                    f"{src} -> {dst}:{port} ({SUSPICIOUS_PORTS[port]})",
                    "Identify the process initiating the connection; block the port at the egress firewall if unused.",
                )
            )
        return sort_findings(findings)

    def _spike(self) -> Finding | None:
        if len(self.buckets) < 6:
            return None
        volumes = [b[1] for b in self.buckets.values()]
        baseline = statistics.median(volumes)
        peak_key = max(self.buckets, key=lambda k: self.buckets[k][1])
        peak = self.buckets[peak_key][1]
        if baseline <= 0 or peak < self.t.spike_min_bytes or peak < self.t.spike_factor * baseline:
            return None
        at = datetime.fromtimestamp(peak_key * self.t.bucket_seconds, tz=UTC).isoformat()
        return self._finding(
            "TRF-SPIKE",
            "Unexpected traffic spike",
            Severity.MEDIUM,
            "network",
            f"{peak} bytes in {self.t.bucket_seconds}s at {at} = {peak / baseline:.1f}x the median baseline "
            f"({int(baseline)} bytes)",
            "Correlate with top talkers at that time; check for DoS, misbehaving jobs or exfiltration.",
        )

    def _dns_findings(self) -> list[Finding]:
        findings = []
        dga = [n for n in self.dns_queries if looks_like_dga(n, self.t.dga_min_length, self.t.dga_min_entropy)]
        if dga:
            client = self.dns_first_client.get(dga[0], "unknown")
            findings.append(
                self._finding(
                    "TRF-DGA",
                    "Algorithmically generated (DGA-like) domain lookups",
                    Severity.MEDIUM,
                    client,
                    f"{len(dga)} high-entropy domain(s): {', '.join(sorted(dga)[:10])}",
                    "Inspect the querying hosts for malware; enable DNS filtering / RPZ.",
                )
            )
        for parent, subs in self.dns_subdomains.items():
            if len(subs) >= self.t.tunnel_unique_subdomains or parent in self.long_qnames:
                findings.append(
                    self._finding(
                        "TRF-DNS-TUNNEL",
                        f"Possible DNS tunnelling via {parent}",
                        Severity.HIGH,
                        self.long_qnames.get(parent) or self.dns_first_client.get(next(iter(subs)), "unknown"),
                        f"{len(subs)} unique sub-domains queried under {parent}"
                        + (" with very long query names" if parent in self.long_qnames else ""),
                        "Block the domain, inspect the client, and restrict DNS egress to internal resolvers only.",
                    )
                )
        if (
            self.dns_responses >= self.t.nxdomain_min_responses
            and self.dns_nxdomain / self.dns_responses >= self.t.nxdomain_ratio
        ):
            findings.append(
                self._finding(
                    "TRF-NXDOMAIN",
                    "High rate of failed DNS resolutions (NXDOMAIN)",
                    Severity.MEDIUM,
                    "network",
                    f"{self.dns_nxdomain}/{self.dns_responses} responses were NXDOMAIN",
                    "Investigate clients generating failed lookups (DGA malware, misconfiguration).",
                )
            )
        return findings

    def summarize(self) -> TrafficSummary:
        anomalies = self.detect_anomalies()
        health = max(0.0, 100.0 - sum(_PENALTY[f.severity] for f in anomalies))
        duration = (self.last_ts - self.first_ts) if self.first_ts and self.last_ts else 0.0
        return TrafficSummary(
            source=self.source,
            started_at=_ts(self.first_ts),
            ended_at=_ts(self.last_ts),
            duration_seconds=round(duration, 3),
            total_packets=self.packets,
            total_bytes=self.bytes,
            protocols=dict(self.proto_packets.most_common()),
            protocol_bytes=dict(self.proto_bytes.most_common()),
            top_talkers=[
                {"ip": ip, "bytes": size, "packets": self.talker_packets[ip], "internal": is_internal(ip)}
                for ip, size in self.talker_bytes.most_common(10)
            ],
            top_destinations=[
                {"ip": ip, "bytes": size, "internal": is_internal(ip)} for ip, size in self.dest_bytes.most_common(10)
            ],
            top_ports=[
                {"protocol": proto, "port": port, "packets": count}
                for (proto, port), count in self.port_packets.most_common(10)
            ],
            dns={
                "queries": sum(self.dns_queries.values()),
                "unique_domains": len(self.dns_queries),
                "responses": self.dns_responses,
                "nxdomain": self.dns_nxdomain,
                "top_domains": [{"domain": d, "count": c} for d, c in self.dns_queries.most_common(10)],
            },
            http={
                "requests": sum(self.http_methods.values()),
                "methods": dict(self.http_methods),
                "top_hosts": [{"host": h, "count": c} for h, c in self.http_hosts.most_common(10)],
            },
            tls={
                "handshakes": sum(self.tls_versions.values()),
                "versions": dict(self.tls_versions),
                "top_sni": [{"sni": s, "count": c} for s, c in self.tls_sni.most_common(10)],
                "legacy_connections": len(self.legacy_tls),
            },
            trends=self._trend_points(),
            anomalies=anomalies,
            severity_counts=severity_counts(anomalies),
            health_score=round(health, 1),
        )
