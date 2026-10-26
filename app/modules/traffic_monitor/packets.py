"""Privacy-preserving packet metadata extraction.

Only **metadata** is retained: addresses, ports, sizes, protocol, DNS query
names, HTTP method/host/path (query string stripped) and TLS SNI/version.
Payloads, cookies, authorization headers, form data and credentials are never
parsed nor stored. This module is strictly passive (no injection, no MITM).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT")
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


@dataclass(slots=True)
class PacketRecord:
    """Normalised packet metadata."""

    timestamp: float
    length: int
    network: str  # "IPv4" | "IPv6" | "ARP" | "other"
    transport: str  # "TCP" | "UDP" | "ICMP" | "other"
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    tcp_flags: str = ""
    dns_query: str | None = None
    dns_is_response: bool = False
    dns_rcode: int | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_path: str | None = None
    tls_sni: str | None = None
    tls_version: str | None = None


def parse_tls_client_hello(payload: bytes) -> tuple[str | None, str | None] | None:
    """Extract ``(sni, highest_offered_version)`` from a TLS ClientHello.

    Returns ``None`` if the payload is not a ClientHello. Parsing is bounds
    checked at every step and never raises on malformed input.
    """
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        legacy_version = int.from_bytes(payload[9:11], "big")
        pos = 43  # 5 (record) + 4 (handshake hdr) + 2 (version) + 32 (random)
        session_len = payload[pos]
        pos += 1 + session_len
        suites_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + suites_len
        compression_len = payload[pos]
        pos += 1 + compression_len
        sni: str | None = None
        best = legacy_version
        if pos + 2 <= len(payload):
            ext_total = int.from_bytes(payload[pos : pos + 2], "big")
            pos += 2
            end = min(len(payload), pos + ext_total)
            while pos + 4 <= end:
                ext_type = int.from_bytes(payload[pos : pos + 2], "big")
                ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
                data = payload[pos + 4 : pos + 4 + ext_len]
                if ext_type == 0x0000 and len(data) >= 5 and data[2] == 0:  # server_name / host_name
                    name_len = int.from_bytes(data[3:5], "big")
                    sni = data[5 : 5 + name_len].decode("ascii", errors="replace").lower() or None
                elif ext_type == 0x002B and data:  # supported_versions
                    count = data[0]
                    for i in range(1, 1 + count, 2):
                        candidate = int.from_bytes(data[i : i + 2], "big")
                        is_grease = (candidate & 0x0F0F) == 0x0A0A
                        if not is_grease and candidate in TLS_VERSIONS and candidate > best:
                            best = candidate
                pos += 4 + ext_len
        return sni, TLS_VERSIONS.get(best, f"0x{best:04x}")
    except (IndexError, ValueError):
        return None


def parse_http_request(payload: bytes) -> tuple[str, str | None, str] | None:
    """Return ``(method, host, path_without_query)`` for an HTTP request start, else ``None``."""
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload[:4096].split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1", errors="replace").split(" ")
    if len(request_line) < 3 or not request_line[2].startswith("HTTP/"):
        return None
    method = request_line[0]
    path = request_line[1].split("?", 1)[0].split("#", 1)[0][:256]
    host = None
    for line in lines[1:]:
        if line[:5].lower() == b"host:":
            host = line[5:].decode("latin-1", errors="replace").strip().lower()[:253] or None
            break
    return method, host, path


def _dns_query_name(dns: Any) -> str | None:
    qd = dns.qd
    if isinstance(qd, list):  # scapy >= 2.6: PacketListField
        if not qd:
            return None
        qd = qd[0]
    qname = getattr(qd, "qname", None)
    if qname is None:
        return None
    name = qname.decode("ascii", errors="replace") if isinstance(qname, bytes) else str(qname)
    return name.rstrip(".").lower() or None


def from_scapy(packet: Any) -> PacketRecord:
    """Convert a scapy packet into a :class:`PacketRecord` (metadata only)."""
    timestamp = float(getattr(packet, "time", 0.0))
    length = len(packet)
    if packet.haslayer(ARP):
        return PacketRecord(timestamp, length, "ARP", "other", packet[ARP].psrc, packet[ARP].pdst)
    if packet.haslayer(IP):
        layer, network = packet[IP], "IPv4"
    elif packet.haslayer(IPv6):
        layer, network = packet[IPv6], "IPv6"
    else:
        return PacketRecord(timestamp, length, "other", "other")
    record = PacketRecord(timestamp, length, network, "other", str(layer.src), str(layer.dst))
    payload = b""
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        record.transport, record.sport, record.dport = "TCP", int(tcp.sport), int(tcp.dport)
        record.tcp_flags = str(tcp.flags)
        # bytes(payload) works whether scapy dissected it as Raw, HTTP or TLS.
        payload = bytes(tcp.payload)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        record.transport, record.sport, record.dport = "UDP", int(udp.sport), int(udp.dport)
    elif packet.haslayer(ICMP):
        record.transport = "ICMP"
    if packet.haslayer(DNS):
        dns = packet[DNS]
        record.dns_query = _dns_query_name(dns)
        record.dns_is_response = bool(dns.qr)
        record.dns_rcode = int(dns.rcode) if dns.qr else None
    elif payload:
        http = parse_http_request(payload)
        if http:
            record.http_method, record.http_host, record.http_path = http
        else:
            tls = parse_tls_client_hello(payload)
            if tls:
                record.tls_sni, record.tls_version = tls
    return record
