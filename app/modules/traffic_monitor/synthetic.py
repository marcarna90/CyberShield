"""Synthetic traffic generator for demos, tests and sample PCAPs.

All addresses are private (10.10.0.0/24) or RFC 5737 documentation ranges, and
all domains use reserved ``.example`` names, so the generated captures never
reference real infrastructure.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from app.modules.traffic_monitor.packets import PacketRecord

INTERNAL_CLIENTS = [f"10.10.0.{i}" for i in range(50, 58)]
DNS_SERVER = "10.10.0.2"
EXTERNAL_WEB = [f"192.0.2.{i}" for i in range(10, 30)]
C2_IP = "203.0.113.66"
EXFIL_IP = "203.0.113.50"
NORMAL_DOMAINS = [
    "www.example.com",
    "mail.example.org",
    "updates.example.net",
    "intranet.example.com",
    "cdn.example.net",
    "docs.example.org",
]


def build_client_hello(sni: str | None, max_version: int = 0x0304) -> bytes:
    """Build a minimal but well-formed TLS ClientHello record."""
    extensions = b""
    if sni:
        name = sni.encode("ascii")
        server_name = b"\x00" + len(name).to_bytes(2, "big") + name
        server_name_list = len(server_name).to_bytes(2, "big") + server_name
        extensions += b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    if max_version >= 0x0304:
        versions = b"\x04\x03\x04\x03\x03"
        extensions += b"\x00\x2b" + len(versions).to_bytes(2, "big") + versions
    legacy = min(max_version, 0x0303)
    body = (
        legacy.to_bytes(2, "big")
        + bytes(32)  # random
        + b"\x00"  # session id length
        + b"\x00\x02\x13\x01"  # one cipher suite
        + b"\x01\x00"  # compression: null
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def _eth() -> Any:
    # Explicit locally-administered MACs: avoids scapy ARP/route resolution when building frames.
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def _stamp(packet: Any, ts: float) -> Any:
    packet.time = ts
    return packet


def _dns_pair(client: str, name: str, ts: float, rcode: int = 0, port: int = 53000) -> list[Any]:
    query = _eth() / IP(src=client, dst=DNS_SERVER) / UDP(sport=port, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    reply = (
        _eth()
        / IP(src=DNS_SERVER, dst=client)
        / UDP(sport=53, dport=port)
        / DNS(qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name))
    )
    return [_stamp(query, ts), _stamp(reply, ts + 0.01)]


def baseline_packets(start: float, duration: int = 600, seed: int = 7) -> list[Any]:
    """Normal browsing: DNS lookups, TLS 1.3 handshakes and encrypted data."""
    rng = random.Random(seed)  # noqa: S311 - deterministic test data, not crypto # nosec B311
    packets: list[Any] = []
    for second in range(0, duration, 2):
        client, server = rng.choice(INTERNAL_CLIENTS), rng.choice(EXTERNAL_WEB)
        ts = start + second + rng.random()
        sport = rng.randint(40000, 60000)
        if second % 20 == 0:
            packets += _dns_pair(client, rng.choice(NORMAL_DOMAINS), ts, port=sport)
        if second % 10 == 0:
            hello = (
                _eth()
                / IP(src=client, dst=server)
                / TCP(sport=sport, dport=443, flags="PA")
                / Raw(build_client_hello(rng.choice(NORMAL_DOMAINS)))
            )
            packets.append(_stamp(hello, ts + 0.02))
        for i in range(3):
            data = (
                _eth()
                / IP(src=server, dst=client)
                / TCP(sport=443, dport=sport, flags="A")
                / Raw(b"\x17\x03\x03" + bytes(rng.randint(600, 1300)))
            )
            packets.append(_stamp(data, ts + 0.05 + i * 0.01))
    return packets


def incident_packets(start: float, seed: int = 11) -> list[Any]:
    """Suspicious activity: C2 beacons, DGA, DNS tunnelling, port scan, legacy TLS, cleartext HTTP."""
    rng = random.Random(seed)  # noqa: S311 - deterministic test data, not crypto # nosec B311
    packets: list[Any] = []
    # Legacy TLS 1.0 client
    hello = (
        _eth()
        / IP(src="10.10.0.53", dst="192.0.2.40")
        / TCP(sport=51000, dport=443, flags="PA")
        / Raw(build_client_hello("legacy-portal.example.org", max_version=0x0301))
    )
    packets.append(_stamp(hello, start + 30))
    # Cleartext HTTP download from an Internet host (query string is discarded by the parser)
    http = (
        _eth()
        / IP(src="10.10.0.54", dst="192.0.2.41")
        / TCP(sport=51001, dport=80, flags="PA")
        / Raw(
            b"GET /files/setup.exe?token=DO-NOT-STORE HTTP/1.1\r\nHost: downloads.example.net\r\n"
            b"User-Agent: Mozilla/5.0\r\nCookie: session=DO-NOT-STORE\r\n\r\n"
        )
    )
    packets.append(_stamp(http, start + 45))
    # DGA-like lookups resolving to NXDOMAIN
    for i in range(45):
        label = "".join(rng.choice("bcdfghjklmnpqrstvwxz0123456789") for _ in range(16))
        packets += _dns_pair("10.10.0.55", f"{label}.example", start + 60 + i, rcode=3, port=52000 + i)
    # DNS tunnelling: many unique, long sub-domains under one parent
    for i in range(60):
        chunk = "".join(rng.choice("0123456789abcdef") for _ in range(48))
        name = f"{chunk}.{chunk[:40]}.{i}.tunnel-exfil.example"
        packets += _dns_pair("10.10.0.56", name, start + 120 + i * 0.5, port=53500 + i)
    # TCP SYN port scan from an internal host
    for i, port in enumerate(
        [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1433,
            1521,
            2049,
            3306,
            3389,
            5432,
            5900,
            6379,
            8080,
            8443,
            9200,
            11211,
            27017,
            5000,
            7001,
        ]
    ):
        syn = _eth() / IP(src="10.10.0.99", dst="10.10.0.10") / TCP(sport=61000 + i, dport=port, flags="S")
        packets.append(_stamp(syn, start + 200 + i * 0.05))
    # C2 beaconing (IP and SNI are both on the sample IOC list)
    for i in range(10):
        beacon = (
            _eth()
            / IP(src="10.10.0.13", dst=C2_IP)
            / TCP(sport=55000 + i, dport=443, flags="PA")
            / Raw(build_client_hello("malware-c2.example"))
        )
        packets.append(_stamp(beacon, start + 15 + i * 60))
    # Outbound connection attempt to a classic backdoor port
    syn = _eth() / IP(src="10.10.0.57", dst="198.51.100.200") / TCP(sport=56000, dport=4444, flags="S")
    packets.append(_stamp(syn, start + 300))
    return packets


def exfiltration_records(
    start: float, megabytes: int = 60, window: float = 30.0, src: str = "10.10.0.13", dst: str = EXFIL_IP
) -> list[PacketRecord]:
    """Bulk outbound transfer as lightweight records (too large to materialise as scapy packets)."""
    size = 1500
    count = megabytes * 1024 * 1024 // size
    return [
        PacketRecord(
            timestamp=start + window * i / count,
            length=size,
            network="IPv4",
            transport="TCP",
            src=src,
            dst=dst,
            sport=57000,
            dport=443,
            tcp_flags="PA",
        )
        for i in range(count)
    ]


def write_sample_pcap(path: Path, start: float = 1_767_225_600.0) -> Path:
    """Write a compact sample capture (baseline + incidents) for documentation and tests."""
    packets = sorted(baseline_packets(start, duration=300) + incident_packets(start), key=lambda p: p.time)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    return path
