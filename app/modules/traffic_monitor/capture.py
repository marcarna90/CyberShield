"""Passive packet acquisition: live sniffing (read-only) and offline PCAP analysis.

Live capture needs ``CAP_NET_RAW`` (root, or ``setcap cap_net_raw+eip`` on
the interpreter, or the Docker ``sensor`` profile). The interface is opened in
read-only mode: CyberShield never injects, modifies or redirects traffic.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from scapy.all import PcapReader, conf, sniff
from scapy.error import Scapy_Exception

from app.modules.threat_intelligence.intel import IOCDatabase
from app.modules.traffic_monitor.analyzer import TrafficAnalyzer, TrafficSummary, TrafficThresholds
from app.modules.traffic_monitor.packets import from_scapy

logger = logging.getLogger(__name__)
conf.verb = 0  # silence scapy console output


class CaptureError(RuntimeError):
    """Raised when packets cannot be read (permissions, bad file, missing interface)."""


def analyze_pcap(
    path: Path,
    thresholds: TrafficThresholds | None = None,
    iocs: IOCDatabase | None = None,
    max_packets: int = 200_000,
) -> TrafficSummary:
    """Stream a PCAP/PCAPNG file through the analyzer (bounded by ``max_packets``)."""
    analyzer = TrafficAnalyzer(thresholds, iocs, source=f"pcap:{path.name}")
    try:
        with PcapReader(str(path)) as reader:
            for index, packet in enumerate(reader):
                if index >= max_packets:
                    logger.warning("PCAP truncated at %d packets", max_packets)
                    break
                analyzer.ingest(from_scapy(packet))
    except (Scapy_Exception, OSError, EOFError) as exc:
        raise CaptureError(f"Cannot read capture file: {exc}") from exc
    return analyzer.summarize()


def has_capture_privileges() -> bool:
    """Best-effort check for raw socket capability."""
    if os.geteuid() == 0:
        return True
    try:
        with open("/proc/self/status", encoding="utf-8") as status:
            for line in status:
                if line.startswith("CapEff:"):
                    return bool(int(line.split()[1], 16) & (1 << 13))  # CAP_NET_RAW
    except OSError:
        return False
    return False


def live_capture(
    interface: str | None,
    duration: int,
    thresholds: TrafficThresholds | None = None,
    iocs: IOCDatabase | None = None,
    bpf_filter: str | None = None,
    max_packets: int = 200_000,
) -> TrafficSummary:
    """Sniff passively for ``duration`` seconds and return the summary."""
    if not has_capture_privileges():
        raise CaptureError("Live capture requires root or CAP_NET_RAW (try: sudo cybershield traffic capture ...)")
    analyzer = TrafficAnalyzer(thresholds, iocs, source=f"live:{interface or 'default'}")
    try:
        sniff(
            iface=interface,
            timeout=duration,
            count=max_packets,
            store=False,
            filter=bpf_filter,
            prn=lambda pkt: analyzer.ingest(from_scapy(pkt)),
        )
    except (Scapy_Exception, OSError) as exc:
        raise CaptureError(f"Capture failed on {interface or 'default interface'}: {exc}") from exc
    return analyzer.summarize()
