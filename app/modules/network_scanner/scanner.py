"""Nmap-based discovery restricted to the authorised scope.

Safety model:

* Targets are validated by :class:`~app.core.scope.TargetScope` (allow-list,
  size cap, no option injection, hostnames resolved once).
* Users choose a **named profile**; raw Nmap arguments are never accepted.
* Profiles use TCP connect scans (``-sT``) and service version detection only:
  no NSE exploitation scripts, no evasion, no aggressive timing.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import nmap
from pydantic import BaseModel, Field

from app.core.models import utcnow
from app.core.scope import TargetScope

logger = logging.getLogger(__name__)


class ScanError(RuntimeError):
    """Raised when Nmap is missing or reports an error."""


@dataclass(frozen=True)
class ScanProfile:
    name: str
    arguments: str
    version_detection: bool
    description: str


SCAN_PROFILES: dict[str, ScanProfile] = {
    "discovery": ScanProfile("discovery", "-sn -T3", False, "Host discovery only (no port scan)"),
    "quick": ScanProfile("quick", "-sT -T3 --top-ports 100 --open", False, "Top 100 TCP ports"),
    "standard": ScanProfile(
        "standard",
        "-sT -sV --version-intensity 5 -T3 --top-ports 1000 --open",
        True,
        "Top 1000 TCP ports with service/version detection",
    ),
    "full": ScanProfile(
        "full",
        "-sT -sV --version-intensity 7 -T3 -p- --open",
        True,
        "All 65535 TCP ports with service/version detection (slow)",
    ),
}


class DiscoveredService(BaseModel):
    port: int = Field(..., ge=0, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""


class DiscoveredAsset(BaseModel):
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    status: str = "up"
    os_guess: str | None = None
    services: list[DiscoveredService] = Field(default_factory=list)


class NetworkScanResult(BaseModel):
    targets: list[str]
    profile: str
    command_line: str = ""
    started_at: datetime
    finished_at: datetime
    hosts_up: int
    hosts_total: int
    assets: list[DiscoveredAsset]


def ip_sort_key(value: str) -> tuple[int, int, str]:
    """Numeric sort key for IPv4/IPv6 strings (invalid values sort last)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return (9, 0, value)
    return (ip.version, int(ip), value)


def _first_cpe(value: Any) -> str:
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def parse_nmap_result(raw: dict[str, Any]) -> list[DiscoveredAsset]:
    """Convert python-nmap's result dictionary into :class:`DiscoveredAsset` objects."""
    assets: list[DiscoveredAsset] = []
    for host, data in (raw.get("scan") or {}).items():
        addresses = data.get("addresses", {})
        hostnames = [h.get("name") for h in data.get("hostnames", []) if h.get("name")]
        mac = addresses.get("mac")
        vendor = (data.get("vendor") or {}).get(mac) if mac else None
        os_matches = data.get("osmatch") or []
        services = []
        for protocol in ("tcp", "udp"):
            for port, info in sorted((data.get(protocol) or {}).items()):
                if info.get("state") not in ("open", "open|filtered"):
                    continue
                services.append(
                    DiscoveredService(
                        port=int(port),
                        protocol=protocol,
                        state=info.get("state", "open"),
                        name=info.get("name", ""),
                        product=info.get("product", ""),
                        version=info.get("version", ""),
                        extrainfo=info.get("extrainfo", ""),
                        cpe=_first_cpe(info.get("cpe")),
                    )
                )
        assets.append(
            DiscoveredAsset(
                ip=addresses.get("ipv4") or addresses.get("ipv6") or host,
                hostname=hostnames[0] if hostnames else None,
                mac=mac,
                vendor=vendor,
                status=(data.get("status") or {}).get("state", "up"),
                os_guess=os_matches[0].get("name") if os_matches else None,
                services=services,
            )
        )
    return sorted(assets, key=lambda a: ip_sort_key(a.ip))


class NetworkScanner:
    """Run authorised Nmap scans."""

    def __init__(
        self,
        scope: TargetScope,
        host_timeout: str = "5m",
        scanner_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.scope = scope
        self.host_timeout = host_timeout
        self._factory = scanner_factory or self._default_factory

    @staticmethod
    def _default_factory() -> Any:
        try:
            return nmap.PortScanner()
        except nmap.PortScannerError as exc:
            raise ScanError("Nmap is not installed or not in PATH (apt install nmap)") from exc

    def build_arguments(self, profile: str) -> str:
        if profile not in SCAN_PROFILES:
            raise ValueError(f"Unknown scan profile {profile!r}; choose from {sorted(SCAN_PROFILES)}")
        return f"{SCAN_PROFILES[profile].arguments} --host-timeout {self.host_timeout}"

    def scan(self, targets: Iterable[str], profile: str = "standard") -> NetworkScanResult:
        """Validate targets against the scope, run Nmap and parse the output."""
        validated = self.scope.validate_many(targets)
        arguments = self.build_arguments(profile)
        started = utcnow()
        scanner = self._factory()
        logger.info("Starting %s scan of %s", profile, validated)
        try:
            raw = scanner.scan(hosts=" ".join(validated), arguments=arguments)
        except nmap.PortScannerError as exc:
            raise ScanError(f"Nmap error: {exc}") from exc
        scaninfo = (raw.get("nmap") or {}).get("scaninfo") or {}
        if scaninfo.get("error"):
            raise ScanError(f"Nmap error: {scaninfo['error']}")
        stats = (raw.get("nmap") or {}).get("scanstats") or {}
        assets = parse_nmap_result(raw)
        return NetworkScanResult(
            targets=validated,
            profile=profile,
            command_line=(raw.get("nmap") or {}).get("command_line", ""),
            started_at=started,
            finished_at=utcnow(),
            hosts_up=int(stats.get("uphosts", len(assets))),
            hosts_total=int(stats.get("totalhosts", len(assets))),
            assets=assets,
        )
