"""Threat intelligence: IOC storage, matching and feed ingestion.

Supported indicator formats (one per line, ``#`` comments allowed)::

    203.0.113.66                      # IPv4 / IPv6 address
    198.51.100.0/24                   # CIDR network
    malicious-domain.example          # domain (matches sub-domains too)
    203.0.113.66,botnet-c2,Feodo      # optional "indicator,description,source"

Feeds are fetched over HTTPS only, size-capped, and every line is validated
before being accepted - a feed can never inject anything but indicators.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.core.netutils import classify_ip

logger = logging.getLogger(__name__)

DEFAULT_IOC_FILE = Path(__file__).parent / "data" / "default_iocs.txt"
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_FEED_BYTES = 20 * 1024 * 1024


__all__ = ["IOC", "IOCDatabase", "classify_ip", "load_default_iocs"]


@dataclass(frozen=True)
class IOC:
    indicator: str
    ioc_type: str  # "ip" | "network" | "domain"
    description: str = "Known malicious indicator"
    source: str = "local"


class IOCDatabase:
    """In-memory IOC index with O(1) IP/domain lookups and CIDR containment."""

    def __init__(self) -> None:
        self._ips: dict[str, IOC] = {}
        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, IOC]] = []
        self._domains: dict[str, IOC] = {}

    # ------------------------------------------------------------- ingestion
    def add(self, indicator: str, description: str = "Known malicious indicator", source: str = "local") -> bool:
        """Validate and add one indicator. Returns ``False`` if it is invalid."""
        value = indicator.strip().lower().rstrip(".")
        if not value:
            return False
        try:
            if "/" in value:
                network = ipaddress.ip_network(value, strict=False)
                self._networks.append((network, IOC(str(network), "network", description, source)))
                return True
            ip = ipaddress.ip_address(value)
            self._ips[str(ip)] = IOC(str(ip), "ip", description, source)
            return True
        except ValueError:
            pass
        if _DOMAIN_RE.match(value):
            self._domains[value] = IOC(value, "domain", description, source)
            return True
        return False

    def load_lines(self, lines: Iterable[str], source: str = "local") -> int:
        added = 0
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            indicator = parts[0]
            description = parts[1] if len(parts) > 1 and parts[1] else "Known malicious indicator"
            origin = parts[2] if len(parts) > 2 and parts[2] else source
            if self.add(indicator, description[:200], origin[:64]):
                added += 1
        return added

    def load_file(self, path: Path, source: str | None = None) -> int:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read IOC file %s: %s", path, exc)
            return 0
        return self.load_lines(text.splitlines(), source or path.stem)

    def refresh_from_feeds(
        self, urls: Iterable[str], cache_dir: Path, timeout: float = 20.0, client: httpx.Client | None = None
    ) -> dict[str, int]:
        """Download HTTPS feeds, cache them locally and load them."""
        results: dict[str, int] = {}
        cache_dir.mkdir(parents=True, exist_ok=True)
        own_client = client is None
        http = client or httpx.Client(timeout=timeout, follow_redirects=True)
        try:
            for index, url in enumerate(urls):
                if not url.lower().startswith("https://"):
                    logger.warning("Refusing non-HTTPS threat feed: %s", url)
                    results[url] = -1
                    continue
                try:
                    response = http.get(url)
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    logger.warning("Threat feed %s failed: %s", url, exc)
                    results[url] = -1
                    continue
                content = response.content[:MAX_FEED_BYTES].decode("utf-8", errors="replace")
                (cache_dir / f"feed_{index}.txt").write_text(content, encoding="utf-8")
                results[url] = self.load_lines(content.splitlines(), source=f"feed:{index}")
        finally:
            if own_client:
                http.close()
        return results

    # -------------------------------------------------------------- matching
    def match_ip(self, value: str) -> IOC | None:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return None
        hit = self._ips.get(str(ip))
        if hit:
            return hit
        for network, ioc in self._networks:
            if ip.version == network.version and ip in network:
                return ioc
        return None

    def match_domain(self, value: str) -> IOC | None:
        """Exact or parent-domain match (``a.b.evil.example`` matches ``evil.example``)."""
        name = value.strip().lower().rstrip(".")
        labels = name.split(".")
        for i in range(len(labels) - 1):
            hit = self._domains.get(".".join(labels[i:]))
            if hit:
                return hit
        return None

    def lookup(self, indicator: str) -> dict[str, object]:
        """Return a reputation verdict for an IP or domain."""
        ioc = self.match_ip(indicator) or self.match_domain(indicator)
        return {
            "indicator": indicator,
            "classification": classify_ip(indicator),
            "malicious": ioc is not None,
            "match": ioc.__dict__ if ioc else None,
        }

    def stats(self) -> dict[str, int]:
        return {"ips": len(self._ips), "networks": len(self._networks), "domains": len(self._domains)}

    def __len__(self) -> int:
        return len(self._ips) + len(self._networks) + len(self._domains)


def load_default_iocs(extra_files: Iterable[Path] = (), cache_dir: Path | None = None) -> IOCDatabase:
    """Bundled sample IOCs + operator files + previously cached feeds."""
    db = IOCDatabase()
    db.load_file(DEFAULT_IOC_FILE, source="bundled-sample")
    for path in extra_files:
        db.load_file(path)
    if cache_dir and cache_dir.is_dir():
        for cached in sorted(cache_dir.glob("feed_*.txt")):
            db.load_file(cached, source=f"cached:{cached.stem}")
    return db
