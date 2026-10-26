"""Process-wide caches for heavy, read-mostly resources (CVE database, IOC index)."""

from __future__ import annotations

import threading

from app.core.config import Settings
from app.core.scope import TargetScope
from app.modules.threat_intelligence.intel import IOCDatabase, load_default_iocs
from app.modules.traffic_monitor.analyzer import TrafficThresholds
from app.modules.vulnerability_analyzer.cve_db import CVEDatabase, load_cve_database

_lock = threading.Lock()
_cve_db: CVEDatabase | None = None
_iocs: IOCDatabase | None = None


def cve_db_path(settings: Settings):
    return settings.data_dir / "cve_db.json"


def ioc_cache_dir(settings: Settings):
    return settings.data_dir / "threat_feeds"


def get_cve_db(settings: Settings) -> CVEDatabase:
    global _cve_db
    with _lock:
        if _cve_db is None:
            _cve_db = load_cve_database(cve_db_path(settings))
        return _cve_db


def get_iocs(settings: Settings) -> IOCDatabase:
    global _iocs
    with _lock:
        if _iocs is None:
            _iocs = load_default_iocs(settings.ioc_file_list, ioc_cache_dir(settings))
        return _iocs


def reset_caches() -> None:
    """Force reload on next access (after imports/feed refresh, and in tests)."""
    global _cve_db, _iocs
    with _lock:
        _cve_db = None
        _iocs = None


def get_scope(settings: Settings) -> TargetScope:
    return TargetScope(settings.allowed_target_list, settings.max_scan_hosts)


def traffic_thresholds(settings: Settings) -> TrafficThresholds:
    return TrafficThresholds(
        large_transfer_bytes=int(settings.traffic_large_transfer_mb * 1024 * 1024),
        spike_factor=settings.traffic_spike_factor,
        portscan_threshold=settings.traffic_portscan_threshold,
    )
