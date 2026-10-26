"""Demo dataset: realistic, clearly-flagged sample data produced by the *real* pipelines.

Nothing is hard-coded as a "result": fictional assets, a deliberately weak
host configuration and synthetic traffic are fed through the actual auditor,
vulnerability analyzer, traffic analyzer, compliance checker and alerting.
Every row is flagged ``is_demo`` (assets are tagged ``demo``) and can be purged.

All IPs are private or RFC 5737 documentation addresses; all domains use the
reserved ``.example`` TLD.
"""

from __future__ import annotations

import os
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.models import utcnow
from app.database import repository
from app.database.models import Alert, Asset, ComplianceResult, FindingRecord, Scan, TrafficSnapshot
from app.modules.network_scanner.scanner import DiscoveredAsset, DiscoveredService
from app.modules.system_auditor.checks import AuditContext
from app.modules.traffic_monitor.analyzer import TrafficAnalyzer
from app.modules.traffic_monitor.packets import from_scapy
from app.modules.traffic_monitor.synthetic import baseline_packets, exfiltration_records, incident_packets
from app.services import operations
from app.services.context import get_iocs, traffic_thresholds

DEMO_TAG = "demo"
DEMO_ACTOR = "demo-seeder"


def _svc(port: int, name: str, product: str = "", version: str = "", extrainfo: str = "", cpe: str = "") -> dict:
    return {"port": port, "name": name, "product": product, "version": version, "extrainfo": extrainfo, "cpe": cpe}


DEMO_ASSETS: dict[str, dict[str, Any]] = {
    "web": {
        "ip": "10.10.0.10",
        "hostname": "web-prod-01.corp.example",
        "os_guess": "Linux 5.x",
        "services": [
            _svc(
                22,
                "ssh",
                "OpenSSH",
                "8.9p1 Ubuntu 3ubuntu0.6",
                "Ubuntu Linux; protocol 2.0",
                "cpe:/a:openbsd:openssh:8.9p1",
            ),
            _svc(80, "http", "Apache httpd", "2.4.49", "(Unix) OpenSSL/1.0.1f", "cpe:/a:apache:http_server:2.4.49"),
            _svc(3306, "mysql", "MySQL", "8.0.36"),
        ],
    },
    "files": {
        "ip": "10.10.0.11",
        "hostname": "files-01.corp.example",
        "os_guess": "Linux 4.x",
        "services": [
            _svc(21, "ftp", "vsftpd", "2.3.4", cpe="cpe:/a:vsftpd:vsftpd:2.3.4"),
            _svc(22, "ssh", "OpenSSH", "7.4", "protocol 2.0", "cpe:/a:openbsd:openssh:7.4"),
            _svc(445, "netbios-ssn", "Samba smbd", "4.5.9", "workgroup: CORP"),
        ],
    },
    "mail": {
        "ip": "10.10.0.12",
        "hostname": "mail-01.corp.example",
        "os_guess": "Linux 5.x",
        "services": [
            _svc(22, "ssh", "OpenSSH", "9.7p1", "protocol 2.0", "cpe:/a:openbsd:openssh:9.7p1"),
            _svc(25, "smtp", "Exim smtpd", "4.89", cpe="cpe:/a:exim:exim:4.89"),
        ],
    },
    "app": {
        "ip": "10.10.0.13",
        "hostname": "app-01.corp.example",
        "os_guess": "Linux 5.x",
        "services": [
            _svc(8009, "ajp13", "Apache Jserv", "", "Protocol v1.3"),
            _svc(8080, "http", "Apache Tomcat", "9.0.30", cpe="cpe:/a:apache:tomcat:9.0.30"),
            _svc(6379, "redis", "Redis key-value store", "5.0.7"),
        ],
    },
    "backup_old": {
        "ip": "10.10.0.30",
        "hostname": "backup-01.corp.example",
        "os_guess": "Linux 5.x",
        "services": [
            _svc(22, "ssh", "OpenSSH", "8.2p1", "protocol 2.0", "cpe:/a:openbsd:openssh:8.2p1"),
            _svc(5432, "postgresql", "PostgreSQL DB", "15.4"),
        ],
    },
    "backup": {
        "ip": "10.10.0.30",
        "hostname": "backup-01.corp.example",
        "os_guess": "Linux 6.x",
        "services": [
            _svc(22, "ssh", "OpenSSH", "9.8p1", "protocol 2.0", "cpe:/a:openbsd:openssh:9.8p1"),
        ],
    },
    "proxy": {
        "ip": "10.10.0.14",
        "hostname": "proxy-01.corp.example",
        "os_guess": "Linux 5.x",
        "services": [
            _svc(80, "http", "nginx", "1.18.0", "Ubuntu", "cpe:/a:igor_sysoev:nginx:1.18.0"),
            _svc(443, "https", "nginx", "1.18.0", "Ubuntu", "cpe:/a:igor_sysoev:nginx:1.18.0"),
        ],
    },
    "switch": {
        "ip": "10.10.0.20",
        "hostname": "core-sw-legacy.corp.example",
        "os_guess": "embedded",
        "services": [
            _svc(23, "telnet", "Linux telnetd"),
        ],
    },
    "docker": {
        "ip": "10.10.0.21",
        "hostname": "dev-docker-01.corp.example",
        "os_guess": "Linux 6.x",
        "services": [
            _svc(2375, "docker", "Docker", "20.10.7"),
            _svc(22, "ssh", "OpenSSH", "9.8p1", "protocol 2.0", "cpe:/a:openbsd:openssh:9.8p1"),
        ],
    },
}

DEMO_HOST_FILES: dict[str, tuple[str, int]] = {
    "etc/hostname": ("web-prod-01\n", 0o644),
    "etc/os-release": ('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nID=debian\n', 0o644),
    "etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "svc-backup:x:0:0:legacy backup account:/var/backups:/bin/bash\n"
        "postgres:x:110:118:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
        "alice:x:1000:1000:Alice Admin:/home/alice:/bin/bash\n"
        "bob:x:1001:1001:Bob Dev:/home/bob:/bin/bash\n",
        0o644,
    ),
    "etc/shadow": (
        "root:$y$j9T$demo$demo:19800:0:99999:7:::\n"
        "daemon:*:19800:0:99999:7:::\n"
        "svc-backup::19800:0:99999:7:::\n"
        "postgres:!:19800::::::\n"
        "alice:$y$j9T$demo$demo:19800:0:99999:7:::\n"
        "bob:$y$j9T$demo$demo:19800:0:99999:7:::\n",
        0o644,  # deliberately too permissive for the demo
    ),
    "etc/group": ("root:x:0:\nsudo:x:27:alice\n", 0o644),
    "etc/login.defs": ("PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nENCRYPT_METHOD SHA512\n", 0o644),
    "etc/pam.d/common-password": (
        "password [success=1 default=ignore] pam_unix.so obscure yescrypt\npassword requisite pam_deny.so\n",
        0o644,
    ),
    "etc/sudoers": (
        "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
        0o440,
    ),
    "etc/sudoers.d/deploy": ("bob ALL=(ALL) NOPASSWD: ALL\n", 0o440),
    "etc/ssh/sshd_config": (
        "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\nPasswordAuthentication yes\n"
        "X11Forwarding yes\nMaxAuthTries 6\nCiphers aes128-cbc,aes256-ctr,aes256-gcm@openssh.com\n"
        "Subsystem sftp /usr/lib/openssh/sftp-server\n",
        0o644,
    ),
    "etc/ssh/sshd_config.d/10-banner.conf": ("Banner /etc/issue.net\n", 0o644),
    "etc/ufw/ufw.conf": ("ENABLED=no\nLOGLEVEL=low\n", 0o644),
    "etc/apt/apt.conf.d/50unattended-upgrades": ("// not enabled by 20auto-upgrades\n", 0o644),
    "proc/sys/kernel/randomize_va_space": ("2\n", 0o644),
    "proc/sys/kernel/osrelease": ("6.1.0-18-amd64\n", 0o644),
    "proc/sys/net/ipv4/ip_forward": ("0\n", 0o644),
    "proc/net/tcp": (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001\n"
        "   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002\n"
        "   2: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   110        0 1003\n"
        "   3: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 1004\n",
        0o644,
    ),
    "proc/net/tcp6": ("  sl  local_address remote_address st\n", 0o644),
}


def build_demo_host_root(root: Path) -> Path:
    """Materialise a deliberately weak Debian host configuration under ``root``."""
    for relative, (content, mode) in DEMO_HOST_FILES.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        os.chmod(target, mode)
    return root


def _assets(*keys: str) -> list[DiscoveredAsset]:
    return [
        DiscoveredAsset(
            ip=DEMO_ASSETS[k]["ip"],
            hostname=DEMO_ASSETS[k]["hostname"],
            os_guess=DEMO_ASSETS[k]["os_guess"],
            services=[DiscoveredService(**s) for s in DEMO_ASSETS[k]["services"]],
        )
        for k in keys
    ]


def has_demo_data(db: Session) -> bool:
    return db.scalar(select(Scan.id).where(Scan.is_demo.is_(True)).limit(1)) is not None


def _demo_scan(db: Session, settings: Settings, keys: tuple[str, ...], when) -> None:
    assets = _assets(*keys)
    scan = repository.create_scan(
        db,
        scan_type="network",
        target=",".join(a.ip for a in assets),
        profile="standard",
        requested_by=DEMO_ACTOR,
        is_demo=True,
    )
    scan.started_at = when
    for asset in assets:
        payload = asset.model_dump()
        # a host that was re-scanned with fewer services: drop stale services
        existing = db.scalars(select(Asset).where(Asset.ip == asset.ip)).first()
        if existing is not None:
            existing.services.clear()
            db.commit()
        repository.upsert_asset(db, payload, tags=[DEMO_TAG])
    operations.record_vulnerability_analysis(
        db,
        settings,
        scan,
        assets,
        extra={
            "targets": [a.ip for a in assets],
            "profile": "standard",
            "hosts_up": len(assets),
            "hosts_total": len(assets),
        },
        is_demo=True,
        now=when,
    )


def _demo_traffic(db: Session, settings: Settings, when, *, incident: bool) -> None:
    start = (when - timedelta(minutes=10)).timestamp()
    analyzer = TrafficAnalyzer(traffic_thresholds(settings), get_iocs(settings), source="demo:sensor-eth0")
    packets = baseline_packets(start)
    if incident:
        packets += incident_packets(start)
    for packet in packets:
        analyzer.ingest(from_scapy(packet))
    if incident:
        analyzer.ingest_many(exfiltration_records(start + 420))
    operations.record_traffic(db, settings, analyzer.summarize(), DEMO_ACTOR, is_demo=True, now=when)


def seed_demo_data(db: Session, settings: Settings) -> dict[str, int]:
    """Replay a 14-day scenario through the real pipelines."""
    if has_demo_data(db):
        purge_demo_data(db)
    now = utcnow()
    _demo_scan(db, settings, ("web", "files"), now - timedelta(days=13))
    _demo_scan(db, settings, ("mail", "app", "backup_old"), now - timedelta(days=10))
    _demo_scan(db, settings, ("proxy", "switch"), now - timedelta(days=6))
    with tempfile.TemporaryDirectory(prefix="cybershield-demo-") as tmp:
        root = build_demo_host_root(Path(tmp))
        operations.run_host_audit(
            db,
            settings,
            DEMO_ACTOR,
            host_root=root,
            context=AuditContext(host_root=root),
            is_demo=True,
            now=now - timedelta(days=5),
        )
    _demo_scan(db, settings, ("backup",), now - timedelta(days=3))  # patched: OpenSSH CVEs auto-resolve
    _demo_traffic(db, settings, now - timedelta(days=2), incident=False)
    _demo_scan(db, settings, ("web", "files", "mail", "app", "backup", "proxy", "switch", "docker"), now)
    _demo_traffic(db, settings, now, incident=True)
    return {
        "assets": len(list(db.scalars(select(Asset.id)))),
        "open_findings": len(repository.open_findings(db)),
        "alerts": len(list(db.scalars(select(Alert.id).where(Alert.is_demo.is_(True))))),
    }


def purge_demo_data(db: Session) -> dict[str, int]:
    counts = {}
    for model, name in (
        (FindingRecord, "findings"),
        (Alert, "alerts"),
        (ComplianceResult, "compliance"),
        (TrafficSnapshot, "traffic"),
        (Scan, "scans"),
    ):
        result = db.execute(delete(model).where(model.is_demo.is_(True)))
        counts[name] = result.rowcount or 0
    demo_assets = [a for a in db.scalars(select(Asset)) if DEMO_TAG in (a.tags or [])]
    for asset in demo_assets:
        db.delete(asset)
    counts["assets"] = len(demo_assets)
    db.commit()
    return counts
