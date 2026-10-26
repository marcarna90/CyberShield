"""Shared fixtures: isolated settings/database per test, API client, host roots, fake Nmap."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.database.init_db import create_schema
from app.database.session import configure_database, get_session_factory
from app.services.context import reset_caches
from app.services.demo import build_demo_host_root

ADMIN_PASSWORD = "Adm1n-Test-Passw0rd!"
USER_PASSWORD = "Us3r-Test-Passw0rd!"
API = "/api/v1"


# =============================================================================
# Settings / database
# =============================================================================


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    for key in list(os.environ):
        if key.startswith("CYBERSHIELD_"):
            monkeypatch.delenv(key, raising=False)
    env = {
        "CYBERSHIELD_ENVIRONMENT": "test",
        "CYBERSHIELD_DATA_DIR": str(tmp_path / "data"),
        "CYBERSHIELD_REPORTS_DIR": str(tmp_path / "reports"),
        "CYBERSHIELD_LOGS_DIR": str(tmp_path / "logs"),
        "CYBERSHIELD_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "CYBERSHIELD_SECRET_KEY": "k" * 48,
        "CYBERSHIELD_RATE_LIMIT_PER_MINUTE": "100000",
        "CYBERSHIELD_AUTH_RATE_LIMIT_PER_MINUTE": "100000",
        "CYBERSHIELD_LOG_LEVEL": "WARNING",
        "CYBERSHIELD_HOST_ROOT": str(tmp_path / "host"),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(tmp_path)  # no stray .env file is picked up
    get_settings.cache_clear()
    reset_caches()
    build_demo_host_root(tmp_path / "host")
    current = get_settings()
    current.ensure_directories()
    configure_database(current.sqlalchemy_url)
    create_schema()
    yield current
    get_settings.cache_clear()
    reset_caches()


@pytest.fixture
def db(settings: Settings) -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


# =============================================================================
# API
# =============================================================================


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    from app.main import create_app

    with TestClient(create_app(settings)) as test_client:
        yield test_client


def login(client: TestClient, username: str = "admin", password: str = ADMIN_PASSWORD) -> dict[str, str]:
    response = client.post(f"{API}/auth/token", data={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture
def admin_headers(client: TestClient) -> dict[str, str]:
    return login(client)


@pytest.fixture
def make_user(client: TestClient, admin_headers: dict[str, str]):
    def _make(role: str, username: str | None = None) -> dict[str, str]:
        name = username or f"{role}_user"
        response = client.post(
            f"{API}/users",
            headers=admin_headers,
            json={"username": name, "email": f"{name}@corp.example", "password": USER_PASSWORD, "role": role},
        )
        assert response.status_code == 201, response.text
        return login(client, name, USER_PASSWORD)

    return _make


# =============================================================================
# Host roots
# =============================================================================

HARDENED_FILES: dict[str, tuple[str, int]] = {
    "etc/hostname": ("secure-host\n", 0o644),
    "etc/os-release": ('PRETTY_NAME="Ubuntu 24.04 LTS"\n', 0o644),
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
    "etc/shadow": (
        "root:$y$j9T$x$y:19800:1:365:7:::\ndaemon:*:19800::::::\nalice:$y$j9T$x$y:19800:1:365:7:::\n",
        0o640,
    ),
    "etc/group": ("root:x:0:\n", 0o644),
    "etc/login.defs": ("PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 14\nENCRYPT_METHOD YESCRYPT\n", 0o644),
    "etc/pam.d/common-password": (
        "password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so yescrypt\n",
        0o644,
    ),
    "etc/security/pwquality.conf": ("minlen = 14\n", 0o644),
    "etc/sudoers": ('Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nroot ALL=(ALL:ALL) ALL\n', 0o440),
    "etc/ssh/sshd_config": (
        "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\n"
        "MaxAuthTries 3\nX11Forwarding no\nClientAliveInterval 300\nLoginGraceTime 30\n"
        "Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\n",
        0o600,
    ),
    "etc/ufw/ufw.conf": ("ENABLED=yes\n", 0o644),
    "etc/apt/apt.conf.d/20auto-upgrades": ('APT::Periodic::Unattended-Upgrade "1";\n', 0o644),
    "etc/audit/auditd.conf": ("log_file = /var/log/audit/audit.log\n", 0o640),
    "proc/sys/kernel/randomize_va_space": ("2\n", 0o644),
    "proc/sys/net/ipv4/ip_forward": ("0\n", 0o644),
    "proc/net/tcp": (
        "  sl  local_address rem_address   st\n"
        "   0: 00000000:0016 00000000:0000 0A 0\n"
        "   1: 0100007F:1538 00000000:0000 0A 0\n",
        0o644,
    ),
}


def write_tree(root: Path, files: dict[str, Any]) -> Path:
    for relative, spec in files.items():
        content, mode = spec if isinstance(spec, tuple) else (spec, 0o644)
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
    return root


@pytest.fixture
def hardened_root(tmp_path: Path) -> Path:
    return write_tree(tmp_path / "hardened", HARDENED_FILES)


@pytest.fixture
def weak_root(tmp_path: Path) -> Path:
    return build_demo_host_root(tmp_path / "weak")


# =============================================================================
# Fake Nmap
# =============================================================================

SAMPLE_NMAP: dict[str, Any] = {
    "nmap": {
        "command_line": "nmap -oX - -sT -sV --version-intensity 5 -T3 --top-ports 1000 --open 10.0.0.0/29",
        "scaninfo": {"tcp": {"method": "connect", "services": "1-1000"}},
        "scanstats": {"uphosts": "2", "downhosts": "6", "totalhosts": "8"},
    },
    "scan": {
        "10.0.0.6": {
            "hostnames": [],
            "addresses": {"ipv4": "10.0.0.6"},
            "vendor": {},
            "status": {"state": "up", "reason": "syn-ack"},
            "tcp": {23: {"state": "open", "name": "telnet", "product": "", "version": "", "extrainfo": "", "cpe": ""}},
        },
        "10.0.0.5": {
            "hostnames": [{"name": "web.lab.example", "type": "PTR"}],
            "addresses": {"ipv4": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF"},
            "vendor": {"AA:BB:CC:DD:EE:FF": "Acme Networks"},
            "status": {"state": "up", "reason": "syn-ack"},
            "osmatch": [{"name": "Linux 5.4"}],
            "tcp": {
                22: {
                    "state": "open",
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "8.9p1 Ubuntu 3ubuntu0.6",
                    "extrainfo": "Ubuntu Linux; protocol 2.0",
                    "cpe": "cpe:/a:openbsd:openssh:8.9p1",
                },
                80: {
                    "state": "open",
                    "name": "http",
                    "product": "Apache httpd",
                    "version": "2.4.49",
                    "extrainfo": "(Unix) OpenSSL/1.0.1f",
                    "cpe": "cpe:/a:apache:http_server:2.4.49",
                },
                443: {"state": "closed", "name": "https", "product": "", "version": "", "extrainfo": "", "cpe": ""},
            },
        },
    },
}


class FakeNmap:
    """Stands in for nmap.PortScanner()."""

    def __init__(self, result: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.result = result if result is not None else SAMPLE_NMAP
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def scan(self, hosts: str, arguments: str) -> dict[str, Any]:
        self.calls.append((hosts, arguments))
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def fake_nmap(monkeypatch: pytest.MonkeyPatch) -> FakeNmap:
    from app.modules.network_scanner.scanner import NetworkScanner

    fake = FakeNmap()
    monkeypatch.setattr(NetworkScanner, "_default_factory", staticmethod(lambda: fake))
    return fake
