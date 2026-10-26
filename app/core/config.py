"""Centralised, validated configuration.

All settings are read from environment variables prefixed with ``CYBERSHIELD_``
(or from a ``.env`` file). Secrets can be supplied either directly or through a
``*_FILE`` variable pointing at a file (Docker secrets pattern), which keeps
them out of ``docker inspect`` output and process listings.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, PrivateAttr, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL

logger = logging.getLogger(__name__)

#: Private (RFC 1918) ranges plus loopback. Public address space is never
#: scannable unless an operator explicitly adds it.
DEFAULT_ALLOWED_TARGETS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8"

_DURATION_RE = re.compile(r"^\d{1,4}[smh]$")


def read_secret_file(path: Path | str | None) -> str | None:
    """Return the stripped content of a secret file, or ``None`` if unavailable."""
    if not path:
        return None
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    """Application settings (immutable after load, cached by :func:`get_settings`)."""

    model_config = SettingsConfigDict(
        env_prefix="CYBERSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------ general
    app_name: str = "CyberShield Enterprise Security Platform"
    environment: Literal["development", "production", "test"] = "production"
    api_prefix: str = "/api/v1"
    enable_docs: bool = True
    organization: str = "My Organization"

    # -------------------------------------------------------------------- paths
    data_dir: Path = Path("data")
    reports_dir: Path = Path("reports")
    logs_dir: Path = Path("logs")
    #: Root of the filesystem to audit. ``/`` on a host, ``/host`` in a container
    #: where the host's ``/etc`` is bind-mounted read-only under ``/host/etc``.
    host_root: Path = Path("/")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = True

    # ------------------------------------------------------------------ secrets
    secret_key: SecretStr | None = None
    secret_key_file: Path | None = None
    access_token_expire_minutes: int = Field(30, ge=5, le=1440)
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"

    # ----------------------------------------------------------------- database
    database_url: str | None = None
    db_host: str | None = None
    db_port: int = Field(5432, ge=1, le=65535)
    db_name: str = "cybershield"
    db_user: str = "cybershield"
    db_password: SecretStr | None = None
    db_password_file: Path | None = None

    # ------------------------------------------------------------ bootstrap admin
    admin_username: str = "admin"
    admin_email: str = "admin@localhost"
    admin_password: SecretStr | None = None
    admin_password_file: Path | None = None

    # ------------------------------------------------------------- API security
    cors_origins: str = "http://localhost:8501"
    rate_limit_per_minute: int = Field(120, ge=1)
    auth_rate_limit_per_minute: int = Field(10, ge=1)
    max_failed_logins: int = Field(5, ge=1)
    lockout_minutes: int = Field(15, ge=1)
    max_upload_mb: int = Field(50, ge=1, le=2048)

    # ------------------------------------------------------------ scanning scope
    allowed_targets: str = DEFAULT_ALLOWED_TARGETS
    max_scan_hosts: int = Field(1024, ge=1, le=65536)
    nmap_host_timeout: str = "5m"

    # ----------------------------------------------------------------- traffic
    traffic_large_transfer_mb: float = Field(50.0, gt=0)
    traffic_spike_factor: float = Field(3.0, gt=1)
    traffic_portscan_threshold: int = Field(25, ge=2)
    traffic_max_packets: int = Field(200_000, ge=100)
    sensor_interface: str | None = None
    sensor_interval_seconds: int = Field(60, ge=5, le=3600)

    # ------------------------------------------------------------ threat intel
    ioc_files: str = ""
    threat_feeds: str = ""

    # ------------------------------------------------------------------ alerts
    smtp_host: str | None = None
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_password_file: Path | None = None
    smtp_from: str = "cybershield@localhost"
    smtp_starttls: bool = True
    alert_email_to: str = ""
    alert_email_min_severity: Literal["critical", "high", "medium", "low"] = "high"
    alert_cooldown_minutes: int = Field(60, ge=0)
    compliance_alert_threshold: float = Field(70.0, ge=0, le=100)

    # -------------------------------------------------------------------- demo
    seed_demo: bool = False

    _secret_cache: str | None = PrivateAttr(default=None)

    # ============================================================== validators
    @field_validator(
        "database_url",
        "db_host",
        "sensor_interface",
        "smtp_host",
        "smtp_user",
        "secret_key_file",
        "db_password_file",
        "admin_password_file",
        "smtp_password_file",
        mode="before",
    )
    @classmethod
    def _empty_to_none(cls, value: object) -> object:
        """Treat empty environment values (``VAR=``) as unset."""
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("allowed_targets")
    @classmethod
    def _validate_targets(cls, value: str) -> str:
        for item in _split_csv(value):
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid network in allowed_targets: {item!r}") from exc
        return value

    @field_validator("nmap_host_timeout")
    @classmethod
    def _validate_timeout(cls, value: str) -> str:
        if not _DURATION_RE.match(value):
            raise ValueError("nmap_host_timeout must look like '30s', '5m' or '1h'")
        return value

    @field_validator("api_prefix")
    @classmethod
    def _validate_prefix(cls, value: str) -> str:
        if not value.startswith("/") or value.endswith("/"):
            raise ValueError("api_prefix must start with '/' and not end with '/'")
        return value

    # ============================================================== properties
    @property
    def cors_origin_list(self) -> list[str]:
        return _split_csv(self.cors_origins)

    @property
    def allowed_target_list(self) -> list[str]:
        return _split_csv(self.allowed_targets)

    @property
    def ioc_file_list(self) -> list[Path]:
        return [Path(p) for p in _split_csv(self.ioc_files)]

    @property
    def threat_feed_list(self) -> list[str]:
        return _split_csv(self.threat_feeds)

    @property
    def alert_email_recipients(self) -> list[str]:
        return _split_csv(self.alert_email_to)

    @property
    def smtp_password_value(self) -> str | None:
        from_file = read_secret_file(self.smtp_password_file)
        if from_file:
            return from_file
        return self.smtp_password.get_secret_value() if self.smtp_password else None

    @property
    def admin_password_value(self) -> str | None:
        from_file = read_secret_file(self.admin_password_file)
        if from_file:
            return from_file
        return self.admin_password.get_secret_value() if self.admin_password else None

    @property
    def sqlalchemy_url(self) -> str:
        """Database URL: explicit URL > PostgreSQL components > local SQLite file."""
        if self.database_url:
            return self.database_url
        if self.db_host:
            password = read_secret_file(self.db_password_file)
            if password is None and self.db_password is not None:
                password = self.db_password.get_secret_value()
            url = URL.create(
                "postgresql+psycopg",
                username=self.db_user,
                password=password,
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
            )
            return url.render_as_string(hide_password=False)
        return f"sqlite:///{(self.data_dir / 'cybershield.db').as_posix()}"

    # ================================================================= helpers
    def get_secret_key(self) -> str:
        """Return the JWT signing key.

        Resolution order: ``*_FILE`` > env var > persisted key in ``data_dir`` >
        freshly generated key (persisted with ``0600`` permissions so tokens
        survive restarts).
        """
        if self._secret_cache:
            return self._secret_cache
        key = read_secret_file(self.secret_key_file)
        if key is None and self.secret_key is not None:
            key = self.secret_key.get_secret_value()
        if key is None:
            key_path = self.data_dir / ".jwt_secret"
            key = read_secret_file(key_path)
            if key is None:
                key = secrets.token_urlsafe(64)
                self.data_dir.mkdir(parents=True, exist_ok=True)
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(key)
                logger.warning("No secret key configured: generated one at %s", key_path)
        if len(key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters long")
        self._secret_cache = key
        return key

    def ensure_directories(self) -> None:
        for directory in (self.data_dir, self.reports_dir, self.logs_dir):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance (cached)."""
    return Settings()
