"""Structured JSON logging with secret redaction and rotating log files.

Three log streams are produced under ``logs_dir``:

* ``cybershield.log`` - application events
* ``audit.log``       - security audit trail (who did what, when, from where)
* ``alerts.log``      - security alerts (log alert channel)
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from typing import Any, TextIO

from app.core.config import Settings

_SENSITIVE_KEY = re.compile(r"(passw|secret|token|authorization|api[_-]?key|cookie|credential)", re.I)
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-_.=]+")
_KV_SECRET = re.compile(r"(?i)((?:password|passwd|secret|token)\s*[=:]\s*)\S+")
_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {"message", "asctime"}

REDACTED = "***REDACTED***"


def redact_value(key: str, value: Any) -> Any:
    """Redact a value whose key looks sensitive; recurse into dicts."""
    if _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, dict):
        return {k: redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    """Scrub bearer tokens and ``password=...`` style fragments from free text."""
    text = _BEARER.sub(r"\1" + REDACTED, text)
    return _KV_SECRET.sub(r"\1" + REDACTED, text)


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON documents."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = redact_value(key, value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """Human friendly formatter that still redacts secrets."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


_CONFIGURED = False


def setup_logging(settings: Settings, *, force: bool = False, stream: TextIO | None = None) -> None:
    """Configure root, audit and alert loggers (idempotent).

    ``stream`` defaults to stdout (container friendly); the CLI uses stderr so
    that its own stdout output stays machine-readable.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return
    settings.logs_dir.mkdir(parents=True, exist_ok=True)
    formatter: logging.Formatter = JsonFormatter() if settings.log_json else TextFormatter()

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(settings.log_level)

    console = logging.StreamHandler(stream or sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    app_file = RotatingFileHandler(
        settings.logs_dir / "cybershield.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    app_file.setFormatter(JsonFormatter())
    root.addHandler(app_file)

    for name, filename in (("cybershield.audit", "audit.log"), ("cybershield.alerts", "alerts.log")):
        dedicated = logging.getLogger(name)
        for handler in list(dedicated.handlers):
            dedicated.removeHandler(handler)
        file_handler = RotatingFileHandler(
            settings.logs_dir / filename, maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
        )
        file_handler.setFormatter(JsonFormatter())
        dedicated.addHandler(file_handler)
        dedicated.setLevel(logging.INFO)
        dedicated.propagate = True

    # Quieten noisy third-party loggers.
    for noisy in ("scapy.runtime", "urllib3", "httpx", "multipart"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _CONFIGURED = True
