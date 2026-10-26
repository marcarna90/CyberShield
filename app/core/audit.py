"""Tamper-evident audit trail (OWASP ASVS V7 - Error Handling and Logging).

Each event stores ``hash = SHA-256(prev_hash || canonical_json(event))``.
Modifying or deleting any historical row breaks the chain, which
:func:`verify_chain` detects and reports.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import redact_value
from app.core.models import utcnow
from app.database.models import AuditEvent

GENESIS_HASH = "0" * 64
_LOCK = threading.Lock()
audit_logger = logging.getLogger("cybershield.audit")


def _fmt_ts(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(
    *, timestamp: datetime, actor: str, action: str, resource: str, outcome: str, ip: str | None, details: dict
) -> str:
    return json.dumps(
        {
            "timestamp": _fmt_ts(timestamp),
            "actor": actor,
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "ip": ip,
            "details": details,
        },
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )


def compute_hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def record_event(
    db: Session,
    *,
    actor: str,
    action: str,
    resource: str = "",
    outcome: str = "success",
    ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append an event to the audit trail and commit it."""
    safe_details = redact_value("details", details or {})
    with _LOCK:
        last = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).first()
        prev_hash = last.hash if last else GENESIS_HASH
        timestamp = utcnow()
        canonical = _canonical(
            timestamp=timestamp,
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            ip=ip,
            details=safe_details,
        )
        event = AuditEvent(
            timestamp=timestamp,
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            ip=ip,
            details=safe_details,
            prev_hash=prev_hash,
            hash=compute_hash(prev_hash, canonical),
        )
        db.add(event)
        db.commit()
    audit_logger.info(
        "%s %s %s",
        actor,
        action,
        outcome,
        extra={"audit_actor": actor, "audit_action": action, "audit_resource": resource, "audit_ip": ip},
    )
    return event


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    checked: int
    first_invalid_id: int | None = None
    reason: str = ""


def verify_chain(db: Session) -> ChainVerification:
    """Recompute every hash in order and report the first inconsistency."""
    prev_hash = GENESIS_HASH
    checked = 0
    for event in db.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        if event.prev_hash != prev_hash:
            return ChainVerification(False, checked, event.id, "prev_hash mismatch (row deleted or reordered)")
        canonical = _canonical(
            timestamp=event.timestamp,
            actor=event.actor,
            action=event.action,
            resource=event.resource,
            outcome=event.outcome,
            ip=event.ip,
            details=event.details or {},
        )
        if compute_hash(prev_hash, canonical) != event.hash:
            return ChainVerification(False, checked, event.id, "content hash mismatch (row modified)")
        prev_hash = event.hash
        checked += 1
    return ChainVerification(True, checked)
