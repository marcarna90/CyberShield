"""Role-based access control (least privilege, deny by default)."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class Perm:
    """Permission identifiers (``resource:action``)."""

    ASSETS_READ = "assets:read"
    FINDINGS_READ = "findings:read"
    FINDINGS_UPDATE = "findings:update"
    SCAN_RUN = "scan:run"
    AUDIT_RUN = "audit:run"
    TRAFFIC_RUN = "traffic:run"
    TRAFFIC_READ = "traffic:read"
    COMPLIANCE_RUN = "compliance:run"
    COMPLIANCE_READ = "compliance:read"
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"
    ALERT_READ = "alert:read"
    ALERT_ACK = "alert:ack"
    INTEL_READ = "intel:read"
    INTEL_MANAGE = "intel:manage"
    AUDIT_TRAIL_READ = "audit_trail:read"
    USERS_MANAGE = "users:manage"
    ADMIN = "admin:manage"


_VIEWER = {
    Perm.ASSETS_READ,
    Perm.FINDINGS_READ,
    Perm.TRAFFIC_READ,
    Perm.COMPLIANCE_READ,
    Perm.REPORT_READ,
    Perm.ALERT_READ,
}
_AUDITOR = _VIEWER | {Perm.REPORT_GENERATE, Perm.AUDIT_TRAIL_READ, Perm.INTEL_READ}
_ANALYST = _AUDITOR - {Perm.AUDIT_TRAIL_READ} | {
    Perm.FINDINGS_UPDATE,
    Perm.SCAN_RUN,
    Perm.AUDIT_RUN,
    Perm.TRAFFIC_RUN,
    Perm.COMPLIANCE_RUN,
    Perm.ALERT_ACK,
}
_ALL = {value for key, value in vars(Perm).items() if key.isupper()}

ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.VIEWER: frozenset(_VIEWER),
    Role.AUDITOR: frozenset(_AUDITOR),
    Role.ANALYST: frozenset(_ANALYST),
    Role.ADMIN: frozenset(_ALL),
}


def has_permission(role: str | Role, permission: str) -> bool:
    """Return ``True`` if ``role`` grants ``permission``. Unknown roles get nothing."""
    try:
        resolved = Role(role)
    except ValueError:
        return False
    return permission in ROLE_PERMISSIONS[resolved]


def permissions_for(role: str | Role) -> list[str]:
    try:
        return sorted(ROLE_PERMISSIONS[Role(role)])
    except ValueError:
        return []
