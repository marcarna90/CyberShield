"""Host security audits."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.deps import DbDep, SettingsDep, client_ip, require
from app.core.audit import record_event
from app.core.rbac import Perm
from app.database.models import User
from app.services import operations

router = APIRouter(prefix="/audits", tags=["host audit"])


@router.post("/host", summary="Audit the configured host (CYBERSHIELD_HOST_ROOT)")
def run_host_audit(
    request: Request, user: Annotated[User, Depends(require(Perm.AUDIT_RUN))], db: DbDep, settings: SettingsDep
) -> dict[str, Any]:
    # The audited root is configuration, never user input (prevents path traversal).
    scan, report = operations.run_host_audit(db, settings, user.username)
    record_event(
        db,
        actor=user.username,
        action="audit.host",
        resource=report.hostname,
        ip=client_ip(request),
        details={"scan_id": scan.id, "score": report.score},
    )
    return {"scan_id": scan.id, **report.model_dump(mode="json")}


@router.get("/host/latest")
def latest_host_audit(_: Annotated[User, Depends(require(Perm.FINDINGS_READ))], db: DbDep) -> dict[str, Any]:
    report = operations.latest_host_audit(db)
    if report is None:
        raise HTTPException(status_code=404, detail="No host audit yet")
    return report
