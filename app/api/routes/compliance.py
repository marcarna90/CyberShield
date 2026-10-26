"""Compliance evaluation, latest report and score history."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select

from app.api.deps import DbDep, SettingsDep, client_ip, require
from app.core.audit import record_event
from app.core.rbac import Perm
from app.database.models import ComplianceResult, User
from app.services import operations

router = APIRouter(prefix="/compliance", tags=["compliance"])
Reader = Annotated[User, Depends(require(Perm.COMPLIANCE_READ))]


@router.post("/evaluate", summary="Re-evaluate CIS / NIST CSF / ISO 27001 compliance now")
def evaluate(
    request: Request, user: Annotated[User, Depends(require(Perm.COMPLIANCE_RUN))], db: DbDep, settings: SettingsDep
) -> dict[str, Any]:
    report = operations.run_compliance(db, settings, user.username)
    record_event(
        db,
        actor=user.username,
        action="compliance.evaluate",
        ip=client_ip(request),
        details={"overall_score": report.overall_score},
    )
    return report.model_dump(mode="json")


@router.get("/latest")
def latest(_: Reader, db: DbDep) -> dict[str, Any]:
    report = operations.latest_compliance_report(db)
    if report is None:
        raise HTTPException(status_code=404, detail="No compliance evaluation yet")
    return report


@router.get("/history")
def history(_: Reader, db: DbDep, limit: Annotated[int, Query(ge=1, le=1000)] = 300) -> list[dict[str, Any]]:
    rows = db.scalars(select(ComplianceResult).order_by(ComplianceResult.created_at.desc()).limit(limit))
    return [
        {
            "framework": r.framework,
            "score": r.score,
            "passed": r.passed,
            "failed": r.failed,
            "created_at": r.created_at.isoformat(),
        }
        for r in reversed(list(rows))
    ]
