"""Report generation and secure download."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select

from app.api.deps import DbDep, SettingsDep, client_ip, require
from app.api.schemas import Page, ReportOut, ReportRequest
from app.core.audit import record_event
from app.core.rbac import Perm
from app.database.models import ReportRecord, User
from app.modules.reporting_engine import ReportEngine
from app.services import operations

router = APIRouter(prefix="/reports", tags=["reports"])
Reader = Annotated[User, Depends(require(Perm.REPORT_READ))]
MEDIA_TYPES = {"pdf": "application/pdf", "html": "text/html; charset=utf-8", "json": "application/json"}


@router.post("", response_model=list[ReportOut], status_code=status.HTTP_201_CREATED)
def generate(
    request: Request,
    body: ReportRequest,
    user: Annotated[User, Depends(require(Perm.REPORT_GENERATE))],
    db: DbDep,
    settings: SettingsDep,
) -> list[ReportRecord]:
    records = operations.generate_reports(db, settings, user.username, body.report_type, body.formats)
    record_event(
        db,
        actor=user.username,
        action="report.generate",
        resource=body.report_type.value,
        ip=client_ip(request),
        details={"formats": [f.value for f in body.formats], "ids": [r.id for r in records]},
    )
    return records


@router.get("", response_model=Page[ReportOut])
def list_reports(
    _: Reader,
    db: DbDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ReportOut]:
    total = db.scalar(select(func.count(ReportRecord.id))) or 0
    rows = db.scalars(select(ReportRecord).order_by(ReportRecord.id.desc()).limit(limit).offset(offset))
    return Page[ReportOut](items=[ReportOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{report_id}/download", summary="Download a generated report")
def download(request: Request, report_id: int, user: Reader, db: DbDep, settings: SettingsDep) -> FileResponse:
    record = db.get(ReportRecord, report_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        path = ReportEngine(settings.reports_dir).resolve(record.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid report") from exc
    if not path.is_file():
        raise HTTPException(status_code=410, detail="Report file no longer available")
    record_event(db, actor=user.username, action="report.download", resource=record.filename, ip=client_ip(request))
    return FileResponse(
        path,
        media_type=MEDIA_TYPES.get(record.format, "application/octet-stream"),
        filename=record.filename,
        headers={"X-Content-SHA256": record.sha256},
    )
