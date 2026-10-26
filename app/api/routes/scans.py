"""Authorised network scans (asynchronous) and scan history."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select

from app.api.deps import DbDep, SettingsDep, client_ip, require
from app.api.schemas import Page, ScanBrief, ScanOut, ScanRequest
from app.core.audit import record_event
from app.core.config import Settings
from app.core.rbac import Perm
from app.core.scope import ScopeError
from app.database.models import Scan, User
from app.database.session import session_scope
from app.modules.network_scanner import SCAN_PROFILES
from app.services import operations
from app.services.context import get_scope

router = APIRouter(prefix="/scans", tags=["scans"])
logger = logging.getLogger(__name__)
Scanner = Annotated[User, Depends(require(Perm.SCAN_RUN))]
Reader = Annotated[User, Depends(require(Perm.FINDINGS_READ))]


def run_scan_job(settings: Settings, scan_id: int, targets: list[str], profile: str) -> None:
    """Background job: runs in the threadpool with its own DB session."""
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:  # pragma: no cover - deleted meanwhile
            return
        try:
            operations.execute_network_scan(db, settings, scan, targets, profile)
        except Exception as exc:  # never leave a scan stuck in "running"
            logger.exception("Scan %s crashed", scan_id)
            scan.status, scan.error = "failed", f"Internal error: {type(exc).__name__}"
            db.commit()


@router.get("/profiles")
def profiles(_: Reader) -> list[dict[str, object]]:
    return [
        {"name": p.name, "description": p.description, "version_detection": p.version_detection}
        for p in SCAN_PROFILES.values()
    ]


@router.post(
    "",
    response_model=ScanBrief,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Queue an authorised network + vulnerability scan",
)
def create_scan(
    request: Request, body: ScanRequest, background: BackgroundTasks, user: Scanner, db: DbDep, settings: SettingsDep
) -> Scan:
    try:
        targets = get_scope(settings).validate_many(body.targets)
    except ScopeError as exc:
        # Scope violations are security-relevant: always audited.
        record_event(
            db,
            actor=user.username,
            action="scan.create",
            resource=",".join(body.targets)[:255],
            outcome="denied",
            ip=client_ip(request),
            details={"reason": str(exc)},
        )
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = operations.queue_network_scan(db, user.username, targets, body.profile)
    record_event(
        db,
        actor=user.username,
        action="scan.create",
        resource=",".join(targets)[:255],
        ip=client_ip(request),
        details={"scan_id": scan.id, "profile": body.profile},
    )
    background.add_task(run_scan_job, settings, scan.id, targets, body.profile)
    return scan


@router.get("", response_model=Page[ScanBrief])
def list_scans(
    _: Reader,
    db: DbDep,
    scan_type: Annotated[str | None, Query(pattern=r"^[a-z_]{1,32}$")] = None,
    status_filter: Annotated[str | None, Query(alias="status", pattern=r"^[a-z]{1,16}$")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ScanBrief]:
    query = select(Scan)
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    if status_filter:
        query = query.where(Scan.status == status_filter)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(Scan.started_at.desc(), Scan.id.desc()).limit(limit).offset(offset))
    return Page[ScanBrief](items=[ScanBrief.model_validate(s) for s in rows], total=total, limit=limit, offset=offset)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, _: Reader, db: DbDep) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
