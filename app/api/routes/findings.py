"""Findings: filtering and triage (status workflow)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import case, func, or_, select

from app.api.deps import DbDep, client_ip, require
from app.api.schemas import FindingOut, FindingUpdate, Page
from app.core.audit import record_event
from app.core.models import utcnow
from app.core.rbac import Perm
from app.database import repository
from app.database.models import FindingRecord, User

router = APIRouter(prefix="/findings", tags=["findings"])
Reader = Annotated[User, Depends(require(Perm.FINDINGS_READ))]

_SEVERITY_ORDER = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}, value=FindingRecord.severity, else_=5
)


@router.get("", response_model=Page[FindingOut])
def list_findings(
    _: Reader,
    db: DbDep,
    severity: Annotated[list[str] | None, Query(max_length=5)] = None,
    source: Annotated[str | None, Query(pattern=r"^[a-z_]{1,64}$")] = None,
    status: Annotated[str | None, Query(pattern=r"^[a-z_]{1,16}$")] = "open",
    asset: Annotated[str | None, Query(max_length=255)] = None,
    q: Annotated[str | None, Query(max_length=100)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FindingOut]:
    query = select(FindingRecord)
    if severity:
        query = query.where(FindingRecord.severity.in_([s.lower() for s in severity]))
    if source:
        query = query.where(FindingRecord.source == source)
    if status:
        query = query.where(FindingRecord.status == status)
    if asset:
        query = query.where(FindingRecord.asset == asset)
    if q:
        like = f"%{q}%"
        query = query.where(or_(FindingRecord.title.like(like), FindingRecord.finding_id.like(like)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(_SEVERITY_ORDER, FindingRecord.cvss.desc().nulls_last(), FindingRecord.id)
        .limit(limit)
        .offset(offset)
    )
    return Page[FindingOut](items=[FindingOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset)


@router.get("/{finding_pk}", response_model=FindingOut)
def get_finding(finding_pk: int, _: Reader, db: DbDep) -> FindingRecord:
    record = db.get(FindingRecord, finding_pk)
    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return record


@router.patch("/{finding_pk}", response_model=FindingOut, summary="Triage a finding")
def update_finding(
    request: Request,
    finding_pk: int,
    body: FindingUpdate,
    user: Annotated[User, Depends(require(Perm.FINDINGS_UPDATE))],
    db: DbDep,
) -> FindingRecord:
    record = db.get(FindingRecord, finding_pk)
    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    previous = record.status
    record.status = body.status
    record.resolved_at = utcnow() if body.status != "open" else None
    db.commit()
    repository.update_asset_risk(db)
    record_event(
        db,
        actor=user.username,
        action="finding.update",
        resource=f"{record.finding_id}@{record.asset}",
        ip=client_ip(request),
        details={"from": previous, "to": body.status, "comment": body.comment},
    )
    return record
