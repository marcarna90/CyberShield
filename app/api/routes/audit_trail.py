"""Tamper-evident audit trail access."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import DbDep, require
from app.api.schemas import AuditEventOut, Page
from app.core.audit import verify_chain
from app.core.rbac import Perm
from app.database.models import AuditEvent, User

router = APIRouter(prefix="/audit-trail", tags=["audit trail"])
Auditor = Annotated[User, Depends(require(Perm.AUDIT_TRAIL_READ))]


@router.get("", response_model=Page[AuditEventOut])
def list_events(
    _: Auditor,
    db: DbDep,
    actor: Annotated[str | None, Query(max_length=64)] = None,
    action: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AuditEventOut]:
    query = select(AuditEvent)
    if actor:
        query = query.where(AuditEvent.actor == actor)
    if action:
        query = query.where(AuditEvent.action == action)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(AuditEvent.id.desc()).limit(limit).offset(offset))
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )


@router.get("/verify", summary="Verify the hash chain integrity")
def verify(_: Auditor, db: DbDep) -> dict[str, Any]:
    return verify_chain(db).__dict__
