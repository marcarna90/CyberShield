"""Security alerts (dashboard channel) and acknowledgement."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select

from app.api.deps import DbDep, client_ip, require
from app.api.schemas import AlertOut, Page
from app.core.audit import record_event
from app.core.models import utcnow
from app.core.rbac import Perm
from app.database.models import Alert, User

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut])
def list_alerts(
    _: Annotated[User, Depends(require(Perm.ALERT_READ))],
    db: DbDep,
    acknowledged: bool | None = None,
    severity: Annotated[str | None, Query(pattern=r"^(critical|high|medium|low)$")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AlertOut]:
    query = select(Alert)
    if acknowledged is not None:
        query = query.where(Alert.acknowledged.is_(acknowledged))
    if severity:
        query = query.where(Alert.severity == severity)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit).offset(offset))
    return Page[AlertOut](items=[AlertOut.model_validate(a) for a in rows], total=total, limit=limit, offset=offset)


@router.post("/{alert_id}/ack", response_model=AlertOut)
def acknowledge(
    request: Request, alert_id: int, user: Annotated[User, Depends(require(Perm.ALERT_ACK))], db: DbDep
) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if not alert.acknowledged:
        alert.acknowledged, alert.acknowledged_by, alert.acknowledged_at = True, user.username, utcnow()
        db.commit()
        record_event(db, actor=user.username, action="alert.ack", resource=str(alert_id), ip=client_ip(request))
    return alert
