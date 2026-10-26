"""Administrative operations: demo dataset management."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.api.deps import DbDep, SettingsDep, client_ip, require
from app.core.audit import record_event
from app.core.rbac import Perm
from app.database.models import User
from app.services import demo

router = APIRouter(prefix="/admin", tags=["admin"])
Admin = Annotated[User, Depends(require(Perm.ADMIN))]


@router.get("/demo-data")
def demo_status(_: Admin, db: DbDep) -> dict[str, bool]:
    return {"present": demo.has_demo_data(db)}


@router.post("/demo-data", summary="Load the demo dataset (flagged, purgeable)")
def seed(request: Request, admin: Admin, db: DbDep, settings: SettingsDep) -> dict[str, int]:
    result = demo.seed_demo_data(db, settings)
    record_event(db, actor=admin.username, action="demo.seed", ip=client_ip(request), details=result)
    return result


@router.delete("/demo-data", summary="Remove every demo record")
def purge(request: Request, admin: Admin, db: DbDep) -> dict[str, int]:
    result = demo.purge_demo_data(db)
    record_event(db, actor=admin.username, action="demo.purge", ip=client_ip(request), details=result)
    return result
