"""Discovered asset inventory."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload

from app.api.deps import DbDep, require
from app.api.schemas import AssetOut, Page
from app.core.rbac import Perm
from app.database.models import Asset, User

router = APIRouter(prefix="/assets", tags=["assets"])
Reader = Annotated[User, Depends(require(Perm.ASSETS_READ))]


@router.get("", response_model=Page[AssetOut])
def list_assets(
    _: Reader,
    db: DbDep,
    q: Annotated[str | None, Query(max_length=100)] = None,
    min_risk: Annotated[float, Query(ge=0, le=100)] = 0,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssetOut]:
    query = select(Asset).where(Asset.risk_score >= min_risk)
    if q:
        like = f"%{q}%"
        query = query.where(or_(Asset.ip.like(like), Asset.hostname.like(like)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    ordered = query.options(selectinload(Asset.services)).order_by(Asset.risk_score.desc(), Asset.ip)
    rows = db.scalars(ordered.limit(limit).offset(offset))
    return Page[AssetOut](items=[AssetOut.model_validate(a) for a in rows], total=total, limit=limit, offset=offset)


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, _: Reader, db: DbDep) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset
