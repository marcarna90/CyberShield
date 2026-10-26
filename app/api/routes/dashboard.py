"""Aggregated metrics for the Streamlit dashboard."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends

from app.api.deps import DbDep, require
from app.core.rbac import Perm
from app.database import repository
from app.database.models import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview")
def overview(_: Annotated[User, Depends(require(Perm.FINDINGS_READ))], db: DbDep) -> dict[str, Any]:
    return repository.overview(db)
