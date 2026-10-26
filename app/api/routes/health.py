"""Liveness and readiness probes (unauthenticated, minimal information disclosure)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from sqlalchemy import text

from app import __version__
from app.api.deps import DbDep

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/ready")
def ready(db: DbDep) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ready"}
