"""Threat intelligence lookups and feed refresh."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.deps import DbDep, SettingsDep, client_ip, require
from app.api.schemas import IndicatorQuery
from app.core.audit import record_event
from app.core.rbac import Perm
from app.database.models import User
from app.services.context import get_iocs, ioc_cache_dir, reset_caches

router = APIRouter(prefix="/intel", tags=["threat intelligence"])
Reader = Annotated[User, Depends(require(Perm.INTEL_READ))]


@router.get("/stats")
def stats(_: Reader, settings: SettingsDep) -> dict[str, Any]:
    return {**get_iocs(settings).stats(), "feeds_configured": len(settings.threat_feed_list)}


@router.get("/lookup")
def lookup(_: Reader, settings: SettingsDep, indicator: Annotated[str, Query(max_length=253)]) -> dict[str, Any]:
    try:
        value = IndicatorQuery(indicator=indicator).indicator
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Indicator must be an IP address or domain name") from exc
    return get_iocs(settings).lookup(value)


@router.post("/refresh", summary="Download configured HTTPS threat feeds")
def refresh(
    request: Request, user: Annotated[User, Depends(require(Perm.INTEL_MANAGE))], db: DbDep, settings: SettingsDep
) -> dict[str, int]:
    if not settings.threat_feed_list:
        raise HTTPException(status_code=409, detail="No threat feeds configured (CYBERSHIELD_THREAT_FEEDS)")
    results = get_iocs(settings).refresh_from_feeds(settings.threat_feed_list, ioc_cache_dir(settings))
    reset_caches()
    record_event(db, actor=user.username, action="intel.refresh", ip=client_ip(request), details=results)
    return results
