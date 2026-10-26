"""Aggregate all API routers under the versioned prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    admin,
    alerts,
    assets,
    audit_trail,
    audits,
    auth,
    compliance,
    dashboard,
    findings,
    health,
    intel,
    reports,
    scans,
    traffic,
    users,
)

api_router = APIRouter()
for module in (
    health,
    auth,
    users,
    dashboard,
    assets,
    scans,
    audits,
    findings,
    traffic,
    compliance,
    alerts,
    reports,
    intel,
    audit_trail,
    admin,
):
    api_router.include_router(module.router)
