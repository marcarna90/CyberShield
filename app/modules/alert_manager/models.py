"""Alert data model."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, computed_field

from app.core.models import Severity, utcnow


class AlertTrigger(StrEnum):
    UNSAFE_CONFIGURATION = "unsafe_configuration"
    VULNERABILITY_DISCOVERED = "vulnerability_discovered"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    TRAFFIC_SPIKE = "traffic_spike"
    COMPLIANCE_FAILURE = "compliance_failure"
    THREAT_INTEL_MATCH = "threat_intel_match"


class AlertEvent(BaseModel):
    severity: Severity
    trigger: AlertTrigger
    title: str = Field(..., max_length=300)
    message: str = ""
    source: str = "cybershield"
    asset: str | None = None
    created_at: datetime = Field(default_factory=utcnow)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        raw = f"{self.trigger.value}|{self.title}|{self.asset or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
