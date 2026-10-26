"""Continuous passive network sensor (Docker ``sensor`` profile or ``cybershield sensor``)."""

from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Callable

from app.core.config import Settings
from app.database.session import session_scope
from app.modules.traffic_monitor.analyzer import TrafficSummary
from app.modules.traffic_monitor.capture import CaptureError, live_capture
from app.services import operations
from app.services.context import get_iocs, traffic_thresholds

logger = logging.getLogger(__name__)

CaptureFn = Callable[..., TrafficSummary]


class Sensor:
    """Capture -> analyse -> persist -> alert, in fixed-length windows, until stopped."""

    def __init__(self, settings: Settings, capture: CaptureFn = live_capture) -> None:
        self.settings = settings
        self._capture = capture
        self._stop = threading.Event()

    def stop(self, *_args: object) -> None:
        logger.info("Sensor stop requested")
        self._stop.set()

    def run_once(self) -> TrafficSummary:
        summary = self._capture(
            self.settings.sensor_interface,
            self.settings.sensor_interval_seconds,
            traffic_thresholds(self.settings),
            get_iocs(self.settings),
            max_packets=self.settings.traffic_max_packets,
        )
        with session_scope() as db:
            operations.record_traffic(db, self.settings, summary, actor="sensor")
        logger.info(
            "Sensor window: %d packets, health %.0f, %d anomalies",
            summary.total_packets,
            summary.health_score,
            len(summary.anomalies),
        )
        return summary

    def run_forever(self, max_windows: int | None = None) -> int:
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, self.stop)
            signal.signal(signal.SIGINT, self.stop)
        windows = 0
        while not self._stop.is_set() and (max_windows is None or windows < max_windows):
            try:
                self.run_once()
            except CaptureError as exc:
                logger.error("Capture error: %s (retrying in 30s)", exc)
                self._stop.wait(30)
            windows += 1
        return windows
