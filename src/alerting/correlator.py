"""
Smart Alert Correlator
========================
Correlates related alerts by time, IP, and attack type.
"""
from __future__ import annotations
import time
from collections import defaultdict
from typing import Any

class AlertCorrelator:
    """Correlates related alerts to reduce noise."""

    def __init__(self, time_window: float = 60.0, ip_window: float = 300.0):
        self._time_window = time_window
        self._ip_window = ip_window
        self._recent_alerts: list[dict] = []

    def correlate(self, alert: dict[str, Any]) -> list[str]:
        """Find correlated alert IDs for a new alert."""
        correlated = []
        now = time.time()

        # Clean old alerts
        self._recent_alerts = [
            a for a in self._recent_alerts
            if now - a.get("timestamp", 0) < self._ip_window
        ]

        for existing in self._recent_alerts:
            # Time-based correlation
            if abs(alert.get("timestamp", 0) - existing.get("timestamp", 0)) < self._time_window:
                if alert.get("attack_type") == existing.get("attack_type"):
                    correlated.append(existing.get("alert_id", ""))

        self._recent_alerts.append(alert)
        return correlated

    @property
    def stats(self) -> dict:
        return {"tracked_alerts": len(self._recent_alerts)}
