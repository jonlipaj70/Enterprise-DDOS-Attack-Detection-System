"""Health Check Endpoints."""
from __future__ import annotations
import time
from typing import Any

class HealthChecker:
    def __init__(self):
        self._start_time = time.time()
        self._checks: dict[str, bool] = {}

    def register_check(self, name: str, healthy: bool) -> None:
        self._checks[name] = healthy

    def get_health(self) -> dict[str, Any]:
        all_healthy = all(self._checks.values()) if self._checks else True
        return {
            "status": "healthy" if all_healthy else "degraded",
            "uptime_seconds": round(time.time() - self._start_time),
            "checks": self._checks,
        }
