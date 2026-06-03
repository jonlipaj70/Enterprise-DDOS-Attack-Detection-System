"""
Alert Rate Limiter
====================
Token bucket rate limiting to prevent alert storms.
"""
from __future__ import annotations
import time
from typing import Optional

class AlertRateLimiter:
    """Rate limits alerts to prevent notification storms."""

    def __init__(self, max_per_minute: int = 100, cooldown_seconds: int = 300):
        self._max_per_minute = max_per_minute
        self._cooldown = cooldown_seconds
        self._tokens = float(max_per_minute)
        self._last_refill = time.time()
        self._cooldowns: dict[str, float] = {}
        self._stats = {"allowed": 0, "throttled": 0}

    def allow(self, alert_type: str = "") -> bool:
        """Check if an alert should be allowed through."""
        now = time.time()

        # Check cooldown
        if alert_type in self._cooldowns:
            if now - self._cooldowns[alert_type] < self._cooldown:
                self._stats["throttled"] += 1
                return False

        # Token bucket refill
        elapsed = now - self._last_refill
        self._tokens = min(self._max_per_minute, self._tokens + elapsed * (self._max_per_minute / 60.0))
        self._last_refill = now

        if self._tokens >= 1:
            self._tokens -= 1
            self._cooldowns[alert_type] = now
            self._stats["allowed"] += 1
            return True

        self._stats["throttled"] += 1
        return False

    @property
    def stats(self) -> dict:
        return {**self._stats, "available_tokens": round(self._tokens, 2)}
