"""Unit tests for Rate Limiter."""
import pytest
from src.alerting.rate_limiter import AlertRateLimiter

class TestRateLimiter:
    def test_allows_within_limit(self):
        limiter = AlertRateLimiter(max_per_minute=10, cooldown_seconds=0)
        for i in range(10):
            assert limiter.allow(f"type_{i}") is True

    def test_cooldown(self):
        limiter = AlertRateLimiter(max_per_minute=100, cooldown_seconds=300)
        assert limiter.allow("test") is True
        assert limiter.allow("test") is False  # Same type within cooldown
