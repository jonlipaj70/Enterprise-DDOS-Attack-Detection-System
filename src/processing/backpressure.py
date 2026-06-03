"""
Backpressure & Flow Control
=============================
Adaptive rate control using token bucket algorithm for flow management.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class TokenBucketStats:
    """Token bucket statistics."""
    tokens_consumed: int = 0
    requests_throttled: int = 0
    current_tokens: float = 0.0
    max_tokens: float = 0.0
    refill_rate: float = 0.0


class TokenBucket:
    """
    Token bucket rate limiter for backpressure management.

    Provides smooth rate limiting with burst capacity.
    """

    def __init__(self, rate: float, capacity: float):
        """
        Args:
            rate: Token refill rate per second
            capacity: Maximum token capacity (burst size)
        """
        self._rate = rate
        self._capacity = capacity
        self._tokens = capacity
        self._last_refill = time.time()
        self._stats = TokenBucketStats(max_tokens=capacity, refill_rate=rate)

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens. Returns True if successful.

        Args:
            tokens: Number of tokens to consume
        """
        self._refill()

        if self._tokens >= tokens:
            self._tokens -= tokens
            self._stats.tokens_consumed += tokens
            return True

        self._stats.requests_throttled += 1
        return False

    async def wait_for_token(self, tokens: int = 1) -> None:
        """Wait until tokens are available."""
        while not self.consume(tokens):
            wait_time = (tokens - self._tokens) / self._rate
            await asyncio.sleep(min(wait_time, 0.1))

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now
        self._stats.current_tokens = self._tokens

    @property
    def available_tokens(self) -> float:
        self._refill()
        return self._tokens

    @property
    def stats(self) -> dict:
        self._refill()
        return {
            "tokens_consumed": self._stats.tokens_consumed,
            "requests_throttled": self._stats.requests_throttled,
            "current_tokens": round(self._stats.current_tokens, 2),
            "max_tokens": self._stats.max_tokens,
            "refill_rate": self._stats.refill_rate,
        }


class AdaptiveBackpressure:
    """
    Adaptive backpressure controller.

    Monitors processing latency and adjusts ingestion rate dynamically.
    """

    def __init__(
        self,
        target_latency_ms: float = 200.0,
        min_rate: float = 100.0,
        max_rate: float = 100000.0,
        adjustment_factor: float = 0.1,
    ):
        self._target_latency = target_latency_ms
        self._min_rate = min_rate
        self._max_rate = max_rate
        self._adjustment_factor = adjustment_factor
        self._current_rate = max_rate
        self._bucket = TokenBucket(rate=max_rate, capacity=max_rate)

    def report_latency(self, latency_ms: float) -> float:
        """
        Report observed processing latency and get adjusted rate.

        Args:
            latency_ms: Observed processing latency

        Returns:
            New target rate
        """
        if latency_ms > self._target_latency:
            # Reduce rate
            reduction = self._adjustment_factor * (latency_ms / self._target_latency - 1)
            self._current_rate *= max(0.5, 1.0 - reduction)
        else:
            # Increase rate
            increase = self._adjustment_factor * (1 - latency_ms / self._target_latency)
            self._current_rate *= min(2.0, 1.0 + increase)

        self._current_rate = max(self._min_rate, min(self._max_rate, self._current_rate))
        self._bucket = TokenBucket(rate=self._current_rate, capacity=self._current_rate)
        return self._current_rate

    async def throttle(self, batch_size: int = 1) -> None:
        """Wait if necessary to maintain target rate."""
        await self._bucket.wait_for_token(batch_size)

    @property
    def current_rate(self) -> float:
        return self._current_rate

    @property
    def stats(self) -> dict:
        return {
            "current_rate": round(self._current_rate, 2),
            "target_latency_ms": self._target_latency,
            "bucket": self._bucket.stats,
        }
