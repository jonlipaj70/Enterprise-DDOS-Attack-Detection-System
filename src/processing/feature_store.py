"""
Feature Store
==============
In-memory feature store with TTL-based eviction for ML model serving.
"""

from __future__ import annotations

import time
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional

from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class FeatureEntry:
    """A single feature store entry with metadata."""
    key: str
    features: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    ttl_seconds: float = 3600.0
    access_count: int = 0

    @property
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl_seconds


class FeatureStore:
    """
    In-memory feature store for ML model serving.

    Features:
    - TTL-based automatic eviction
    - Thread-safe access
    - Time-series history for trend analysis
    - Efficient key-based lookup
    """

    def __init__(self, max_entries: int = 10000, default_ttl: float = 3600.0):
        self._store: OrderedDict[str, FeatureEntry] = OrderedDict()
        self._history: dict[str, list[dict[str, Any]]] = {}
        self._max_entries = max_entries
        self._default_ttl = default_ttl
        self._lock = threading.Lock()
        self._stats = {
            "puts": 0,
            "gets": 0,
            "hits": 0,
            "misses": 0,
            "evictions": 0,
        }

    def put(
        self,
        key: str,
        features: dict[str, Any],
        ttl: Optional[float] = None,
    ) -> None:
        """
        Store a feature vector.

        Args:
            key: Feature key (e.g., 'window_1s', 'ip_10.0.1.1')
            features: Feature dictionary
            ttl: Time-to-live in seconds (None = use default)
        """
        with self._lock:
            entry = FeatureEntry(
                key=key,
                features=features,
                ttl_seconds=ttl or self._default_ttl,
            )
            self._store[key] = entry
            self._store.move_to_end(key)

            # Maintain history
            if key not in self._history:
                self._history[key] = []
            self._history[key].append({
                "timestamp": entry.timestamp,
                "features": features,
            })
            # Keep last 100 entries per key
            if len(self._history[key]) > 100:
                self._history[key] = self._history[key][-100:]

            self._stats["puts"] += 1

            # Evict if over capacity
            while len(self._store) > self._max_entries:
                evicted_key, _ = self._store.popitem(last=False)
                self._stats["evictions"] += 1

            # Evict expired entries periodically
            self._evict_expired()

    def get(self, key: str) -> Optional[dict[str, Any]]:
        """Get features by key."""
        with self._lock:
            self._stats["gets"] += 1
            entry = self._store.get(key)

            if entry is None:
                self._stats["misses"] += 1
                return None

            if entry.is_expired:
                del self._store[key]
                self._stats["misses"] += 1
                self._stats["evictions"] += 1
                return None

            entry.access_count += 1
            self._stats["hits"] += 1
            return entry.features

    def get_history(self, key: str, limit: int = 60) -> list[dict[str, Any]]:
        """Get feature history for trend analysis."""
        with self._lock:
            history = self._history.get(key, [])
            return history[-limit:]

    def get_latest(self, prefix: str = "") -> dict[str, dict[str, Any]]:
        """Get all latest features, optionally filtered by key prefix."""
        with self._lock:
            result = {}
            for key, entry in self._store.items():
                if prefix and not key.startswith(prefix):
                    continue
                if not entry.is_expired:
                    result[key] = entry.features
            return result

    def _evict_expired(self) -> None:
        """Remove expired entries."""
        expired_keys = [
            key for key, entry in self._store.items() if entry.is_expired
        ]
        for key in expired_keys:
            del self._store[key]
            self._stats["evictions"] += 1

    def clear(self) -> None:
        """Clear all entries."""
        with self._lock:
            self._store.clear()
            self._history.clear()

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def stats(self) -> dict:
        hit_rate = (
            self._stats["hits"] / max(self._stats["gets"], 1) * 100
        )
        return {
            **self._stats,
            "size": self.size,
            "hit_rate_pct": round(hit_rate, 2),
        }
