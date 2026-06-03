"""
Multi-Window Aggregator
========================
Sliding window aggregations at 1s, 5s, and 60s granularity.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from src.processing.feature_engine import FeatureEngine, FeatureVector
from src.config.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class WindowState:
    """State for a single time window."""
    window_size_seconds: float
    packets: deque = field(default_factory=deque)
    latest_features: Optional[FeatureVector] = None
    last_computed: float = 0.0

    def add_packets(self, new_packets: list[dict]) -> None:
        """Add packets to the window buffer."""
        self.packets.extend(new_packets)
        self._evict_old()

    def _evict_old(self) -> None:
        """Remove packets outside the window."""
        cutoff = time.time() - self.window_size_seconds
        while self.packets and self.packets[0].get("timestamp", 0) < cutoff:
            self.packets.popleft()

    def get_packets(self) -> list[dict]:
        """Get all packets in the current window."""
        self._evict_old()
        return list(self.packets)


class WindowAggregator:
    """
    Multi-window aggregation engine.

    Maintains sliding windows at 1s, 5s, and 60s granularity,
    computing feature vectors for each window independently.
    """

    def __init__(self):
        self._feature_engine = FeatureEngine()
        self._windows = {
            "1s": WindowState(window_size_seconds=1.0),
            "5s": WindowState(window_size_seconds=5.0),
            "60s": WindowState(window_size_seconds=60.0),
        }
        self._aggregation_count = 0

    def ingest(self, packets: list[dict]) -> dict[str, FeatureVector]:
        """
        Ingest a batch of packets and compute features for all windows.

        Args:
            packets: List of packet dictionaries

        Returns:
            Dictionary mapping window name to FeatureVector
        """
        results = {}

        for window_name, window_state in self._windows.items():
            window_state.add_packets(packets)
            window_packets = window_state.get_packets()

            fv = self._feature_engine.extract_features(
                window_packets,
                window_duration=window_state.window_size_seconds,
            )
            window_state.latest_features = fv
            window_state.last_computed = time.time()
            results[window_name] = fv

        self._aggregation_count += 1
        return results

    def get_latest_features(self) -> dict[str, Optional[dict]]:
        """Get the latest feature vectors for all windows."""
        return {
            name: state.latest_features.to_dict() if state.latest_features else None
            for name, state in self._windows.items()
        }

    def get_window_stats(self) -> dict[str, dict]:
        """Get statistics for each window."""
        return {
            name: {
                "window_size": state.window_size_seconds,
                "packet_count": len(state.packets),
                "last_computed": state.last_computed,
            }
            for name, state in self._windows.items()
        }

    @property
    def stats(self) -> dict:
        return {
            "aggregation_count": self._aggregation_count,
            "windows": self.get_window_stats(),
        }
